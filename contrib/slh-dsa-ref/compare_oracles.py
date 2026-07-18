#!/usr/bin/env python3
"""Build and compare independent SLH-DSA-SHA2-128s reference oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "vectors.json"
OPENSSL_SOURCE = HERE / "openssl_oracle.c"
SLHDSA_C_SOURCE = HERE / "slhdsa_c_oracle.c"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ReferenceError(RuntimeError):
    pass


def load_manifest() -> dict:
    with MANIFEST_PATH.open(encoding="utf8") as manifest_file:
        manifest = json.load(manifest_file)
    validate_manifest(manifest)
    return manifest


def require_hex(value: str, byte_length: int, label: str) -> None:
    if len(value) != byte_length * 2 or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise ReferenceError(f"{label} must be {byte_length} lowercase-hex bytes")


def validate_manifest(manifest: dict) -> None:
    profile = manifest["profile"]
    expected_profile = {
        "name": "SLH-DSA-SHA2-128s",
        "standard": "FIPS 205",
        "signature_interface": "external",
        "message_mode": "pure",
        "public_key_bytes": 32,
        "private_key_bytes": 64,
        "keygen_seed_bytes": 48,
        "signature_bytes": 7856,
        "prototype_message_bytes": 32,
    }
    for name, expected in expected_profile.items():
        if profile.get(name) != expected:
            raise ReferenceError(f"profile {name} must be {expected!r}")

    context_hex = profile["prototype_context_hex"]
    if bytes.fromhex(context_hex).decode("ascii") != profile["prototype_context_ascii"]:
        raise ReferenceError("prototype context hex/ascii mismatch")
    if len(bytes.fromhex(context_hex)) > 255:
        raise ReferenceError("prototype context exceeds FIPS 205 limit")

    expected_cost_model = {
        "held_rc2_signature_bytes": 4480,
        "block_weight_limit": 16_000_000,
        "signature_witness_weight_per_byte": 1,
    }
    if manifest.get("system_cost_model") != expected_cost_model:
        raise ReferenceError("system cost model does not match the held PQBTC baseline")

    sources = manifest["sources"]
    for source_name in ("nist_acvp", "slhdsa_c"):
        if re.fullmatch(r"[0-9a-f]{40}", sources[source_name]["commit"]) is None:
            raise ReferenceError(f"{source_name} commit must be a full Git SHA")
    expected_nist_files = {
        "gen-val/json-files/SLH-DSA-keyGen-FIPS205/prompt.json",
        "gen-val/json-files/SLH-DSA-keyGen-FIPS205/expectedResults.json",
        "gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json",
        "gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json",
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/prompt.json",
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/expectedResults.json",
    }
    nist_files = sources["nist_acvp"]["files"]
    if set(nist_files) != expected_nist_files:
        raise ReferenceError("NIST source file set does not match the reference contract")
    for file_hash in nist_files.values():
        if HEX_64.fullmatch(file_hash) is None:
            raise ReferenceError("NIST source hashes must be SHA256 values")

    vectors = manifest["vectors"]
    keygen = vectors["nist_keygen_tg1_tc1"]
    require_hex(keygen["seed_hex"], profile["keygen_seed_bytes"], "NIST keygen seed")
    require_hex(keygen["expected_private_key_hex"], profile["private_key_bytes"], "NIST private key")
    require_hex(keygen["expected_public_key_hex"], profile["public_key_bytes"], "NIST public key")

    siggen = vectors["nist_siggen_tg19_tc161"]
    require_hex(siggen["private_key_hex"], profile["private_key_bytes"], "NIST signing key")
    if len(bytes.fromhex(siggen["context_hex"])) > 255:
        raise ReferenceError("NIST context exceeds FIPS 205 limit")
    if HEX_64.fullmatch(siggen["expected_signature_sha256"]) is None:
        raise ReferenceError("NIST signature hash must be SHA256")

    sigver = vectors["nist_sigver_tg19"]
    expected_sigver_profile = {
        "parameter_set": profile["name"],
        "signature_interface": profile["signature_interface"],
        "message_mode": profile["message_mode"],
    }
    for name, expected in expected_sigver_profile.items():
        if sigver.get(name) != expected:
            raise ReferenceError(f"NIST sigver {name} must be {expected!r}")
    cases = sigver["cases"]
    if len(cases) != 2:
        raise ReferenceError("NIST sigver reference must contain exactly two cases")
    if {case["test_case_id"] for case in cases} != {253, 266}:
        raise ReferenceError("NIST sigver cases must be tcId 253 and 266")
    if {case["expected_valid"] for case in cases} != {False, True}:
        raise ReferenceError("NIST sigver cases must include acceptance and rejection")
    for case in cases:
        require_hex(case["public_key_hex"], profile["public_key_bytes"], "NIST sigver key")
        if case["context_bytes"] > 255:
            raise ReferenceError("NIST sigver context exceeds FIPS 205 limit")
        if case["signature_bytes"] != profile["signature_bytes"]:
            raise ReferenceError("NIST sigver signature size mismatch")
        for field in ("message_sha256", "context_sha256", "signature_sha256"):
            if HEX_64.fullmatch(case[field]) is None:
                raise ReferenceError(f"NIST sigver {field} must be SHA256")

    pqbtc = vectors["pqbtc_sighash_v1"]
    require_hex(pqbtc["seed_hex"], profile["keygen_seed_bytes"], "PQBTC keygen seed")
    require_hex(pqbtc["message_hex"], profile["prototype_message_bytes"], "PQBTC message")
    require_hex(pqbtc["expected_private_key_hex"], profile["private_key_bytes"], "PQBTC private key")
    require_hex(pqbtc["expected_public_key_hex"], profile["public_key_bytes"], "PQBTC public key")
    if pqbtc["context_hex"] != context_hex:
        raise ReferenceError("PQBTC vector does not use the frozen prototype context")
    if HEX_64.fullmatch(pqbtc["expected_signature_sha256"]) is None:
        raise ReferenceError("PQBTC signature hash must be SHA256")


def run(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        rendered = shlex.join(command)
        raise ReferenceError(
            f"command failed ({result.returncode}): {rendered}\n{result.stderr.strip()}"
        )
    return result.stdout


def parse_version(value: str, label: str) -> tuple[int, int, int]:
    match = re.search(r"(?:OpenSSL )?(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise ReferenceError(f"cannot parse {label} version: {value}")
    return tuple(int(part) for part in match.groups())


def openssl_version() -> tuple[str, tuple[int, int, int]]:
    output = run(["openssl", "version"]).strip()
    version = parse_version(output, "OpenSSL CLI")
    if version < (3, 5, 0):
        raise ReferenceError("OpenSSL 3.5.0 or later is required")
    pkg_config_output = run(["pkg-config", "--modversion", "openssl"]).strip()
    pkg_config_version = parse_version(pkg_config_output, "OpenSSL pkg-config")
    if pkg_config_version != version:
        raise ReferenceError(
            f"OpenSSL CLI/pkg-config mismatch: {version}, {pkg_config_version}"
        )
    return output, version


def compile_openssl_oracle(build_dir: Path) -> Path:
    openssl_version()
    compiler = os.environ.get("CC", "cc")
    pkg_config = shlex.split(run(["pkg-config", "--cflags", "--libs", "openssl"]))
    output = build_dir / "openssl_slh_dsa_oracle"
    command = [
        compiler,
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        str(OPENSSL_SOURCE),
        "-o",
        str(output),
        *pkg_config,
    ]
    run(command)
    return output


def require_git_commit(source_dir: Path, expected_commit: str, source_name: str) -> None:
    actual_commit = run(["git", "rev-parse", "HEAD"], cwd=source_dir).strip()
    if actual_commit != expected_commit:
        raise ReferenceError(
            f"{source_name} commit mismatch: expected {expected_commit}, got {actual_commit}"
        )
    dirty = run(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source_dir
    ).strip()
    if dirty:
        raise ReferenceError(f"{source_name} checkout must be clean")


def require_slhdsa_c_source(source_dir: Path, expected_commit: str) -> None:
    if not (source_dir / "slh_dsa.h").is_file():
        raise ReferenceError(f"missing slhdsa-c source at {source_dir}")
    require_git_commit(source_dir, expected_commit, "slhdsa-c")


def find_test(document: dict, group_id: int, test_id: int) -> tuple[dict, dict]:
    group = next((group for group in document["testGroups"] if group["tgId"] == group_id), None)
    if group is None:
        raise ReferenceError(f"missing ACVP group {group_id}")
    test = next((test for test in group["tests"] if test["tcId"] == test_id), None)
    if test is None:
        raise ReferenceError(f"missing ACVP test {group_id}/{test_id}")
    return group, test


def sha256_hex(hex_value: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def verify_nist_sources(manifest: dict, source_dir: Path) -> dict:
    source = manifest["sources"]["nist_acvp"]
    require_git_commit(source_dir, source["commit"], "NIST ACVP")
    loaded: dict[str, dict] = {}
    for relative_path, expected_hash in source["files"].items():
        path = source_dir / relative_path
        if not path.is_file():
            raise ReferenceError(f"missing NIST source file: {path}")
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ReferenceError(
                f"NIST source hash mismatch for {relative_path}: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        loaded[relative_path] = json.loads(path.read_text(encoding="utf8"))

    vectors = manifest["vectors"]
    keygen_prompt = loaded["gen-val/json-files/SLH-DSA-keyGen-FIPS205/prompt.json"]
    keygen_expected = loaded[
        "gen-val/json-files/SLH-DSA-keyGen-FIPS205/expectedResults.json"
    ]
    keygen_group, keygen_test = find_test(keygen_prompt, 1, 1)
    _, keygen_result = find_test(keygen_expected, 1, 1)
    if keygen_group.get("parameterSet") != "SLH-DSA-SHA2-128s":
        raise ReferenceError("NIST keygen parameter set mismatch")
    expected_keygen = vectors["nist_keygen_tg1_tc1"]
    require_equal(
        "NIST source keygen seed",
        (keygen_test["skSeed"] + keygen_test["skPrf"] + keygen_test["pkSeed"]).lower(),
        expected_keygen["seed_hex"],
    )
    require_equal(
        "NIST source private key",
        keygen_result["sk"].lower(),
        expected_keygen["expected_private_key_hex"],
    )
    require_equal(
        "NIST source public key",
        keygen_result["pk"].lower(),
        expected_keygen["expected_public_key_hex"],
    )

    siggen_prompt = loaded["gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json"]
    siggen_expected = loaded[
        "gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json"
    ]
    siggen_group, siggen_test = find_test(siggen_prompt, 19, 161)
    _, siggen_result = find_test(siggen_expected, 19, 161)
    expected_siggen = vectors["nist_siggen_tg19_tc161"]
    expected_group = {
        "parameterSet": "SLH-DSA-SHA2-128s",
        "deterministic": True,
        "signatureInterface": "external",
        "preHash": "pure",
    }
    for name, expected_value in expected_group.items():
        if siggen_group.get(name) != expected_value:
            raise ReferenceError(f"NIST siggen group {name} mismatch")
    for source_name, manifest_name in (
        ("sk", "private_key_hex"),
        ("message", "message_hex"),
        ("context", "context_hex"),
    ):
        require_equal(
            f"NIST source siggen {source_name}",
            siggen_test[source_name].lower(),
            expected_siggen[manifest_name],
        )
    require_equal(
        "NIST source signature hash",
        sha256_hex(siggen_result["signature"]),
        expected_siggen["expected_signature_sha256"],
    )

    sigver_prompt = loaded["gen-val/json-files/SLH-DSA-sigVer-FIPS205/prompt.json"]
    sigver_expected = loaded[
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/expectedResults.json"
    ]
    sigver_group, _ = find_test(sigver_prompt, 19, 253)
    expected_sigver = vectors["nist_sigver_tg19"]
    expected_group = {
        "parameterSet": expected_sigver["parameter_set"],
        "signatureInterface": expected_sigver["signature_interface"],
        "preHash": expected_sigver["message_mode"],
    }
    for name, expected_value in expected_group.items():
        if sigver_group.get(name) != expected_value:
            raise ReferenceError(f"NIST sigver group {name} mismatch")

    sigver_cases: list[dict] = []
    for expected_case in expected_sigver["cases"]:
        test_id = expected_case["test_case_id"]
        _, source_case = find_test(sigver_prompt, 19, test_id)
        _, source_result = find_test(sigver_expected, 19, test_id)
        require_equal(
            f"NIST source sigver {test_id} public key",
            source_case["pk"].lower(),
            expected_case["public_key_hex"],
        )
        for field in ("message", "context", "signature"):
            source_hex = source_case[field].lower()
            if len(source_hex) != expected_case[f"{field}_bytes"] * 2:
                raise ReferenceError(f"NIST source sigver {test_id} {field} size mismatch")
            require_equal(
                f"NIST source sigver {test_id} {field} hash",
                sha256_hex(source_hex),
                expected_case[f"{field}_sha256"],
            )
        if source_result.get("testPassed") is not expected_case["expected_valid"]:
            raise ReferenceError(f"NIST source sigver {test_id} result mismatch")
        sigver_cases.append(
            {
                "test_case_id": test_id,
                "public_key_hex": source_case["pk"].lower(),
                "message_hex": source_case["message"].lower(),
                "context_hex": source_case["context"].lower(),
                "signature_hex": source_case["signature"].lower(),
                "expected_valid": expected_case["expected_valid"],
            }
        )

    return {
        "siggen_signature_hex": siggen_result["signature"].lower(),
        "sigver_cases": sigver_cases,
    }


def compile_slhdsa_c_oracle(build_dir: Path, source_dir: Path, expected_commit: str) -> Path:
    require_slhdsa_c_source(source_dir, expected_commit)
    sources = sorted(str(path) for path in source_dir.glob("*.c"))
    if not sources:
        raise ReferenceError("slhdsa-c source list is empty")
    compiler = os.environ.get("CC", "cc")
    output = build_dir / "slhdsa_c_oracle"
    command = [
        compiler,
        "-std=c99",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-I{source_dir}",
        str(SLHDSA_C_SOURCE),
        *sources,
        "-o",
        str(output),
    ]
    run(command)
    return output


def parse_oracle_output(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            raise ReferenceError(f"invalid oracle output line: {line}")
        name, value = line.split("=", 1)
        parsed[name] = value
    return parsed


def oracle_keygen(executable: Path, seed_hex: str) -> dict[str, str]:
    return parse_oracle_output(run([str(executable), "keygen", seed_hex]))


def oracle_sign(
    executable: Path, private_key_hex: str, message_hex: str, context_hex: str
) -> dict[str, str]:
    result = parse_oracle_output(
        run([str(executable), "sign", private_key_hex, message_hex, context_hex])
    )
    if result.get("verified") != "1":
        raise ReferenceError(f"oracle {executable.name} did not self-verify")
    return result


def oracle_verify(
    executable: Path,
    public_key_hex: str,
    message_hex: str,
    context_hex: str,
    signature_hex: str,
) -> dict[str, str]:
    result = parse_oracle_output(
        run(
            [
                str(executable),
                "verify",
                public_key_hex,
                message_hex,
                context_hex,
                signature_hex,
            ]
        )
    )
    if result.get("verified") not in {"0", "1"}:
        raise ReferenceError(f"oracle {executable.name} returned invalid verify result")
    return result


def signature_hash(signature_hex: str, expected_bytes: int) -> str:
    require_hex(signature_hex, expected_bytes, "signature")
    return hashlib.sha256(bytes.fromhex(signature_hex)).hexdigest()


def require_equal(label: str, *values: str) -> None:
    if len(set(values)) != 1:
        raise ReferenceError(f"{label} mismatch")


def median_ms(values: list[int]) -> float:
    return round(statistics.median(values) / 1_000_000, 3)


def evaluate(
    manifest: dict,
    openssl_oracle: Path,
    slhdsa_c_oracle: Path,
    benchmark_iterations: int,
    nist_source_vectors: dict,
) -> dict:
    profile = manifest["profile"]
    vectors = manifest["vectors"]
    oracles = {
        "openssl": openssl_oracle,
        "slhdsa_c": slhdsa_c_oracle,
    }

    keygen_vector = vectors["nist_keygen_tg1_tc1"]
    keygen_results = {
        name: oracle_keygen(executable, keygen_vector["seed_hex"])
        for name, executable in oracles.items()
    }
    for result in keygen_results.values():
        require_equal("NIST public key", result["pk"], keygen_vector["expected_public_key_hex"])
        require_equal("NIST private key", result["sk"], keygen_vector["expected_private_key_hex"])
    require_equal("oracle NIST public key", *(result["pk"] for result in keygen_results.values()))
    require_equal("oracle NIST private key", *(result["sk"] for result in keygen_results.values()))

    siggen_vector = vectors["nist_siggen_tg19_tc161"]
    siggen_results = {
        name: oracle_sign(
            executable,
            siggen_vector["private_key_hex"],
            siggen_vector["message_hex"],
            siggen_vector["context_hex"],
        )
        for name, executable in oracles.items()
    }
    siggen_hashes = {
        name: signature_hash(result["signature"], profile["signature_bytes"])
        for name, result in siggen_results.items()
    }
    require_equal(
        "NIST signature hash",
        *siggen_hashes.values(),
        siggen_vector["expected_signature_sha256"],
    )
    require_equal(
        "NIST signature bytes", *(result["signature"] for result in siggen_results.values())
    )
    require_equal(
        "NIST source signature bytes",
        *(result["signature"] for result in siggen_results.values()),
        nist_source_vectors["siggen_signature_hex"],
    )

    for case in nist_source_vectors["sigver_cases"]:
        verify_results = {
            name: oracle_verify(
                executable,
                case["public_key_hex"],
                case["message_hex"],
                case["context_hex"],
                case["signature_hex"],
            )
            for name, executable in oracles.items()
        }
        expected_result = "1" if case["expected_valid"] else "0"
        require_equal(
            f"NIST sigver tcId {case['test_case_id']}",
            *(result["verified"] for result in verify_results.values()),
            expected_result,
        )

    pqbtc_vector = vectors["pqbtc_sighash_v1"]
    benchmark: dict[str, dict[str, list[int]]] = {
        name: {"keygen_ns": [], "sign_ns": [], "verify_ns": []} for name in oracles
    }
    profile_signatures: dict[str, str] = {}
    for _ in range(benchmark_iterations):
        for name, executable in oracles.items():
            generated = oracle_keygen(executable, pqbtc_vector["seed_hex"])
            require_equal("PQBTC public key", generated["pk"], pqbtc_vector["expected_public_key_hex"])
            require_equal("PQBTC private key", generated["sk"], pqbtc_vector["expected_private_key_hex"])
            signed = oracle_sign(
                executable,
                generated["sk"],
                pqbtc_vector["message_hex"],
                pqbtc_vector["context_hex"],
            )
            signature_digest = signature_hash(signed["signature"], profile["signature_bytes"])
            require_equal(
                "PQBTC signature hash",
                signature_digest,
                pqbtc_vector["expected_signature_sha256"],
            )
            if name in profile_signatures:
                require_equal("deterministic PQBTC signature", profile_signatures[name], signed["signature"])
            profile_signatures[name] = signed["signature"]
            benchmark[name]["keygen_ns"].append(int(generated["keygen_ns"]))
            benchmark[name]["sign_ns"].append(int(signed["sign_ns"]))
            benchmark[name]["verify_ns"].append(int(signed["verify_ns"]))

    require_equal("PQBTC signature bytes", *profile_signatures.values())
    version_text, _ = openssl_version()
    cost_model = manifest["system_cost_model"]
    rc2_signature_weight = (
        cost_model["held_rc2_signature_bytes"]
        * cost_model["signature_witness_weight_per_byte"]
    )
    slh_signature_weight = (
        profile["signature_bytes"] * cost_model["signature_witness_weight_per_byte"]
    )
    rc2_capacity = cost_model["block_weight_limit"] // rc2_signature_weight
    slh_capacity = cost_model["block_weight_limit"] // slh_signature_weight
    return {
        "status": "PASS",
        "profile": profile["name"],
        "openssl_version": version_text,
        "slhdsa_c_commit": manifest["sources"]["slhdsa_c"]["commit"],
        "checks": {
            "nist_source_provenance": "PASS",
            "nist_keygen": "PASS",
            "nist_siggen": "PASS",
            "nist_sigver_accept_reject": "PASS",
            "pqbtc_sighash_vector": "PASS",
            "full_signature_byte_agreement": "PASS",
        },
        "signature_sha256": {
            "nist": siggen_vector["expected_signature_sha256"],
            "pqbtc": pqbtc_vector["expected_signature_sha256"],
        },
        "block_space_model": {
            **cost_model,
            "slh_dsa_signature_bytes": profile["signature_bytes"],
            "signature_size_increase_percent": round(
                (profile["signature_bytes"] / cost_model["held_rc2_signature_bytes"] - 1)
                * 100,
                2,
            ),
            "rc2_signature_only_capacity": rc2_capacity,
            "slh_dsa_signature_only_capacity": slh_capacity,
            "capacity_ratio_percent": round(slh_capacity / rc2_capacity * 100, 2),
        },
        "benchmark": {
            name: {
                "iterations": benchmark_iterations,
                "median_keygen_ms": median_ms(values["keygen_ns"]),
                "median_sign_ms": median_ms(values["sign_ns"]),
                "median_verify_ms": median_ms(values["verify_ns"]),
            }
            for name, values in benchmark.items()
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acvp-server",
        type=Path,
        help="path to the pinned usnistgov/ACVP-Server checkout (required for a full run)",
    )
    parser.add_argument(
        "--slhdsa-c",
        type=Path,
        default=Path(os.environ["SLHDSA_C_DIR"]) if "SLHDSA_C_DIR" in os.environ else None,
        help="path to the pinned slh-dsa/slhdsa-c checkout",
    )
    parser.add_argument(
        "--benchmark-iterations",
        type=int,
        default=1,
        help="repeat the PQBTC vector for median timings (1-10)",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="validate the checked-in profile and vector manifest without external oracles",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = load_manifest()
        if args.manifest_only:
            print("SLH-DSA reference manifest validation passed")
            return 0
        if args.slhdsa_c is None:
            raise ReferenceError("--slhdsa-c or SLHDSA_C_DIR is required")
        if args.acvp_server is None:
            raise ReferenceError("--acvp-server is required for a full run")
        if not 1 <= args.benchmark_iterations <= 10:
            raise ReferenceError("--benchmark-iterations must be between 1 and 10")

        nist_source_vectors = verify_nist_sources(manifest, args.acvp_server.resolve())

        with tempfile.TemporaryDirectory(prefix="pqbtc-slh-dsa-") as temporary:
            build_dir = Path(temporary)
            openssl_oracle = compile_openssl_oracle(build_dir)
            slhdsa_c_oracle = compile_slhdsa_c_oracle(
                build_dir,
                args.slhdsa_c.resolve(),
                manifest["sources"]["slhdsa_c"]["commit"],
            )
            report = evaluate(
                manifest,
                openssl_oracle,
                slhdsa_c_oracle,
                args.benchmark_iterations,
                nist_source_vectors,
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, KeyError, ReferenceError, ValueError) as error:
        print(f"compare_oracles.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
