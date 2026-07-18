#!/usr/bin/env python3
"""Build and compare independent SLH-DSA-SHA2-128s reference oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
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
    if manifest.get("schema_version") != 2:
        raise ReferenceError("manifest schema_version must be 2")

    profile = manifest["profile"]
    expected_profile = {
        "name": "SLH-DSA-SHA2-128s",
        "standard": "FIPS 205",
        "signature_interface": "external",
        "message_mode": "pure",
        "public_key_bytes": 32,
        "private_key_bytes": 64,
        "keygen_seed_bytes": 48,
        "randomizer_bytes": 16,
        "signature_bytes": 7856,
        "prototype_message_bytes": 32,
        "exact_vector_signing": "deterministic_or_fixed_randomizer",
        "production_signing_if_selected": "randomized",
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

    expected_acvp_coverage = {
        "keygen": {
            "group_id": 1,
            "test_case_ids": list(range(1, 11)),
        },
        "siggen": [
            {
                "group_id": 19,
                "deterministic": True,
                "signature_interface": "external",
                "message_mode": "pure",
                "test_case_ids": list(range(157, 164)),
            },
            {
                "group_id": 55,
                "deterministic": False,
                "signature_interface": "external",
                "message_mode": "pure",
                "test_case_ids": list(range(469, 476)),
            },
        ],
        "sigver": {
            "group_id": 19,
            "signature_interface": "external",
            "message_mode": "pure",
            "test_case_ids": list(range(253, 267)),
            "accepted_test_case_ids": [258, 266],
        },
        "total_cases": 38,
    }
    if manifest.get("acvp_coverage") != expected_acvp_coverage:
        raise ReferenceError("ACVP coverage does not match the frozen 38-case contract")

    sources = manifest["sources"]
    for source_name in ("nist_acvp", "openssl", "slhdsa_c"):
        if re.fullmatch(r"[0-9a-f]{40}", sources[source_name]["commit"]) is None:
            raise ReferenceError(f"{source_name} commit must be a full Git SHA")
    if sources["openssl"].get("version") != "3.6.3":
        raise ReferenceError("OpenSSL source and runtime version must be 3.6.3")
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
    require_hex(
        keygen["expected_private_key_hex"],
        profile["private_key_bytes"],
        "NIST private key",
    )
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
    require_hex(
        pqbtc["expected_private_key_hex"],
        profile["private_key_bytes"],
        "PQBTC private key",
    )
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


def require_command_failure(command: list[str], label: str) -> None:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0:
        raise ReferenceError(f"{label} unexpectedly succeeded")


def parse_version(value: str, label: str) -> tuple[int, int, int]:
    match = re.search(r"(?:OpenSSL )?(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise ReferenceError(f"cannot parse {label} version: {value}")
    return tuple(int(part) for part in match.groups())


def openssl_version(expected_version: str) -> tuple[str, tuple[int, int, int]]:
    output = run(["openssl", "version"]).strip()
    version = parse_version(output, "OpenSSL CLI")
    expected = parse_version(expected_version, "expected OpenSSL")
    if version != expected:
        raise ReferenceError(
            f"OpenSSL runtime mismatch: expected {expected_version}, got {version}"
        )
    pkg_config_output = run(["pkg-config", "--modversion", "openssl"]).strip()
    pkg_config_version = parse_version(pkg_config_output, "OpenSSL pkg-config")
    if pkg_config_version != version:
        raise ReferenceError(
            f"OpenSSL CLI/pkg-config mismatch: {version}, {pkg_config_version}"
        )
    return output, version


def compiler_mode_flags(sanitized: bool) -> list[str]:
    if sanitized:
        return [
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
        ]
    return ["-O2"]


def compile_openssl_oracle(
    build_dir: Path, expected_version: str, sanitized: bool = False
) -> Path:
    openssl_version(expected_version)
    compiler = os.environ.get("CC", "cc")
    pkg_config = shlex.split(run(["pkg-config", "--cflags", "--libs", "openssl"]))
    suffix = "_sanitized" if sanitized else ""
    output = build_dir / f"openssl_slh_dsa_oracle{suffix}"
    command = [
        compiler,
        "-std=c11",
        *compiler_mode_flags(sanitized),
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


def require_openssl_source(source_dir: Path, expected_commit: str) -> None:
    required_files = (
        "crypto/slh_dsa/slh_dsa.c",
        "doc/man7/EVP_SIGNATURE-SLH-DSA.pod",
        "providers/implementations/signature/slh_dsa_sig.c.in",
    )
    if any(not (source_dir / relative_path).is_file() for relative_path in required_files):
        raise ReferenceError(f"missing OpenSSL SLH-DSA source at {source_dir}")
    require_git_commit(source_dir, expected_commit, "OpenSSL")


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


def require_acvp_group(
    document: dict,
    group_id: int,
    expected_metadata: dict,
    expected_test_ids: list[int],
    label: str,
) -> dict:
    group = next(
        (candidate for candidate in document["testGroups"] if candidate["tgId"] == group_id),
        None,
    )
    if group is None:
        raise ReferenceError(f"missing {label} group {group_id}")
    for name, expected_value in expected_metadata.items():
        if group.get(name) != expected_value:
            raise ReferenceError(f"{label} group {group_id} {name} mismatch")
    actual_test_ids = [test["tcId"] for test in group["tests"]]
    if actual_test_ids != expected_test_ids:
        raise ReferenceError(f"{label} group {group_id} test-case set mismatch")
    return group


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

    profile = manifest["profile"]
    coverage = manifest["acvp_coverage"]
    vectors = manifest["vectors"]
    keygen_prompt = loaded["gen-val/json-files/SLH-DSA-keyGen-FIPS205/prompt.json"]
    keygen_expected = loaded[
        "gen-val/json-files/SLH-DSA-keyGen-FIPS205/expectedResults.json"
    ]
    keygen_contract = coverage["keygen"]
    keygen_group = require_acvp_group(
        keygen_prompt,
        keygen_contract["group_id"],
        {"parameterSet": profile["name"]},
        keygen_contract["test_case_ids"],
        "NIST keygen",
    )
    keygen_cases: list[dict] = []
    for source_case in keygen_group["tests"]:
        test_id = source_case["tcId"]
        _, source_result = find_test(keygen_expected, keygen_contract["group_id"], test_id)
        seed_hex = (
            source_case["skSeed"] + source_case["skPrf"] + source_case["pkSeed"]
        ).lower()
        private_key_hex = source_result["sk"].lower()
        public_key_hex = source_result["pk"].lower()
        require_hex(seed_hex, profile["keygen_seed_bytes"], f"NIST keygen {test_id} seed")
        require_hex(
            private_key_hex,
            profile["private_key_bytes"],
            f"NIST keygen {test_id} private key",
        )
        require_hex(
            public_key_hex,
            profile["public_key_bytes"],
            f"NIST keygen {test_id} public key",
        )
        keygen_cases.append(
            {
                "test_case_id": test_id,
                "seed_hex": seed_hex,
                "private_key_hex": private_key_hex,
                "public_key_hex": public_key_hex,
            }
        )

    representative_keygen = vectors["nist_keygen_tg1_tc1"]
    first_keygen = keygen_cases[0]
    require_equal(
        "NIST source keygen seed",
        first_keygen["seed_hex"],
        representative_keygen["seed_hex"],
    )
    require_equal(
        "NIST source private key",
        first_keygen["private_key_hex"],
        representative_keygen["expected_private_key_hex"],
    )
    require_equal(
        "NIST source public key",
        first_keygen["public_key_hex"],
        representative_keygen["expected_public_key_hex"],
    )

    siggen_prompt = loaded["gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json"]
    siggen_expected = loaded[
        "gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json"
    ]
    siggen_cases: list[dict] = []
    for siggen_contract in coverage["siggen"]:
        group_id = siggen_contract["group_id"]
        group = require_acvp_group(
            siggen_prompt,
            group_id,
            {
                "parameterSet": profile["name"],
                "deterministic": siggen_contract["deterministic"],
                "signatureInterface": siggen_contract["signature_interface"],
                "preHash": siggen_contract["message_mode"],
            },
            siggen_contract["test_case_ids"],
            "NIST siggen",
        )
        for source_case in group["tests"]:
            test_id = source_case["tcId"]
            _, source_result = find_test(siggen_expected, group_id, test_id)
            randomizer_hex = source_case.get("additionalRandomness")
            if siggen_contract["deterministic"]:
                if randomizer_hex is not None:
                    raise ReferenceError(
                        f"NIST deterministic siggen {test_id} has additional randomness"
                    )
            else:
                if randomizer_hex is None:
                    raise ReferenceError(f"NIST randomized siggen {test_id} lacks randomness")
                randomizer_hex = randomizer_hex.lower()
                require_hex(
                    randomizer_hex,
                    profile["randomizer_bytes"],
                    f"NIST siggen {test_id} randomizer",
                )
            signature_hex = source_result["signature"].lower()
            require_hex(
                source_case["sk"].lower(),
                profile["private_key_bytes"],
                f"NIST siggen {test_id} private key",
            )
            require_hex(
                signature_hex,
                profile["signature_bytes"],
                f"NIST siggen {test_id} signature",
            )
            context_hex = source_case.get("context", "").lower()
            if len(bytes.fromhex(context_hex)) > 255:
                raise ReferenceError(f"NIST siggen {test_id} context exceeds 255 bytes")
            siggen_cases.append(
                {
                    "group_id": group_id,
                    "test_case_id": test_id,
                    "deterministic": siggen_contract["deterministic"],
                    "private_key_hex": source_case["sk"].lower(),
                    "message_hex": source_case["message"].lower(),
                    "context_hex": context_hex,
                    "randomizer_hex": randomizer_hex,
                    "signature_hex": signature_hex,
                }
            )

    representative_siggen = vectors["nist_siggen_tg19_tc161"]
    selected_siggen = next(case for case in siggen_cases if case["test_case_id"] == 161)
    for source_name, manifest_name in (
        ("private_key_hex", "private_key_hex"),
        ("message_hex", "message_hex"),
        ("context_hex", "context_hex"),
    ):
        require_equal(
            f"NIST source siggen {source_name}",
            selected_siggen[source_name],
            representative_siggen[manifest_name],
        )
    require_equal(
        "NIST source signature hash",
        sha256_hex(selected_siggen["signature_hex"]),
        representative_siggen["expected_signature_sha256"],
    )

    sigver_prompt = loaded["gen-val/json-files/SLH-DSA-sigVer-FIPS205/prompt.json"]
    sigver_expected = loaded[
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/expectedResults.json"
    ]
    sigver_contract = coverage["sigver"]
    sigver_group = require_acvp_group(
        sigver_prompt,
        sigver_contract["group_id"],
        {
            "parameterSet": profile["name"],
            "signatureInterface": sigver_contract["signature_interface"],
            "preHash": sigver_contract["message_mode"],
        },
        sigver_contract["test_case_ids"],
        "NIST sigver",
    )
    accepted_ids = set(sigver_contract["accepted_test_case_ids"])
    sigver_cases: list[dict] = []
    for source_case in sigver_group["tests"]:
        test_id = source_case["tcId"]
        _, source_result = find_test(
            sigver_expected, sigver_contract["group_id"], test_id
        )
        expected_valid = test_id in accepted_ids
        if source_result.get("testPassed") is not expected_valid:
            raise ReferenceError(f"NIST source sigver {test_id} result mismatch")
        public_key_hex = source_case["pk"].lower()
        context_hex = source_case["context"].lower()
        require_hex(
            public_key_hex,
            profile["public_key_bytes"],
            f"NIST sigver {test_id} public key",
        )
        if len(bytes.fromhex(context_hex)) > 255:
            raise ReferenceError(f"NIST sigver {test_id} context exceeds 255 bytes")
        sigver_cases.append(
            {
                "test_case_id": test_id,
                "public_key_hex": public_key_hex,
                "message_hex": source_case["message"].lower(),
                "context_hex": context_hex,
                "signature_hex": source_case["signature"].lower(),
                "expected_valid": expected_valid,
            }
        )

    representative_sigver = vectors["nist_sigver_tg19"]
    sigver_by_id = {case["test_case_id"]: case for case in sigver_cases}
    for expected_case in representative_sigver["cases"]:
        test_id = expected_case["test_case_id"]
        source_case = sigver_by_id[test_id]
        require_equal(
            f"NIST source sigver {test_id} public key",
            source_case["public_key_hex"],
            expected_case["public_key_hex"],
        )
        for field in ("message", "context", "signature"):
            source_hex = source_case[f"{field}_hex"]
            if len(source_hex) != expected_case[f"{field}_bytes"] * 2:
                raise ReferenceError(f"NIST source sigver {test_id} {field} size mismatch")
            require_equal(
                f"NIST source sigver {test_id} {field} hash",
                sha256_hex(source_hex),
                expected_case[f"{field}_sha256"],
            )
        if source_case["expected_valid"] is not expected_case["expected_valid"]:
            raise ReferenceError(f"NIST source sigver {test_id} result mismatch")

    actual_total = len(keygen_cases) + len(siggen_cases) + len(sigver_cases)
    if actual_total != coverage["total_cases"]:
        raise ReferenceError("NIST selected-profile ACVP case count mismatch")
    return {
        "keygen_cases": keygen_cases,
        "siggen_cases": siggen_cases,
        "sigver_cases": sigver_cases,
        "total_cases": actual_total,
    }


def compile_slhdsa_c_oracle(
    build_dir: Path,
    source_dir: Path,
    expected_commit: str,
    sanitized: bool = False,
) -> Path:
    require_slhdsa_c_source(source_dir, expected_commit)
    sources = sorted(str(path) for path in source_dir.glob("*.c"))
    if not sources:
        raise ReferenceError("slhdsa-c source list is empty")
    compiler = os.environ.get("CC", "cc")
    suffix = "_sanitized" if sanitized else ""
    output = build_dir / f"slhdsa_c_oracle{suffix}"
    command = [
        compiler,
        "-std=c99",
        *compiler_mode_flags(sanitized),
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
    executable: Path,
    private_key_hex: str,
    message_hex: str,
    context_hex: str,
    randomizer_hex: str | None = None,
    randomized: bool = False,
) -> dict[str, str]:
    if randomizer_hex is not None and randomized:
        raise ReferenceError("fixed and default randomized signing are mutually exclusive")
    command = "sign-randomized" if randomized else "sign"
    arguments = [str(executable), command, private_key_hex, message_hex, context_hex]
    if randomizer_hex is not None:
        arguments[1] = "sign-with-randomizer"
        arguments.append(randomizer_hex)
    result = parse_oracle_output(
        run(arguments)
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


def flip_hex_byte(value: str, byte_index: int) -> str:
    data = bytearray.fromhex(value)
    data[byte_index] ^= 1
    return data.hex()


def require_verification(
    oracles: dict[str, Path],
    public_key_hex: str,
    message_hex: str,
    context_hex: str,
    signature_hex: str,
    expected: str,
    label: str,
) -> None:
    results = {
        name: oracle_verify(
            executable,
            public_key_hex,
            message_hex,
            context_hex,
            signature_hex,
        )["verified"]
        for name, executable in oracles.items()
    }
    require_equal(label, *results.values(), expected)


def median_ms(values: list[int]) -> float:
    return round(statistics.median(values) / 1_000_000, 3)


def evaluate_acvp(profile: dict, oracles: dict[str, Path], source_cases: dict) -> None:
    for case in source_cases["keygen_cases"]:
        results = {
            name: oracle_keygen(executable, case["seed_hex"])
            for name, executable in oracles.items()
        }
        for result in results.values():
            require_equal(
                f"NIST keygen {case['test_case_id']} public key",
                result["pk"],
                case["public_key_hex"],
            )
            require_equal(
                f"NIST keygen {case['test_case_id']} private key",
                result["sk"],
                case["private_key_hex"],
            )
        require_equal(
            f"oracle keygen {case['test_case_id']} public key",
            *(result["pk"] for result in results.values()),
        )
        require_equal(
            f"oracle keygen {case['test_case_id']} private key",
            *(result["sk"] for result in results.values()),
        )

    for case in source_cases["siggen_cases"]:
        results = {
            name: oracle_sign(
                executable,
                case["private_key_hex"],
                case["message_hex"],
                case["context_hex"],
                randomizer_hex=case["randomizer_hex"],
            )
            for name, executable in oracles.items()
        }
        for result in results.values():
            signature_hash(result["signature"], profile["signature_bytes"])
            require_equal(
                f"NIST siggen {case['test_case_id']} signature",
                result["signature"],
                case["signature_hex"],
            )
        require_equal(
            f"oracle siggen {case['test_case_id']} signature",
            *(result["signature"] for result in results.values()),
        )
        public_key_hex = case["private_key_hex"][-profile["public_key_bytes"] * 2 :]
        require_verification(
            oracles,
            public_key_hex,
            case["message_hex"],
            case["context_hex"],
            case["signature_hex"],
            "1",
            f"cross-verification for NIST siggen {case['test_case_id']}",
        )

    for case in source_cases["sigver_cases"]:
        require_verification(
            oracles,
            case["public_key_hex"],
            case["message_hex"],
            case["context_hex"],
            case["signature_hex"],
            "1" if case["expected_valid"] else "0",
            f"NIST sigver {case['test_case_id']}",
        )


def evaluate_randomized_interoperability(
    profile: dict, oracles: dict[str, Path], pqbtc_vector: dict
) -> dict:
    randomizers = [secrets.token_hex(profile["randomizer_bytes"]) for _ in range(2)]
    while randomizers[0] == randomizers[1]:
        randomizers[1] = secrets.token_hex(profile["randomizer_bytes"])

    fixed_signatures: list[str] = []
    for index, randomizer_hex in enumerate(randomizers, start=1):
        results = {
            name: oracle_sign(
                executable,
                pqbtc_vector["expected_private_key_hex"],
                pqbtc_vector["message_hex"],
                pqbtc_vector["context_hex"],
                randomizer_hex=randomizer_hex,
            )
            for name, executable in oracles.items()
        }
        require_equal(
            f"fixed-randomizer signature round {index}",
            *(result["signature"] for result in results.values()),
        )
        signature_hex = next(iter(results.values()))["signature"]
        signature_hash(signature_hex, profile["signature_bytes"])
        fixed_signatures.append(signature_hex)
        require_verification(
            oracles,
            pqbtc_vector["expected_public_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
            signature_hex,
            "1",
            f"fixed-randomizer cross-verification round {index}",
        )
    if fixed_signatures[0] == fixed_signatures[1]:
        raise ReferenceError("distinct fixed randomizers produced the same signature")

    openssl_signatures = [
        oracle_sign(
            oracles["openssl"],
            pqbtc_vector["expected_private_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
            randomized=True,
        )["signature"]
        for _ in range(2)
    ]
    if openssl_signatures[0] == openssl_signatures[1]:
        raise ReferenceError("OpenSSL DRBG signing repeated a signature")
    for index, signature_hex in enumerate(openssl_signatures, start=1):
        signature_hash(signature_hex, profile["signature_bytes"])
        require_verification(
            oracles,
            pqbtc_vector["expected_public_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
            signature_hex,
            "1",
            f"OpenSSL DRBG cross-verification round {index}",
        )
    return {
        "fixed_randomizer_rounds": len(fixed_signatures),
        "openssl_drbg_rounds": len(openssl_signatures),
    }


def evaluate_boundaries_and_mutations(
    profile: dict,
    oracles: dict[str, Path],
    pqbtc_vector: dict,
    deterministic_signature_hex: str,
) -> dict:
    boundary_cases = (
        ("empty message and context", "", ""),
        ("maximum context", pqbtc_vector["message_hex"], "a5" * 255),
    )
    for label, message_hex, context_hex in boundary_cases:
        results = {
            name: oracle_sign(
                executable,
                pqbtc_vector["expected_private_key_hex"],
                message_hex,
                context_hex,
            )
            for name, executable in oracles.items()
        }
        require_equal(
            f"{label} signature bytes",
            *(result["signature"] for result in results.values()),
        )
        signature_hex = next(iter(results.values()))["signature"]
        signature_hash(signature_hex, profile["signature_bytes"])
        require_verification(
            oracles,
            pqbtc_vector["expected_public_key_hex"],
            message_hex,
            context_hex,
            signature_hex,
            "1",
            f"{label} cross-verification",
        )

    public_key_hex = pqbtc_vector["expected_public_key_hex"]
    message_hex = pqbtc_vector["message_hex"]
    context_hex = pqbtc_vector["context_hex"]
    mutations = (
        (
            "public key",
            flip_hex_byte(public_key_hex, 0),
            message_hex,
            context_hex,
            deterministic_signature_hex,
        ),
        (
            "message first byte",
            public_key_hex,
            flip_hex_byte(message_hex, 0),
            context_hex,
            deterministic_signature_hex,
        ),
        (
            "message last byte",
            public_key_hex,
            flip_hex_byte(message_hex, -1),
            context_hex,
            deterministic_signature_hex,
        ),
        (
            "context first byte",
            public_key_hex,
            message_hex,
            flip_hex_byte(context_hex, 0),
            deterministic_signature_hex,
        ),
        (
            "context last byte",
            public_key_hex,
            message_hex,
            flip_hex_byte(context_hex, -1),
            deterministic_signature_hex,
        ),
        (
            "signature first byte",
            public_key_hex,
            message_hex,
            context_hex,
            flip_hex_byte(deterministic_signature_hex, 0),
        ),
        (
            "signature middle byte",
            public_key_hex,
            message_hex,
            context_hex,
            flip_hex_byte(
                deterministic_signature_hex, profile["signature_bytes"] // 2
            ),
        ),
        (
            "signature last byte",
            public_key_hex,
            message_hex,
            context_hex,
            flip_hex_byte(deterministic_signature_hex, -1),
        ),
        (
            "signature truncated",
            public_key_hex,
            message_hex,
            context_hex,
            deterministic_signature_hex[:-2],
        ),
        (
            "signature extended",
            public_key_hex,
            message_hex,
            context_hex,
            deterministic_signature_hex + "00",
        ),
        ("signature empty", public_key_hex, message_hex, context_hex, ""),
    )
    for label, key, message, context, signature in mutations:
        require_verification(
            oracles,
            key,
            message,
            context,
            signature,
            "0",
            f"mutated {label} rejection",
        )

    oversized_context = "00" * 256
    malformed_commands = 0
    for executable in oracles.values():
        commands = (
            [str(executable), "keygen", pqbtc_vector["seed_hex"][:-2]],
            [str(executable), "keygen", pqbtc_vector["seed_hex"] + "00"],
            [
                str(executable),
                "sign",
                pqbtc_vector["expected_private_key_hex"][:-2],
                message_hex,
                context_hex,
            ],
            [
                str(executable),
                "sign",
                pqbtc_vector["expected_private_key_hex"] + "00",
                message_hex,
                context_hex,
            ],
            [
                str(executable),
                "sign",
                pqbtc_vector["expected_private_key_hex"],
                message_hex,
                oversized_context,
            ],
            [
                str(executable),
                "sign-with-randomizer",
                pqbtc_vector["expected_private_key_hex"],
                message_hex,
                context_hex,
                "00" * 15,
            ],
            [
                str(executable),
                "sign-with-randomizer",
                pqbtc_vector["expected_private_key_hex"],
                message_hex,
                context_hex,
                "00" * 17,
            ],
            [
                str(executable),
                "verify",
                public_key_hex[:-2],
                message_hex,
                context_hex,
                deterministic_signature_hex,
            ],
            [
                str(executable),
                "verify",
                public_key_hex + "00",
                message_hex,
                context_hex,
                deterministic_signature_hex,
            ],
            [
                str(executable),
                "verify",
                public_key_hex,
                message_hex,
                oversized_context,
                deterministic_signature_hex,
            ],
        )
        for index, command in enumerate(commands, start=1):
            require_command_failure(command, f"{executable.name} malformed input {index}")
            malformed_commands += 1
    return {
        "boundary_cases": len(boundary_cases),
        "cryptographic_rejections": len(mutations),
        "malformed_input_rejections": malformed_commands,
    }


def benchmark_profile(
    profile: dict,
    oracles: dict[str, Path],
    pqbtc_vector: dict,
    benchmark_iterations: int,
) -> dict:
    benchmark = {
        name: {
            "keygen_ns": [],
            "deterministic_sign_ns": [],
            "deterministic_verify_ns": [],
            "randomized_sign_ns": [],
            "randomized_verify_ns": [],
        }
        for name in oracles
    }
    for _ in range(benchmark_iterations):
        deterministic_signatures: dict[str, str] = {}
        for name, executable in oracles.items():
            generated = oracle_keygen(executable, pqbtc_vector["seed_hex"])
            require_equal(
                "PQBTC public key", generated["pk"], pqbtc_vector["expected_public_key_hex"]
            )
            require_equal(
                "PQBTC private key", generated["sk"], pqbtc_vector["expected_private_key_hex"]
            )
            deterministic = oracle_sign(
                executable,
                generated["sk"],
                pqbtc_vector["message_hex"],
                pqbtc_vector["context_hex"],
            )
            require_equal(
                "PQBTC deterministic signature hash",
                signature_hash(deterministic["signature"], profile["signature_bytes"]),
                pqbtc_vector["expected_signature_sha256"],
            )
            deterministic_signatures[name] = deterministic["signature"]
            if name == "openssl":
                randomized = oracle_sign(
                    executable,
                    generated["sk"],
                    pqbtc_vector["message_hex"],
                    pqbtc_vector["context_hex"],
                    randomized=True,
                )
            else:
                randomized = oracle_sign(
                    executable,
                    generated["sk"],
                    pqbtc_vector["message_hex"],
                    pqbtc_vector["context_hex"],
                    randomizer_hex=secrets.token_hex(profile["randomizer_bytes"]),
                )
            signature_hash(randomized["signature"], profile["signature_bytes"])
            require_verification(
                oracles,
                generated["pk"],
                pqbtc_vector["message_hex"],
                pqbtc_vector["context_hex"],
                randomized["signature"],
                "1",
                f"{name} randomized benchmark signature",
            )
            benchmark[name]["keygen_ns"].append(int(generated["keygen_ns"]))
            benchmark[name]["deterministic_sign_ns"].append(int(deterministic["sign_ns"]))
            benchmark[name]["deterministic_verify_ns"].append(int(deterministic["verify_ns"]))
            benchmark[name]["randomized_sign_ns"].append(int(randomized["sign_ns"]))
            benchmark[name]["randomized_verify_ns"].append(int(randomized["verify_ns"]))
        require_equal("PQBTC deterministic signature bytes", *deterministic_signatures.values())

    return {
        name: {
            "iterations": benchmark_iterations,
            "median_keygen_ms": median_ms(values["keygen_ns"]),
            "deterministic": {
                "median_sign_ms": median_ms(values["deterministic_sign_ns"]),
                "median_verify_ms": median_ms(values["deterministic_verify_ns"]),
            },
            "randomized": {
                "median_sign_ms": median_ms(values["randomized_sign_ns"]),
                "median_verify_ms": median_ms(values["randomized_verify_ns"]),
            },
        }
        for name, values in benchmark.items()
    }


def evaluate_sanitized_smoke(
    profile: dict, oracles: dict[str, Path], pqbtc_vector: dict
) -> dict:
    deterministic = {
        name: oracle_sign(
            executable,
            pqbtc_vector["expected_private_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
        )["signature"]
        for name, executable in oracles.items()
    }
    require_equal("sanitized deterministic signatures", *deterministic.values())
    boundary_report = evaluate_boundaries_and_mutations(
        profile,
        oracles,
        pqbtc_vector,
        next(iter(deterministic.values())),
    )
    randomizer_hex = secrets.token_hex(profile["randomizer_bytes"])
    randomized = {
        name: oracle_sign(
            executable,
            pqbtc_vector["expected_private_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
            randomizer_hex=randomizer_hex,
        )["signature"]
        for name, executable in oracles.items()
    }
    require_equal("sanitized fixed-randomizer signatures", *randomized.values())
    return boundary_report


def evaluate(
    manifest: dict,
    oracles: dict[str, Path],
    benchmark_iterations: int,
    nist_source_vectors: dict,
    sanitized_report: dict | None,
) -> dict:
    profile = manifest["profile"]
    vectors = manifest["vectors"]
    evaluate_acvp(profile, oracles, nist_source_vectors)

    pqbtc_vector = vectors["pqbtc_sighash_v1"]
    deterministic_results = {
        name: oracle_sign(
            executable,
            pqbtc_vector["expected_private_key_hex"],
            pqbtc_vector["message_hex"],
            pqbtc_vector["context_hex"],
        )
        for name, executable in oracles.items()
    }
    require_equal(
        "PQBTC deterministic signature bytes",
        *(result["signature"] for result in deterministic_results.values()),
    )
    deterministic_signature = next(iter(deterministic_results.values()))["signature"]
    require_equal(
        "PQBTC deterministic signature hash",
        signature_hash(deterministic_signature, profile["signature_bytes"]),
        pqbtc_vector["expected_signature_sha256"],
    )
    randomized_report = evaluate_randomized_interoperability(profile, oracles, pqbtc_vector)
    mutation_report = evaluate_boundaries_and_mutations(
        profile, oracles, pqbtc_vector, deterministic_signature
    )
    benchmark = benchmark_profile(
        profile, oracles, pqbtc_vector, benchmark_iterations
    )

    version_text, _ = openssl_version(manifest["sources"]["openssl"]["version"])
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
        "openssl_commit": manifest["sources"]["openssl"]["commit"],
        "slhdsa_c_commit": manifest["sources"]["slhdsa_c"]["commit"],
        "checks": {
            "nist_source_provenance": "PASS",
            "nist_selected_profile_acvp_38_cases": "PASS",
            "nist_deterministic_and_randomized_siggen": "PASS",
            "nist_sigver_all_accept_reject_cases": "PASS",
            "pqbtc_sighash_vector": "PASS",
            "full_signature_byte_agreement": "PASS",
            "randomized_interoperability": "PASS",
            "boundary_and_mutation_rejection": "PASS",
            "adapter_asan_ubsan": "PASS" if sanitized_report is not None else "NOT_RUN",
        },
        "acvp": {
            "total_cases": nist_source_vectors["total_cases"],
            "keygen_cases": len(nist_source_vectors["keygen_cases"]),
            "siggen_cases": len(nist_source_vectors["siggen_cases"]),
            "sigver_cases": len(nist_source_vectors["sigver_cases"]),
        },
        "randomized_interoperability": randomized_report,
        "negative_testing": mutation_report,
        "sanitized_smoke": sanitized_report,
        "signature_sha256": {
            "nist": vectors["nist_siggen_tg19_tc161"]["expected_signature_sha256"],
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
        "benchmark": benchmark,
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
        "--openssl-source",
        type=Path,
        default=(
            Path(os.environ["OPENSSL_SOURCE_DIR"])
            if "OPENSSL_SOURCE_DIR" in os.environ
            else None
        ),
        help="path to the pinned OpenSSL source checkout",
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
    parser.add_argument(
        "--sanitizers",
        action="store_true",
        help="also build and exercise both adapters with ASan and UBSan",
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
        if args.openssl_source is None:
            raise ReferenceError("--openssl-source or OPENSSL_SOURCE_DIR is required")
        if args.acvp_server is None:
            raise ReferenceError("--acvp-server is required for a full run")
        if not 1 <= args.benchmark_iterations <= 10:
            raise ReferenceError("--benchmark-iterations must be between 1 and 10")

        nist_source_vectors = verify_nist_sources(manifest, args.acvp_server.resolve())
        require_openssl_source(
            args.openssl_source.resolve(), manifest["sources"]["openssl"]["commit"]
        )

        with tempfile.TemporaryDirectory(prefix="pqbtc-slh-dsa-") as temporary:
            build_dir = Path(temporary)
            openssl_oracle = compile_openssl_oracle(
                build_dir, manifest["sources"]["openssl"]["version"]
            )
            slhdsa_c_oracle = compile_slhdsa_c_oracle(
                build_dir,
                args.slhdsa_c.resolve(),
                manifest["sources"]["slhdsa_c"]["commit"],
            )
            oracles = {
                "openssl": openssl_oracle,
                "slhdsa_c": slhdsa_c_oracle,
            }
            sanitized_report = None
            if args.sanitizers:
                sanitized_oracles = {
                    "openssl": compile_openssl_oracle(
                        build_dir,
                        manifest["sources"]["openssl"]["version"],
                        sanitized=True,
                    ),
                    "slhdsa_c": compile_slhdsa_c_oracle(
                        build_dir,
                        args.slhdsa_c.resolve(),
                        manifest["sources"]["slhdsa_c"]["commit"],
                        sanitized=True,
                    ),
                }
                sanitized_report = evaluate_sanitized_smoke(
                    manifest["profile"],
                    sanitized_oracles,
                    manifest["vectors"]["pqbtc_sighash_v1"],
                )
            report = evaluate(
                manifest,
                oracles,
                args.benchmark_iterations,
                nist_source_vectors,
                sanitized_report,
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, KeyError, ReferenceError, ValueError) as error:
        print(f"compare_oracles.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
