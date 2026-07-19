#!/usr/bin/env python3
"""Build and compare pinned ML-DSA-44 reference oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "vectors.json"
OPENSSL_SOURCE = HERE / "openssl_oracle.c"
MLDSA_NATIVE_SOURCE = HERE / "mldsa_native_oracle.c"
LIBCRUX_SOURCE = HERE / "libcrux_oracle.rs"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ReferenceError(RuntimeError):
    pass


class Oracle:
    def __init__(
        self,
        executable: Path,
        derives_public_key: bool = True,
        sign_requires_public_key: bool = False,
    ) -> None:
        self.executable = executable
        self.derives_public_key = derives_public_key
        self.sign_requires_public_key = sign_requires_public_key


def require_hex(value: str, byte_length: int, label: str) -> None:
    if len(value) != byte_length * 2 or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise ReferenceError(f"{label} must be {byte_length} lowercase-hex bytes")


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schema_version") != 3:
        raise ReferenceError("manifest schema_version must be 3")

    profile = manifest["profile"]
    expected_profile = {
        "name": "ML-DSA-44",
        "standard": "FIPS 204",
        "nist_security_category": 2,
        "signature_interface": "external",
        "message_mode": "pure",
        "public_key_bytes": 1312,
        "private_key_bytes": 2560,
        "keygen_seed_bytes": 32,
        "randomizer_bytes": 32,
        "signature_bytes": 2420,
        "prototype_message_bytes": 32,
        "exact_vector_signing": "deterministic_or_fixed_randomizer",
        "production_signing_if_selected": "hedged_randomized",
    }
    for name, expected in expected_profile.items():
        if profile.get(name) != expected:
            raise ReferenceError(f"profile {name} must be {expected!r}")

    context_hex = profile["prototype_context_hex"]
    if bytes.fromhex(context_hex).decode("ascii") != profile["prototype_context_ascii"]:
        raise ReferenceError("prototype context hex/ascii mismatch")
    if len(bytes.fromhex(context_hex)) > 255:
        raise ReferenceError("prototype context exceeds FIPS 204 limit")

    expected_cost_model = {
        "held_rc2_signature_bytes": 4480,
        "held_rc2_public_key_bytes": 33,
        "block_weight_limit": 16_000_000,
        "witness_weight_per_byte": 1,
        "non_witness_weight_per_byte": 4,
    }
    if manifest.get("system_cost_model") != expected_cost_model:
        raise ReferenceError("system cost model does not match the held PQBTC baseline")

    expected_acvp_coverage = {
        "keygen": {"group_id": 1, "test_case_ids": list(range(1, 26))},
        "siggen": [
            {
                "group_id": 1,
                "deterministic": True,
                "signature_interface": "external",
                "message_mode": "pure",
                "test_case_ids": list(range(1, 16)),
            },
            {
                "group_id": 13,
                "deterministic": False,
                "signature_interface": "external",
                "message_mode": "pure",
                "test_case_ids": list(range(181, 196)),
            },
        ],
        "sigver": {
            "group_id": 1,
            "signature_interface": "external",
            "message_mode": "pure",
            "test_case_ids": list(range(1, 16)),
            "accepted_test_case_ids": [6, 7, 11],
        },
        "total_cases": 70,
    }
    if manifest.get("acvp_coverage") != expected_acvp_coverage:
        raise ReferenceError("ACVP coverage does not match the frozen 70-case contract")

    sources = manifest["sources"]
    for source_name in ("nist_acvp", "openssl", "mldsa_native", "libcrux"):
        if re.fullmatch(r"[0-9a-f]{40}", sources[source_name]["commit"]) is None:
            raise ReferenceError(f"{source_name} commit must be a full Git SHA")
    if sources["openssl"].get("version") != "3.6.3":
        raise ReferenceError("OpenSSL source and runtime version must be 3.6.3")
    if sources["mldsa_native"].get("tag") != "v1.0.0-beta2":
        raise ReferenceError("mldsa-native tag must be v1.0.0-beta2")
    libcrux = sources["libcrux"]
    if libcrux.get("tag") != "libcrux-ml-dsa-v0.0.10":
        raise ReferenceError("libcrux tag must be libcrux-ml-dsa-v0.0.10")
    if libcrux.get("version") != "0.0.10":
        raise ReferenceError("libcrux version must be 0.0.10")
    for field in ("tag_object", "git_tree", "initial_implementation_commit"):
        if re.fullmatch(r"[0-9a-f]{40}", libcrux.get(field, "")) is None:
            raise ReferenceError(f"libcrux {field} must be a full Git object ID")
    if HEX_64.fullmatch(libcrux.get("crate_sha256", "")) is None:
        raise ReferenceError("libcrux crate_sha256 must be SHA256")
    if libcrux.get("license_expression") != "Apache-2.0":
        raise ReferenceError("libcrux license must be Apache-2.0")
    assessment = libcrux.get("independence_assessment", {})
    if assessment.get("outcome") != "separate_implementation_lineage_with_reference_influence":
        raise ReferenceError("libcrux independence assessment outcome mismatch")
    if assessment.get("normal_pqclean_or_pq_crystals_dependency") is not False:
        raise ReferenceError("libcrux normal dependency assessment must be false")
    expected_advisories = {
        "RUSTSEC-2026-0076": {
            "ghsa": "GHSA-xrf2-5r3p-5wgj",
            "fixed_in": "0.0.8",
            "upstream_test": "bad_hint_out_of_bounds",
        },
        "RUSTSEC-2026-0077": {
            "ghsa": "GHSA-cp57-fq8g-qh6v",
            "fixed_in": "0.0.8",
            "upstream_test": "mask_exceeds_norm",
        },
    }
    if libcrux.get("fixed_advisories") != expected_advisories:
        raise ReferenceError("libcrux fixed-advisory contract mismatch")
    for source_name in (
        "nist_fips204",
        "nist_fips204_potential_updates",
        "nist_fips204_section6_guidance",
    ):
        if HEX_64.fullmatch(sources[source_name].get("sha256", "")) is None:
            raise ReferenceError(f"{source_name} must pin a SHA256 value")

    expected_nist_files = {
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json",
    }
    nist_files = sources["nist_acvp"]["files"]
    if set(nist_files) != expected_nist_files:
        raise ReferenceError("NIST source file set does not match the reference contract")
    if any(HEX_64.fullmatch(value) is None for value in nist_files.values()):
        raise ReferenceError("NIST source hashes must be SHA256 values")

    vectors = manifest["vectors"]
    keygen = vectors["nist_keygen_tg1_tc1"]
    require_hex(keygen["seed_hex"], profile["keygen_seed_bytes"], "NIST keygen seed")
    for field in ("expected_private_key_sha256", "expected_public_key_sha256"):
        if HEX_64.fullmatch(keygen[field]) is None:
            raise ReferenceError(f"NIST keygen {field} must be SHA256")

    for vector_name, expected_group, expected_test, deterministic in (
        ("nist_siggen_tg1_tc1", 1, 1, True),
        ("nist_siggen_tg13_tc181", 13, 181, False),
    ):
        vector = vectors[vector_name]
        if vector.get("group_id") != expected_group:
            raise ReferenceError(f"{vector_name} group identity mismatch")
        if vector.get("test_case_id") != expected_test:
            raise ReferenceError(f"{vector_name} test identity mismatch")
        if vector.get("deterministic") is not deterministic:
            raise ReferenceError(f"{vector_name} deterministic flag mismatch")
        if vector["context_bytes"] > 255:
            raise ReferenceError("NIST context exceeds FIPS 204 limit")
        for field in (
            "private_key_sha256",
            "message_sha256",
            "context_sha256",
            "expected_signature_sha256",
        ):
            if HEX_64.fullmatch(vector[field]) is None:
                raise ReferenceError(f"{vector_name} {field} must be SHA256")
        if deterministic:
            if "randomizer_hex" in vector:
                raise ReferenceError("deterministic vector must not include randomness")
        else:
            require_hex(
                vector["randomizer_hex"],
                profile["randomizer_bytes"],
                "NIST randomizer",
            )

    sigver = vectors["nist_sigver_tg1"]
    for name, expected in {
        "parameter_set": profile["name"],
        "signature_interface": profile["signature_interface"],
        "message_mode": profile["message_mode"],
    }.items():
        if sigver.get(name) != expected:
            raise ReferenceError(f"NIST sigver {name} must be {expected!r}")
    cases = sigver["cases"]
    if len(cases) != 2 or {case["test_case_id"] for case in cases} != {1, 6}:
        raise ReferenceError("NIST sigver representatives must be tcId 1 and 6")
    if {case["expected_valid"] for case in cases} != {False, True}:
        raise ReferenceError("NIST sigver representatives must include accept and reject")
    for case in cases:
        if case["context_bytes"] > 255:
            raise ReferenceError("NIST sigver context exceeds FIPS 204 limit")
        if case["signature_bytes"] != profile["signature_bytes"]:
            raise ReferenceError("NIST sigver signature size mismatch")
        for field in (
            "public_key_sha256",
            "message_sha256",
            "context_sha256",
            "signature_sha256",
        ):
            if HEX_64.fullmatch(case[field]) is None:
                raise ReferenceError(f"NIST sigver {field} must be SHA256")

    pqbtc = vectors["pqbtc_sighash_v1"]
    require_hex(pqbtc["seed_hex"], profile["keygen_seed_bytes"], "PQBTC keygen seed")
    require_hex(pqbtc["message_hex"], profile["prototype_message_bytes"], "PQBTC message")
    if pqbtc["context_hex"] != context_hex:
        raise ReferenceError("PQBTC vector does not use the frozen prototype context")
    for field in (
        "expected_private_key_sha256",
        "expected_public_key_sha256",
        "expected_signature_sha256",
    ):
        if HEX_64.fullmatch(pqbtc[field]) is None:
            raise ReferenceError(f"PQBTC {field} must be SHA256")


def load_manifest() -> dict:
    with MANIFEST_PATH.open(encoding="utf8") as manifest_file:
        manifest = json.load(manifest_file)
    validate_manifest(manifest)
    return manifest


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
        raise ReferenceError(
            f"command failed ({result.returncode}): {shlex.join(command)}\n"
            f"{result.stderr.strip()}"
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
    pkg_config_version = parse_version(
        run(["pkg-config", "--modversion", "openssl"]).strip(),
        "OpenSSL pkg-config",
    )
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
    output = build_dir / f"openssl_ml_dsa_oracle{suffix}"
    run(
        [
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
    )
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


def require_openssl_source(source_dir: Path, expected_commit: str) -> None:
    required_files = (
        "crypto/ml_dsa/ml_dsa_sign.c",
        "doc/man7/EVP_SIGNATURE-ML-DSA.pod",
        "providers/implementations/signature/ml_dsa_sig.c.in",
    )
    if any(not (source_dir / relative_path).is_file() for relative_path in required_files):
        raise ReferenceError(f"missing OpenSSL ML-DSA source at {source_dir}")
    require_git_commit(source_dir, expected_commit, "OpenSSL")


def require_mldsa_native_source(source_dir: Path, expected_commit: str) -> None:
    required_files = (
        "examples/monolithic_build/mldsa_native/mldsa_native.c",
        "examples/monolithic_build/mldsa_native/mldsa_native.h",
        "examples/monolithic_build/mldsa_native/mldsa_native_config.h",
    )
    if any(not (source_dir / relative_path).is_file() for relative_path in required_files):
        raise ReferenceError(f"missing mldsa-native source at {source_dir}")
    require_git_commit(source_dir, expected_commit, "mldsa-native")


def require_libcrux_source(source_dir: Path, source: dict) -> None:
    required_files = (
        "LICENSE",
        "libcrux-ml-dsa/Cargo.toml",
        "libcrux-ml-dsa/CHANGELOG.md",
        "libcrux-ml-dsa/src/IMPLEMENTATION-NOTES.md",
        "libcrux-ml-dsa/src/ml_dsa_generic.rs",
        "libcrux-ml-dsa/src/encoding/signature.rs",
        "libcrux-ml-dsa/tests/self.rs",
    )
    if any(not (source_dir / relative_path).is_file() for relative_path in required_files):
        raise ReferenceError(f"missing libcrux ML-DSA source at {source_dir}")
    require_git_commit(source_dir, source["commit"], "libcrux")

    tag_object = run(
        ["git", "rev-parse", f"refs/tags/{source['tag']}"], cwd=source_dir
    ).strip()
    if tag_object != source["tag_object"]:
        raise ReferenceError(
            f"libcrux tag object mismatch: expected {source['tag_object']}, "
            f"got {tag_object}"
        )
    tagged_commit = run(
        ["git", "rev-parse", f"{source['tag']}^{{commit}}"], cwd=source_dir
    ).strip()
    if tagged_commit != source["commit"]:
        raise ReferenceError(
            f"libcrux tag commit mismatch: expected {source['commit']}, "
            f"got {tagged_commit}"
        )
    tree = run(["git", "rev-parse", "HEAD:libcrux-ml-dsa"], cwd=source_dir).strip()
    if tree != source["git_tree"]:
        raise ReferenceError(
            f"libcrux ML-DSA tree mismatch: expected {source['git_tree']}, got {tree}"
        )
    run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            source["initial_implementation_commit"],
            "HEAD",
        ],
        cwd=source_dir,
    )
    ml_dsa_history = run(
        ["git", "log", "--reverse", "--format=%H", "--", "libcrux-ml-dsa"],
        cwd=source_dir,
    ).splitlines()
    if not ml_dsa_history or ml_dsa_history[0] != source["initial_implementation_commit"]:
        raise ReferenceError("libcrux initial ML-DSA implementation commit mismatch")

    cargo_manifest = (source_dir / "libcrux-ml-dsa/Cargo.toml").read_text(
        encoding="utf8"
    )
    if re.search(r'^version = "0\.0\.10"$', cargo_manifest, re.MULTILINE) is None:
        raise ReferenceError("libcrux source package version mismatch")
    manifest_sections = cargo_manifest.split("[dependencies]", 1)
    if len(manifest_sections) != 2:
        raise ReferenceError("libcrux source has no normal dependency section")
    dependency_section = manifest_sections[1].split("\n[", 1)[0]
    if re.search(r"pqclean|pq[-_]crystals", dependency_section, re.IGNORECASE):
        raise ReferenceError("libcrux has an unexpected normal PQClean/PQ-Crystals dependency")


def prepare_libcrux_crate(build_dir: Path, artifact: Path, source: dict) -> Path:
    require_artifact(artifact, source["crate_sha256"], "libcrux ML-DSA crate")
    expected_root = f"libcrux-ml-dsa-{source['version']}"
    extraction_root = build_dir / "libcrux-crate"
    extraction_root.mkdir()
    with tarfile.open(artifact, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise ReferenceError("libcrux crate archive is empty")
        for member in members:
            member_path = Path(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or member_path.parts[0] != expected_root
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ReferenceError(f"unsafe libcrux crate member: {member.name}")
        if sys.version_info >= (3, 12):
            archive.extractall(extraction_root, filter="data")
        else:
            archive.extractall(extraction_root)

    crate_dir = extraction_root / expected_root
    vcs_info_path = crate_dir / ".cargo_vcs_info.json"
    cargo_manifest_path = crate_dir / "Cargo.toml"
    cargo_lock_path = crate_dir / "Cargo.lock"
    if not all(path.is_file() for path in (vcs_info_path, cargo_manifest_path, cargo_lock_path)):
        raise ReferenceError("libcrux crate is missing pinned package metadata")
    vcs_info = json.loads(vcs_info_path.read_text(encoding="utf8"))
    if vcs_info.get("git", {}).get("sha1") != source["commit"]:
        raise ReferenceError("libcrux crate VCS commit mismatch")
    cargo_manifest = cargo_manifest_path.read_text(encoding="utf8")
    for pattern, label in (
        (r'^name = "libcrux-ml-dsa"$', "package name"),
        (r'^version = "0\.0\.10"$', "package version"),
        (r'^license = "Apache-2\.0"$', "license"),
    ):
        if re.search(pattern, cargo_manifest, re.MULTILINE) is None:
            raise ReferenceError(f"libcrux crate {label} mismatch")

    examples_dir = crate_dir / "examples"
    adapter_path = examples_dir / "pqbtc_oracle.rs"
    shutil.copyfile(LIBCRUX_SOURCE, adapter_path)
    cargo_manifest_path.write_text(
        cargo_manifest
        + "\n[[example]]\n"
        + 'name = "pqbtc_oracle"\n'
        + 'path = "examples/pqbtc_oracle.rs"\n',
        encoding="utf8",
    )
    return crate_dir


def compile_libcrux_oracle(build_dir: Path, crate_dir: Path) -> Path:
    target_dir = build_dir / "libcrux-target"
    normal_dependencies = run(
        [
            "cargo",
            "tree",
            "--manifest-path",
            str(crate_dir / "Cargo.toml"),
            "--locked",
            "--edges",
            "normal",
            "--no-default-features",
            "--features",
            "std,mldsa44",
            "--prefix",
            "none",
        ]
    )
    if re.search(
        r"pqclean|pq[-_]crystals|mldsa[-_]native|pqcrypto[-_]mldsa",
        normal_dependencies,
        re.IGNORECASE,
    ):
        raise ReferenceError("libcrux has an unexpected normal reference dependency")
    run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(crate_dir / "Cargo.toml"),
            "--target-dir",
            str(target_dir),
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            "std,mldsa44",
            "--example",
            "pqbtc_oracle",
        ]
    )
    executable = target_dir / "release" / "examples" / "pqbtc_oracle"
    if not executable.is_file():
        raise ReferenceError("cargo did not produce the libcrux oracle executable")
    return executable


def run_libcrux_security_regressions(build_dir: Path, crate_dir: Path) -> dict:
    target_dir = build_dir / "libcrux-security-target"
    regressions = {
        "RUSTSEC-2026-0076": "bad_hint_out_of_bounds",
        "RUSTSEC-2026-0077": "mask_exceeds_norm",
    }
    for test_name in regressions.values():
        run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(crate_dir / "Cargo.toml"),
                "--target-dir",
                str(target_dir),
                "--locked",
                "--test",
                "self",
                test_name,
                "--",
                "--exact",
            ]
        )
    return {advisory: {"test": test, "status": "PASS"} for advisory, test in regressions.items()}


def require_artifact(path: Path, expected_sha256: str, label: str) -> None:
    if not path.is_file():
        raise ReferenceError(f"missing {label}: {path}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise ReferenceError(
            f"{label} SHA256 mismatch: expected {expected_sha256}, got {actual}"
        )


def compile_mldsa_native_oracle(
    build_dir: Path,
    source_dir: Path,
    expected_commit: str,
    sanitized: bool = False,
) -> Path:
    require_mldsa_native_source(source_dir, expected_commit)
    monolithic_dir = source_dir / "examples/monolithic_build/mldsa_native"
    monolithic_source = monolithic_dir / "mldsa_native.c"
    compiler = os.environ.get("CC", "cc")
    suffix = "_sanitized" if sanitized else ""
    output = build_dir / f"mldsa_native_oracle{suffix}"
    run(
        [
            compiler,
            "-std=c99",
            *compiler_mode_flags(sanitized),
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-pragmas",
            "-DMLD_CONFIG_PARAMETER_SET=44",
            f"-I{monolithic_dir}",
            str(MLDSA_NATIVE_SOURCE),
            str(monolithic_source),
            "-o",
            str(output),
        ]
    )
    return output


def find_test(document: dict, group_id: int, test_id: int) -> tuple[dict, dict]:
    group = next(
        (candidate for candidate in document["testGroups"] if candidate["tgId"] == group_id),
        None,
    )
    if group is None:
        raise ReferenceError(f"missing ACVP group {group_id}")
    test = next((candidate for candidate in group["tests"] if candidate["tcId"] == test_id), None)
    if test is None:
        raise ReferenceError(f"missing ACVP test {group_id}/{test_id}")
    return group, test


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
    if [test["tcId"] for test in group["tests"]] != expected_test_ids:
        raise ReferenceError(f"{label} group {group_id} test-case set mismatch")
    return group


def sha256_hex(hex_value: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_value)).hexdigest()


def require_equal(label: str, *values: str) -> None:
    if len(set(values)) != 1:
        raise ReferenceError(f"{label} mismatch")


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
    prefix = "gen-val/json-files"

    keygen_prompt = loaded[f"{prefix}/ML-DSA-keyGen-FIPS204/prompt.json"]
    keygen_expected = loaded[f"{prefix}/ML-DSA-keyGen-FIPS204/expectedResults.json"]
    keygen_contract = coverage["keygen"]
    keygen_group = require_acvp_group(
        keygen_prompt,
        keygen_contract["group_id"],
        {"parameterSet": profile["name"]},
        keygen_contract["test_case_ids"],
        "NIST keygen",
    )
    keygen_cases = []
    for source_case in keygen_group["tests"]:
        test_id = source_case["tcId"]
        _, source_result = find_test(keygen_expected, keygen_contract["group_id"], test_id)
        seed_hex = source_case["seed"].lower()
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
    require_equal("NIST keygen seed", first_keygen["seed_hex"], representative_keygen["seed_hex"])
    require_equal(
        "NIST keygen private-key hash",
        sha256_hex(first_keygen["private_key_hex"]),
        representative_keygen["expected_private_key_sha256"],
    )
    require_equal(
        "NIST keygen public-key hash",
        sha256_hex(first_keygen["public_key_hex"]),
        representative_keygen["expected_public_key_sha256"],
    )

    siggen_prompt = loaded[f"{prefix}/ML-DSA-sigGen-FIPS204/prompt.json"]
    siggen_expected = loaded[f"{prefix}/ML-DSA-sigGen-FIPS204/expectedResults.json"]
    siggen_cases = []
    for contract in coverage["siggen"]:
        group_id = contract["group_id"]
        group = require_acvp_group(
            siggen_prompt,
            group_id,
            {
                "parameterSet": profile["name"],
                "deterministic": contract["deterministic"],
                "signatureInterface": contract["signature_interface"],
                "preHash": contract["message_mode"],
            },
            contract["test_case_ids"],
            "NIST siggen",
        )
        for source_case in group["tests"]:
            test_id = source_case["tcId"]
            _, source_result = find_test(siggen_expected, group_id, test_id)
            randomizer_hex = source_case.get("rnd")
            if contract["deterministic"]:
                if randomizer_hex is not None:
                    raise ReferenceError(f"deterministic siggen {test_id} includes rnd")
            else:
                if randomizer_hex is None:
                    raise ReferenceError(f"randomized siggen {test_id} lacks rnd")
                randomizer_hex = randomizer_hex.lower()
                require_hex(
                    randomizer_hex,
                    profile["randomizer_bytes"],
                    f"NIST siggen {test_id} randomizer",
                )
            private_key_hex = source_case["sk"].lower()
            message_hex = source_case["message"].lower()
            context_hex = source_case.get("context", "").lower()
            signature_hex = source_result["signature"].lower()
            require_hex(
                private_key_hex,
                profile["private_key_bytes"],
                f"NIST siggen {test_id} private key",
            )
            require_hex(
                signature_hex,
                profile["signature_bytes"],
                f"NIST siggen {test_id} signature",
            )
            if len(bytes.fromhex(context_hex)) > 255:
                raise ReferenceError(f"NIST siggen {test_id} context exceeds 255 bytes")
            siggen_cases.append(
                {
                    "group_id": group_id,
                    "test_case_id": test_id,
                    "deterministic": contract["deterministic"],
                    "private_key_hex": private_key_hex,
                    "message_hex": message_hex,
                    "context_hex": context_hex,
                    "randomizer_hex": randomizer_hex,
                    "signature_hex": signature_hex,
                }
            )

    for vector_name, identity in (
        ("nist_siggen_tg1_tc1", (1, 1)),
        ("nist_siggen_tg13_tc181", (13, 181)),
    ):
        representative = vectors[vector_name]
        selected = next(
            case
            for case in siggen_cases
            if (case["group_id"], case["test_case_id"]) == identity
        )
        for source_field, manifest_field in (
            ("private_key_hex", "private_key_sha256"),
            ("message_hex", "message_sha256"),
            ("context_hex", "context_sha256"),
            ("signature_hex", "expected_signature_sha256"),
        ):
            require_equal(
                f"{vector_name} {source_field} hash",
                sha256_hex(selected[source_field]),
                representative[manifest_field],
            )
        if len(bytes.fromhex(selected["message_hex"])) != representative["message_bytes"]:
            raise ReferenceError(f"{vector_name} message size mismatch")
        if len(bytes.fromhex(selected["context_hex"])) != representative["context_bytes"]:
            raise ReferenceError(f"{vector_name} context size mismatch")
        if selected["randomizer_hex"] is not None:
            require_equal(
                f"{vector_name} randomizer",
                selected["randomizer_hex"],
                representative["randomizer_hex"],
            )

    sigver_prompt = loaded[f"{prefix}/ML-DSA-sigVer-FIPS204/prompt.json"]
    sigver_expected = loaded[f"{prefix}/ML-DSA-sigVer-FIPS204/expectedResults.json"]
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
    sigver_cases = []
    for source_case in sigver_group["tests"]:
        test_id = source_case["tcId"]
        _, source_result = find_test(sigver_expected, sigver_contract["group_id"], test_id)
        expected_valid = test_id in accepted_ids
        if source_result.get("testPassed") is not expected_valid:
            raise ReferenceError(f"NIST sigver {test_id} result mismatch")
        public_key_hex = source_case["pk"].lower()
        message_hex = source_case["message"].lower()
        context_hex = source_case.get("context", "").lower()
        signature_hex = source_case["signature"].lower()
        require_hex(
            public_key_hex,
            profile["public_key_bytes"],
            f"NIST sigver {test_id} public key",
        )
        require_hex(
            signature_hex,
            profile["signature_bytes"],
            f"NIST sigver {test_id} signature",
        )
        if len(bytes.fromhex(context_hex)) > 255:
            raise ReferenceError(f"NIST sigver {test_id} context exceeds 255 bytes")
        sigver_cases.append(
            {
                "test_case_id": test_id,
                "public_key_hex": public_key_hex,
                "message_hex": message_hex,
                "context_hex": context_hex,
                "signature_hex": signature_hex,
                "expected_valid": expected_valid,
            }
        )

    sigver_by_id = {case["test_case_id"]: case for case in sigver_cases}
    for representative in vectors["nist_sigver_tg1"]["cases"]:
        source_case = sigver_by_id[representative["test_case_id"]]
        for source_field, manifest_field in (
            ("public_key_hex", "public_key_sha256"),
            ("message_hex", "message_sha256"),
            ("context_hex", "context_sha256"),
            ("signature_hex", "signature_sha256"),
        ):
            require_equal(
                f"NIST sigver {source_case['test_case_id']} {source_field} hash",
                sha256_hex(source_case[source_field]),
                representative[manifest_field],
            )
        if len(bytes.fromhex(source_case["message_hex"])) != representative["message_bytes"]:
            raise ReferenceError("NIST sigver representative message size mismatch")
        if len(bytes.fromhex(source_case["context_hex"])) != representative["context_bytes"]:
            raise ReferenceError("NIST sigver representative context size mismatch")
        if source_case["expected_valid"] is not representative["expected_valid"]:
            raise ReferenceError("NIST sigver representative result mismatch")

    total_cases = len(keygen_cases) + len(siggen_cases) + len(sigver_cases)
    if total_cases != coverage["total_cases"]:
        raise ReferenceError("NIST selected-profile ACVP case count mismatch")
    return {
        "keygen_cases": keygen_cases,
        "siggen_cases": siggen_cases,
        "sigver_cases": sigver_cases,
        "total_cases": total_cases,
    }


def parse_oracle_output(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            raise ReferenceError(f"invalid oracle output line: {line}")
        name, value = line.split("=", 1)
        if name in parsed:
            raise ReferenceError(f"duplicate oracle output field: {name}")
        parsed[name] = value
    return parsed


def oracle_keygen(oracle: Oracle, seed_hex: str) -> dict[str, str]:
    return parse_oracle_output(run([str(oracle.executable), "keygen", seed_hex]))


def oracle_public_key(oracle: Oracle, private_key_hex: str) -> str:
    if not oracle.derives_public_key:
        raise ReferenceError(f"oracle {oracle.executable.name} cannot derive a public key")
    result = parse_oracle_output(
        run([str(oracle.executable), "public-key", private_key_hex])
    )
    public_key = result.get("pk")
    if public_key is None:
        raise ReferenceError(f"oracle {oracle.executable.name} omitted public key")
    return public_key


def oracle_sign(
    oracle: Oracle,
    private_key_hex: str,
    message_hex: str,
    context_hex: str,
    randomizer_hex: str | None = None,
    randomized: bool = False,
    public_key_hex: str | None = None,
) -> dict[str, str]:
    if randomizer_hex is not None and randomized:
        raise ReferenceError("fixed and default randomized signing are mutually exclusive")
    command = "sign-randomized" if randomized else "sign"
    arguments = [
        str(oracle.executable),
        command,
        private_key_hex,
        message_hex,
        context_hex,
    ]
    if randomizer_hex is not None:
        arguments[1] = "sign-with-randomizer"
        arguments.append(randomizer_hex)
    if oracle.sign_requires_public_key:
        if public_key_hex is None:
            raise ReferenceError(
                f"oracle {oracle.executable.name} requires a public key while signing"
            )
        arguments.append(public_key_hex)
    result = parse_oracle_output(run(arguments))
    if result.get("verified") != "1":
        raise ReferenceError(f"oracle {oracle.executable.name} did not self-verify")
    return result


def oracle_verify(
    oracle: Oracle,
    public_key_hex: str,
    message_hex: str,
    context_hex: str,
    signature_hex: str,
) -> dict[str, str]:
    result = parse_oracle_output(
        run(
            [
                str(oracle.executable),
                "verify",
                public_key_hex,
                message_hex,
                context_hex,
                signature_hex,
            ]
        )
    )
    if result.get("verified") not in {"0", "1"}:
        raise ReferenceError(
            f"oracle {oracle.executable.name} returned invalid verify result"
        )
    return result


def signature_hash(signature_hex: str, expected_bytes: int) -> str:
    require_hex(signature_hex, expected_bytes, "signature")
    return sha256_hex(signature_hex)


def flip_hex_byte(value: str, byte_index: int) -> str:
    data = bytearray.fromhex(value)
    data[byte_index] ^= 1
    return data.hex()


def require_verification(
    oracles: dict[str, Oracle],
    public_key_hex: str,
    message_hex: str,
    context_hex: str,
    signature_hex: str,
    expected: str,
    label: str,
) -> None:
    results = {
        name: oracle_verify(
            oracle,
            public_key_hex,
            message_hex,
            context_hex,
            signature_hex,
        )["verified"]
        for name, oracle in oracles.items()
    }
    require_equal(label, *results.values(), expected)


def derived_public_keys(
    oracles: dict[str, Oracle], private_key_hex: str, label: str
) -> dict[str, str]:
    public_keys = {
        name: oracle_public_key(oracle, private_key_hex)
        for name, oracle in oracles.items()
        if oracle.derives_public_key
    }
    if not public_keys:
        raise ReferenceError(f"{label} has no public-key derivation oracle")
    require_equal(label, *public_keys.values())
    return public_keys


def evaluate_acvp(profile: dict, oracles: dict[str, Oracle], source_cases: dict) -> None:
    for case in source_cases["keygen_cases"]:
        results = {
            name: oracle_keygen(oracle, case["seed_hex"])
            for name, oracle in oracles.items()
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
        public_keys = derived_public_keys(
            oracles,
            case["private_key_hex"],
            f"oracle siggen {case['test_case_id']} public key",
        )
        public_key = next(iter(public_keys.values()))
        results = {
            name: oracle_sign(
                oracle,
                case["private_key_hex"],
                case["message_hex"],
                case["context_hex"],
                randomizer_hex=case["randomizer_hex"],
                public_key_hex=public_key,
            )
            for name, oracle in oracles.items()
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
        require_verification(
            oracles,
            public_key,
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


def build_pqbtc_material(
    profile: dict, oracles: dict[str, Oracle], vector: dict
) -> dict[str, str]:
    generated = {
        name: oracle_keygen(oracle, vector["seed_hex"])
        for name, oracle in oracles.items()
    }
    require_equal("PQBTC public key bytes", *(result["pk"] for result in generated.values()))
    require_equal("PQBTC private key bytes", *(result["sk"] for result in generated.values()))
    material = next(iter(generated.values()))
    require_equal(
        "PQBTC public key hash",
        sha256_hex(material["pk"]),
        vector["expected_public_key_sha256"],
    )
    require_equal(
        "PQBTC private key hash",
        sha256_hex(material["sk"]),
        vector["expected_private_key_sha256"],
    )
    require_hex(material["pk"], profile["public_key_bytes"], "PQBTC public key")
    require_hex(material["sk"], profile["private_key_bytes"], "PQBTC private key")
    for name, oracle in oracles.items():
        if not oracle.derives_public_key:
            continue
        require_equal(
            f"{name} derived PQBTC public key",
            oracle_public_key(oracle, material["sk"]),
            material["pk"],
        )
    return material


def evaluate_randomized_interoperability(
    profile: dict,
    oracles: dict[str, Oracle],
    vector: dict,
    private_key_hex: str,
    public_key_hex: str,
) -> dict:
    randomizers = [secrets.token_hex(profile["randomizer_bytes"]) for _ in range(2)]
    while randomizers[0] == randomizers[1]:
        randomizers[1] = secrets.token_hex(profile["randomizer_bytes"])

    fixed_signatures = []
    for index, randomizer_hex in enumerate(randomizers, start=1):
        results = {
            name: oracle_sign(
                oracle,
                private_key_hex,
                vector["message_hex"],
                vector["context_hex"],
                randomizer_hex=randomizer_hex,
                public_key_hex=public_key_hex,
            )
            for name, oracle in oracles.items()
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
            public_key_hex,
            vector["message_hex"],
            vector["context_hex"],
            signature_hex,
            "1",
            f"fixed-randomizer cross-verification round {index}",
        )
    if fixed_signatures[0] == fixed_signatures[1]:
        raise ReferenceError("distinct fixed randomizers produced the same signature")

    all_randomized_signatures = []
    for name, oracle in oracles.items():
        signatures = [
            oracle_sign(
                oracle,
                private_key_hex,
                vector["message_hex"],
                vector["context_hex"],
                randomized=True,
                public_key_hex=public_key_hex,
            )["signature"]
            for _ in range(2)
        ]
        if signatures[0] == signatures[1]:
            raise ReferenceError(f"{name} randomized signing repeated a signature")
        for index, signature_hex in enumerate(signatures, start=1):
            signature_hash(signature_hex, profile["signature_bytes"])
            require_verification(
                oracles,
                public_key_hex,
                vector["message_hex"],
                vector["context_hex"],
                signature_hex,
                "1",
                f"{name} randomized cross-verification round {index}",
            )
            all_randomized_signatures.append(signature_hex)
    if len(set(all_randomized_signatures)) != len(all_randomized_signatures):
        raise ReferenceError("randomized signing repeated a signature across oracles")
    return {
        "fixed_randomizer_rounds": len(fixed_signatures),
        "default_randomized_rounds": len(all_randomized_signatures),
    }


def evaluate_boundaries_and_mutations(
    profile: dict,
    oracles: dict[str, Oracle],
    vector: dict,
    private_key_hex: str,
    public_key_hex: str,
    deterministic_signature_hex: str,
) -> dict:
    boundary_cases = (
        ("empty message and context", "", ""),
        ("maximum context", vector["message_hex"], "a5" * 255),
    )
    for label, message_hex, context_hex in boundary_cases:
        results = {
            name: oracle_sign(
                oracle,
                private_key_hex,
                message_hex,
                context_hex,
                public_key_hex=public_key_hex,
            )
            for name, oracle in oracles.items()
        }
        require_equal(
            f"{label} signature bytes",
            *(result["signature"] for result in results.values()),
        )
        signature_hex = next(iter(results.values()))["signature"]
        require_verification(
            oracles,
            public_key_hex,
            message_hex,
            context_hex,
            signature_hex,
            "1",
            f"{label} cross-verification",
        )

    message_hex = vector["message_hex"]
    context_hex = vector["context_hex"]
    mutations = (
        (
            "public key first byte",
            flip_hex_byte(public_key_hex, 0),
            message_hex,
            context_hex,
            deterministic_signature_hex,
        ),
        (
            "public key last byte",
            flip_hex_byte(public_key_hex, -1),
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
    for oracle in oracles.values():
        executable = str(oracle.executable)
        sign_suffix = [public_key_hex] if oracle.sign_requires_public_key else []
        commands = [
            [executable, "keygen", vector["seed_hex"][:-2]],
            [executable, "keygen", vector["seed_hex"] + "00"],
            [executable, "sign", private_key_hex[:-2], message_hex, context_hex, *sign_suffix],
            [executable, "sign", private_key_hex + "00", message_hex, context_hex, *sign_suffix],
            [executable, "sign", private_key_hex, message_hex, oversized_context, *sign_suffix],
            [
                executable,
                "sign-with-randomizer",
                private_key_hex,
                message_hex,
                context_hex,
                "00" * 31,
                *sign_suffix,
            ],
            [
                executable,
                "sign-with-randomizer",
                private_key_hex,
                message_hex,
                context_hex,
                "00" * 33,
                *sign_suffix,
            ],
            [
                executable,
                "verify",
                public_key_hex[:-2],
                message_hex,
                context_hex,
                deterministic_signature_hex,
            ],
            [
                executable,
                "verify",
                public_key_hex + "00",
                message_hex,
                context_hex,
                deterministic_signature_hex,
            ],
            [
                executable,
                "verify",
                public_key_hex,
                message_hex,
                oversized_context,
                deterministic_signature_hex,
            ],
        ]
        if oracle.derives_public_key:
            commands.extend(
                (
                    [executable, "public-key", private_key_hex[:-2]],
                    [executable, "public-key", private_key_hex + "00"],
                )
            )
        for index, command in enumerate(commands, start=1):
            require_command_failure(
                command, f"{oracle.executable.name} malformed input {index}"
            )
            malformed_commands += 1
    return {
        "boundary_cases": len(boundary_cases),
        "cryptographic_rejections": len(mutations),
        "malformed_input_rejections": malformed_commands,
    }


def median_ms(values: list[int]) -> float:
    return round(statistics.median(values) / 1_000_000, 3)


def benchmark_profile(
    profile: dict,
    oracles: dict[str, Oracle],
    vector: dict,
    iterations: int,
) -> dict:
    values = {
        name: {
            "keygen_ns": [],
            "deterministic_sign_ns": [],
            "deterministic_verify_ns": [],
            "randomized_sign_ns": [],
            "randomized_verify_ns": [],
        }
        for name in oracles
    }
    for _ in range(iterations):
        deterministic_signatures = []
        for name, oracle in oracles.items():
            generated = oracle_keygen(oracle, vector["seed_hex"])
            deterministic = oracle_sign(
                oracle,
                generated["sk"],
                vector["message_hex"],
                vector["context_hex"],
                public_key_hex=generated["pk"],
            )
            require_equal(
                "PQBTC deterministic signature hash",
                signature_hash(deterministic["signature"], profile["signature_bytes"]),
                vector["expected_signature_sha256"],
            )
            randomized = oracle_sign(
                oracle,
                generated["sk"],
                vector["message_hex"],
                vector["context_hex"],
                randomized=True,
                public_key_hex=generated["pk"],
            )
            require_verification(
                oracles,
                generated["pk"],
                vector["message_hex"],
                vector["context_hex"],
                randomized["signature"],
                "1",
                f"{name} randomized benchmark signature",
            )
            deterministic_signatures.append(deterministic["signature"])
            values[name]["keygen_ns"].append(int(generated["keygen_ns"]))
            values[name]["deterministic_sign_ns"].append(int(deterministic["sign_ns"]))
            values[name]["deterministic_verify_ns"].append(int(deterministic["verify_ns"]))
            values[name]["randomized_sign_ns"].append(int(randomized["sign_ns"]))
            values[name]["randomized_verify_ns"].append(int(randomized["verify_ns"]))
        require_equal("PQBTC deterministic signature bytes", *deterministic_signatures)

    return {
        name: {
            "iterations": iterations,
            "median_keygen_ms": median_ms(measurements["keygen_ns"]),
            "deterministic": {
                "median_sign_ms": median_ms(measurements["deterministic_sign_ns"]),
                "median_verify_ms": median_ms(measurements["deterministic_verify_ns"]),
            },
            "randomized": {
                "median_sign_ms": median_ms(measurements["randomized_sign_ns"]),
                "median_verify_ms": median_ms(measurements["randomized_verify_ns"]),
            },
        }
        for name, measurements in values.items()
    }


def evaluate_sanitized_smoke(
    profile: dict, oracles: dict[str, Oracle], vector: dict
) -> dict:
    material = build_pqbtc_material(profile, oracles, vector)
    deterministic = {
        name: oracle_sign(
            oracle,
            material["sk"],
            vector["message_hex"],
            vector["context_hex"],
            public_key_hex=material["pk"],
        )["signature"]
        for name, oracle in oracles.items()
    }
    require_equal("sanitized deterministic signatures", *deterministic.values())
    return evaluate_boundaries_and_mutations(
        profile,
        oracles,
        vector,
        material["sk"],
        material["pk"],
        next(iter(deterministic.values())),
    )


def libcrux_malformed_hint_signature(profile: dict, final_counter: int) -> str:
    if profile["name"] != "ML-DSA-44" or profile["signature_bytes"] != 2420:
        raise ReferenceError("libcrux malformed-hint regression requires ML-DSA-44")
    if final_counter not in {81, 85}:
        raise ReferenceError("libcrux malformed-hint final counter must be 81 or 85")

    signature = bytearray(profile["signature_bytes"])
    hint_offset = 32 + 4 * 576
    signature[hint_offset : hint_offset + 21] = bytes(range(1, 22))
    signature[hint_offset + 21 : hint_offset + 42] = bytes(range(1, 22))
    signature[hint_offset + 42 : hint_offset + 63] = bytes(range(1, 22))
    signature[hint_offset + 63 : hint_offset + 80] = bytes(range(1, 18))
    signature[hint_offset + 80 : hint_offset + 84] = bytes(
        (21, 42, 63, final_counter)
    )
    return signature.hex()


def evaluate_libcrux_advisory_regressions(
    profile: dict,
    oracles: dict[str, Oracle],
    public_key_hex: str,
    message_hex: str,
    context_hex: str,
    upstream_report: dict,
) -> dict:
    expected_advisories = {"RUSTSEC-2026-0076", "RUSTSEC-2026-0077"}
    if set(upstream_report) != expected_advisories or any(
        result.get("status") != "PASS" for result in upstream_report.values()
    ):
        raise ReferenceError("libcrux upstream security regressions did not pass")

    malformed_hint_cases = {
        "bounded_counter_overflow": libcrux_malformed_hint_signature(profile, 81),
        "historical_out_of_bounds_counter": libcrux_malformed_hint_signature(profile, 85),
    }
    for label, signature_hex in malformed_hint_cases.items():
        require_verification(
            oracles,
            public_key_hex,
            message_hex,
            context_hex,
            signature_hex,
            "0",
            f"libcrux {label} rejection",
        )
    return {
        "upstream_release_tests": upstream_report,
        "ml_dsa_44_malformed_hint_rejections": len(malformed_hint_cases),
        "no_panic": "PASS",
    }


def block_space_model(profile: dict, cost: dict) -> dict:
    rc2_signature_bytes = cost["held_rc2_signature_bytes"]
    mldsa_signature_bytes = profile["signature_bytes"]
    rc2_revealed_bytes = rc2_signature_bytes + cost["held_rc2_public_key_bytes"]
    mldsa_revealed_bytes = mldsa_signature_bytes + profile["public_key_bytes"]
    block_limit = cost["block_weight_limit"]
    return {
        **cost,
        "ml_dsa_signature_bytes": mldsa_signature_bytes,
        "ml_dsa_public_key_bytes": profile["public_key_bytes"],
        "signature_size_change_percent": round(
            (mldsa_signature_bytes / rc2_signature_bytes - 1) * 100, 2
        ),
        "signature_only_witness_capacity": {
            "held_rc2": block_limit // rc2_signature_bytes,
            "ml_dsa_44": block_limit // mldsa_signature_bytes,
        },
        "signature_plus_public_key_bytes": {
            "held_rc2": rc2_revealed_bytes,
            "ml_dsa_44": mldsa_revealed_bytes,
        },
        "signature_plus_public_key_witness_capacity": {
            "held_rc2": block_limit // rc2_revealed_bytes,
            "ml_dsa_44": block_limit // mldsa_revealed_bytes,
        },
        "public_key_if_non_witness_weight": {
            "held_rc2": cost["held_rc2_public_key_bytes"]
            * cost["non_witness_weight_per_byte"],
            "ml_dsa_44": profile["public_key_bytes"]
            * cost["non_witness_weight_per_byte"],
        },
        "scope": "raw payload model only; no transaction encoding or activation design",
    }


def evaluate(
    manifest: dict,
    oracles: dict[str, Oracle],
    source_cases: dict,
    benchmark_iterations: int,
    sanitized_report: dict | None,
    libcrux_upstream_report: dict,
) -> dict:
    profile = manifest["profile"]
    vector = manifest["vectors"]["pqbtc_sighash_v1"]
    evaluate_acvp(profile, oracles, source_cases)
    material = build_pqbtc_material(profile, oracles, vector)

    deterministic = {
        name: oracle_sign(
            oracle,
            material["sk"],
            vector["message_hex"],
            vector["context_hex"],
            public_key_hex=material["pk"],
        )["signature"]
        for name, oracle in oracles.items()
    }
    require_equal("PQBTC deterministic signature bytes", *deterministic.values())
    deterministic_signature = next(iter(deterministic.values()))
    require_equal(
        "PQBTC deterministic signature hash",
        signature_hash(deterministic_signature, profile["signature_bytes"]),
        vector["expected_signature_sha256"],
    )
    randomized_report = evaluate_randomized_interoperability(
        profile, oracles, vector, material["sk"], material["pk"]
    )
    negative_report = evaluate_boundaries_and_mutations(
        profile,
        oracles,
        vector,
        material["sk"],
        material["pk"],
        deterministic_signature,
    )
    advisory_report = evaluate_libcrux_advisory_regressions(
        profile,
        oracles,
        material["pk"],
        vector["message_hex"],
        vector["context_hex"],
        libcrux_upstream_report,
    )
    benchmark = benchmark_profile(
        profile, oracles, vector, benchmark_iterations
    )
    version_text, _ = openssl_version(manifest["sources"]["openssl"]["version"])
    return {
        "status": "PASS",
        "profile": profile["name"],
        "openssl_version": version_text,
        "openssl_commit": manifest["sources"]["openssl"]["commit"],
        "mldsa_native_commit": manifest["sources"]["mldsa_native"]["commit"],
        "libcrux_commit": manifest["sources"]["libcrux"]["commit"],
        "libcrux_version": manifest["sources"]["libcrux"]["version"],
        "checks": {
            "fips204_and_update_artifact_provenance": "PASS",
            "nist_source_provenance": "PASS",
            "nist_selected_profile_acvp_70_cases": "PASS",
            "nist_deterministic_and_randomized_siggen": "PASS",
            "nist_sigver_all_accept_reject_cases": "PASS",
            "pqbtc_sighash_vector": "PASS",
            "full_signature_byte_agreement": "PASS",
            "randomized_interoperability": "PASS",
            "boundary_and_mutation_rejection": "PASS",
            "libcrux_source_and_crate_provenance": "PASS",
            "libcrux_disclosed_advisory_regressions": "PASS",
            "adapter_asan_ubsan": "PASS" if sanitized_report is not None else "NOT_RUN",
        },
        "acvp": {
            "total_cases": source_cases["total_cases"],
            "keygen_cases": len(source_cases["keygen_cases"]),
            "siggen_cases": len(source_cases["siggen_cases"]),
            "sigver_cases": len(source_cases["sigver_cases"]),
        },
        "randomized_interoperability": randomized_report,
        "negative_testing": negative_report,
        "libcrux_advisory_regressions": advisory_report,
        "sanitized_smoke": sanitized_report,
        "signature_sha256": {
            "nist_deterministic": manifest["vectors"]["nist_siggen_tg1_tc1"][
                "expected_signature_sha256"
            ],
            "nist_randomized": manifest["vectors"]["nist_siggen_tg13_tc181"][
                "expected_signature_sha256"
            ],
            "pqbtc": vector["expected_signature_sha256"],
        },
        "lineage": {
            "mldsa_native": manifest["sources"]["mldsa_native"]["lineage_limit"],
            "libcrux": manifest["sources"]["libcrux"]["independence_assessment"],
        },
        "block_space_model": block_space_model(profile, manifest["system_cost_model"]),
        "benchmark": benchmark,
    }


def optional_path(environment_name: str) -> Path | None:
    value = os.environ.get(environment_name)
    return Path(value) if value else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acvp-server",
        type=Path,
        default=optional_path("ACVP_SERVER_DIR"),
        help="path to the pinned usnistgov/ACVP-Server checkout",
    )
    parser.add_argument(
        "--mldsa-native",
        type=Path,
        default=optional_path("MLDSA_NATIVE_DIR"),
        help="path to the pinned pq-code-package/mldsa-native checkout",
    )
    parser.add_argument(
        "--openssl-source",
        type=Path,
        default=optional_path("OPENSSL_SOURCE_DIR"),
        help="path to the pinned OpenSSL source checkout",
    )
    parser.add_argument(
        "--libcrux-source",
        type=Path,
        default=optional_path("LIBCRUX_SOURCE_DIR"),
        help="path to the full-history pinned celabshq/libcrux checkout",
    )
    parser.add_argument(
        "--libcrux-crate",
        type=Path,
        default=optional_path("LIBCRUX_CRATE_PATH"),
        help="path to the pinned libcrux-ml-dsa 0.0.10 crate archive",
    )
    parser.add_argument(
        "--fips204",
        type=Path,
        default=optional_path("FIPS204_PATH"),
        help="path to the pinned NIST.FIPS.204.pdf artifact",
    )
    parser.add_argument(
        "--fips204-updates",
        type=Path,
        default=optional_path("FIPS204_UPDATES_PATH"),
        help="path to the pinned FIPS 204 potential-updates spreadsheet",
    )
    parser.add_argument(
        "--fips204-section6-guidance",
        type=Path,
        default=optional_path("FIPS204_SECTION6_GUIDANCE_PATH"),
        help="path to the pinned NIST Section 6 guidance PDF",
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
        help="validate the checked-in profile and provenance manifest only",
    )
    parser.add_argument(
        "--sanitizers",
        action="store_true",
        help="also build and exercise both portable-C adapters with ASan and UBSan",
    )
    return parser.parse_args()


def require_path(value: Path | None, option: str) -> Path:
    if value is None:
        raise ReferenceError(f"{option} or its documented environment variable is required")
    return value.resolve()


def main() -> int:
    args = parse_args()
    try:
        manifest = load_manifest()
        if args.manifest_only:
            print("ML-DSA-44 reference manifest validation passed")
            return 0
        if not 1 <= args.benchmark_iterations <= 10:
            raise ReferenceError("--benchmark-iterations must be between 1 and 10")

        acvp_server = require_path(args.acvp_server, "--acvp-server")
        mldsa_native = require_path(args.mldsa_native, "--mldsa-native")
        openssl_source = require_path(args.openssl_source, "--openssl-source")
        libcrux_source = require_path(args.libcrux_source, "--libcrux-source")
        libcrux_crate = require_path(args.libcrux_crate, "--libcrux-crate")
        fips204 = require_path(args.fips204, "--fips204")
        fips204_updates = require_path(args.fips204_updates, "--fips204-updates")
        section6_guidance = require_path(
            args.fips204_section6_guidance, "--fips204-section6-guidance"
        )

        sources = manifest["sources"]
        require_artifact(fips204, sources["nist_fips204"]["sha256"], "FIPS 204")
        require_artifact(
            fips204_updates,
            sources["nist_fips204_potential_updates"]["sha256"],
            "FIPS 204 potential updates",
        )
        require_artifact(
            section6_guidance,
            sources["nist_fips204_section6_guidance"]["sha256"],
            "FIPS 204 Section 6 guidance",
        )
        source_cases = verify_nist_sources(manifest, acvp_server)
        require_openssl_source(openssl_source, sources["openssl"]["commit"])
        require_mldsa_native_source(
            mldsa_native, sources["mldsa_native"]["commit"]
        )
        require_libcrux_source(libcrux_source, sources["libcrux"])

        with tempfile.TemporaryDirectory(prefix="pqbtc-ml-dsa-") as temporary:
            build_dir = Path(temporary)
            libcrux_crate_dir = prepare_libcrux_crate(
                build_dir, libcrux_crate, sources["libcrux"]
            )
            libcrux_upstream_report = run_libcrux_security_regressions(
                build_dir, libcrux_crate_dir
            )
            oracles = {
                "openssl": Oracle(
                    compile_openssl_oracle(
                        build_dir, sources["openssl"]["version"]
                    )
                ),
                "mldsa_native": Oracle(
                    compile_mldsa_native_oracle(
                        build_dir, mldsa_native, sources["mldsa_native"]["commit"]
                    )
                ),
                "libcrux": Oracle(
                    compile_libcrux_oracle(build_dir, libcrux_crate_dir),
                    derives_public_key=False,
                    sign_requires_public_key=True,
                ),
            }
            sanitized_report = None
            if args.sanitizers:
                sanitized_oracles = {
                    "openssl": Oracle(
                        compile_openssl_oracle(
                            build_dir,
                            sources["openssl"]["version"],
                            sanitized=True,
                        )
                    ),
                    "mldsa_native": Oracle(
                        compile_mldsa_native_oracle(
                            build_dir,
                            mldsa_native,
                            sources["mldsa_native"]["commit"],
                            sanitized=True,
                        )
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
                source_cases,
                args.benchmark_iterations,
                sanitized_report,
                libcrux_upstream_report,
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, KeyError, ReferenceError, ValueError) as error:
        print(f"compare_oracles.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
