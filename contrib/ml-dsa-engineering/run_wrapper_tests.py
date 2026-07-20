#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
SOURCE_DIR = HERE / "vendor" / "mldsa-native"
SOURCE_MANIFEST = SOURCE_DIR / "SOURCE.json"
WRAPPER_SOURCE = HERE / "pqbtc_mldsa44.c"
SMOKE_SOURCE = HERE / "pqbtc_mldsa44_smoke.c"
VECTORS = REPO_ROOT / "contrib" / "ml-dsa-ref" / "vectors.json"

PUBLIC_KEY_BYTES = 1312
SECRET_KEY_BYTES = 2560
SIGNATURE_BYTES = 2420


class HarnessError(RuntimeError):
    pass


def run(command: list[str], env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if completed.returncode != 0:
        raise HarnessError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


def validate_source_capsule() -> dict:
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf8"))
    expected_files = manifest["files"]
    actual_files = sorted(
        path.relative_to(SOURCE_DIR).as_posix()
        for path in SOURCE_DIR.rglob("*")
        if path.is_file() and path != SOURCE_MANIFEST
    )
    if actual_files != expected_files:
        raise HarnessError("vendored mldsa-native file set differs from SOURCE.json")
    if any("/native/" in path or path.endswith(".S") for path in actual_files):
        raise HarnessError("portable source capsule contains a native backend")

    digest_lines = []
    for relative_path in actual_files:
        digest = hashlib.sha256((SOURCE_DIR / relative_path).read_bytes()).hexdigest()
        digest_lines.append(f"{digest}  ./{relative_path}\n")
    capsule_digest = hashlib.sha256("".join(digest_lines).encode()).hexdigest()
    if capsule_digest != manifest["capsule_hash"]["value"]:
        raise HarnessError(
            "vendored mldsa-native capsule hash mismatch: "
            f"expected {manifest['capsule_hash']['value']}, got {capsule_digest}"
        )
    return manifest


def common_flags(compiler: str) -> list[str]:
    flags = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unknown-pragmas",
        "-fvisibility=hidden",
        f"-I{HERE}",
    ]
    return flags


def shared_library_name(testing: bool) -> str:
    suffix = "_test" if testing else ""
    extension = ".dylib" if sys.platform == "darwin" else ".so"
    return f"libpqbtc_mldsa44{suffix}{extension}"


def compile_shared(compiler: str, build_dir: Path, testing: bool) -> Path:
    output = build_dir / shared_library_name(testing)
    command = common_flags(compiler)
    command.extend(["-O2", "-fPIC"])
    if testing:
        command.append("-DPQBTC_MLDSA44_TESTING=1")
    command.append("-dynamiclib" if sys.platform == "darwin" else "-shared")
    command.extend([str(WRAPPER_SOURCE), "-o", str(output)])
    if sys.platform == "win32":
        command.append("-lbcrypt")
    run(command)
    return output


def exported_symbols(library: Path) -> set[str]:
    nm = shutil.which("nm")
    if nm is None:
        raise HarnessError("nm is required for the production symbol audit")
    if sys.platform == "darwin":
        output = run([nm, "-gU", str(library)])
    else:
        output = run([nm, "-D", "--defined-only", str(library)])
    symbols = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        symbol = fields[-1]
        if sys.platform == "darwin" and symbol.startswith("_"):
            symbol = symbol[1:]
        symbols.add(symbol)
    return symbols


def audit_production_symbols(library: Path) -> None:
    expected = {
        "pqbtc_mldsa44_sign_hedged",
        "pqbtc_mldsa44_verify_strict",
    }
    actual = exported_symbols(library)
    if actual != expected:
        raise HarnessError(
            f"production symbol surface mismatch: expected {sorted(expected)}, got {sorted(actual)}"
        )


def compile_smoke(compiler: str, build_dir: Path, sanitizers: bool) -> Path:
    suffix = "_sanitized" if sanitizers else ""
    output = build_dir / f"pqbtc_mldsa44_smoke{suffix}"
    command = common_flags(compiler)
    command.extend(["-DPQBTC_MLDSA44_TESTING=1", "-pthread"])
    if sanitizers:
        command.extend(
            [
                "-O1",
                "-g",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                "-fsanitize=address,undefined",
            ]
        )
    else:
        command.append("-O2")
    command.extend([str(WRAPPER_SOURCE), str(SMOKE_SOURCE), "-o", str(output)])
    run(command)
    return output


def run_smoke(executable: Path, sanitizers: bool) -> None:
    env = os.environ.copy()
    if sanitizers:
        env["ASAN_OPTIONS"] = "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    run([str(executable)], env=env)


def as_array(data: bytes):
    array_type = ctypes.c_uint8 * len(data)
    return array_type.from_buffer_copy(data)


def configure_public_api(loaded) -> None:
    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    loaded.pqbtc_mldsa44_sign_hedged.argtypes = [
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
    ]
    loaded.pqbtc_mldsa44_sign_hedged.restype = ctypes.c_int
    loaded.pqbtc_mldsa44_verify_strict.argtypes = [
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
    ]
    loaded.pqbtc_mldsa44_verify_strict.restype = ctypes.c_int


def validate_frozen_vectors(test_library: Path, production_library: Path) -> None:
    vectors = json.loads(VECTORS.read_text(encoding="utf8"))["vectors"]
    keygen = vectors["nist_keygen_tg1_tc1"]
    signing = vectors["pqbtc_sighash_v1"]
    loaded = ctypes.CDLL(str(test_library))
    production = ctypes.CDLL(str(production_library))
    configure_public_api(loaded)
    configure_public_api(production)

    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    loaded.pqbtc_mldsa44_test_keypair_from_seed.argtypes = [
        byte_pointer,
        byte_pointer,
        byte_pointer,
    ]
    loaded.pqbtc_mldsa44_test_keypair_from_seed.restype = ctypes.c_int
    loaded.pqbtc_mldsa44_test_sign_fixed_randomizer.argtypes = [
        byte_pointer,
        byte_pointer,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
    ]
    loaded.pqbtc_mldsa44_test_sign_fixed_randomizer.restype = ctypes.c_int
    public_key = (ctypes.c_uint8 * PUBLIC_KEY_BYTES)()
    secret_key = (ctypes.c_uint8 * SECRET_KEY_BYTES)()
    seed = as_array(bytes.fromhex(keygen["seed_hex"]))
    if loaded.pqbtc_mldsa44_test_keypair_from_seed(public_key, secret_key, seed) != 0:
        raise HarnessError("test-only key generation failed")
    if hashlib.sha256(bytes(public_key)).hexdigest() != keygen["expected_public_key_sha256"]:
        raise HarnessError("NIST key-generation public-key vector mismatch")
    if hashlib.sha256(bytes(secret_key)).hexdigest() != keygen["expected_private_key_sha256"]:
        raise HarnessError("NIST key-generation private-key vector mismatch")

    message = as_array(bytes.fromhex(signing["message_hex"]))
    context = as_array(bytes.fromhex(signing["context_hex"]))
    randomizer = as_array(bytes(32))
    signature = (ctypes.c_uint8 * SIGNATURE_BYTES)()
    if loaded.pqbtc_mldsa44_test_sign_fixed_randomizer(
        signature,
        secret_key,
        message,
        len(message),
        context,
        len(context),
        randomizer,
    ) != 0:
        raise HarnessError("test-only fixed-randomizer signing failed")
    if hashlib.sha256(bytes(signature)).hexdigest() != signing["expected_signature_sha256"]:
        raise HarnessError("frozen three-oracle signature vector mismatch")
    if loaded.pqbtc_mldsa44_verify_strict(
        signature,
        len(signature),
        public_key,
        len(public_key),
        message,
        len(message),
        context,
        len(context),
    ) != 0:
        raise HarnessError("strict verification rejected the frozen signature vector")

    production_signatures = []
    for _ in range(2):
        hedged_signature = (ctypes.c_uint8 * SIGNATURE_BYTES)()
        if production.pqbtc_mldsa44_sign_hedged(
            hedged_signature,
            len(hedged_signature),
            secret_key,
            len(secret_key),
            public_key,
            len(public_key),
            message,
            len(message),
            context,
            len(context),
        ) != 0:
            raise HarnessError("production-shaped OS-entropy signing failed")
        if production.pqbtc_mldsa44_verify_strict(
            hedged_signature,
            len(hedged_signature),
            public_key,
            len(public_key),
            message,
            len(message),
            context,
            len(context),
        ) != 0:
            raise HarnessError("production-shaped self-verifiable signature was rejected")
        production_signatures.append(bytes(hedged_signature))
    if production_signatures[0] == production_signatures[1]:
        raise HarnessError("two production-shaped hedged signatures were identical")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and test the isolated ML-DSA-44 wrapper")
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--sanitizers", action="store_true")
    args = parser.parse_args()

    manifest = validate_source_capsule()
    if args.manifest_only:
        print(
            "ML-DSA-44 source capsule OK: "
            f"{manifest['commit']} ({len(manifest['files'])} files)"
        )
        return 0

    compiler = os.environ.get("CC", "cc")
    if shutil.which(compiler) is None:
        raise HarnessError(f"C compiler not found: {compiler}")
    with tempfile.TemporaryDirectory(prefix="pqbtc-mldsa44-wrapper-") as temporary:
        build_dir = Path(temporary)
        production_library = compile_shared(compiler, build_dir, testing=False)
        audit_production_symbols(production_library)
        smoke = compile_smoke(compiler, build_dir, sanitizers=args.sanitizers)
        run_smoke(smoke, sanitizers=args.sanitizers)
        if not args.sanitizers:
            test_library = compile_shared(compiler, build_dir, testing=True)
            validate_frozen_vectors(test_library, production_library)

    mode = "sanitized" if args.sanitizers else "normal"
    print(f"ML-DSA-44 isolated wrapper tests passed ({mode}, {compiler})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as error:
        print(f"wrapper harness: {error}", file=sys.stderr)
        raise SystemExit(1)
