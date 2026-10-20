#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Linux contained readiness proof. --preflight-only never compiles or loads C."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WRAPPER = Path("contrib/ml-dsa-engineering")
CAPSULE_HASH = "2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb"
SOURCE_HASHES = {
    "pqbtc_mldsa44.c": "53282d3eb0d29b45cd430236bc8a01ca15f1d91622c2adeeb74b3f823ac832e4",
    "pqbtc_mldsa44.h": "9bb114b51bdc225605b99c92ed8b21ed5e08f9c8efb7ca7924214e1f679a8255",
    "pqbtc_mldsa44_config.h": "50a5b8f09700a2e6b6237c119b5842236f4cd56029f802dbefddd5e724b0d624",
    "pqbtc_mldsa44_test.h": "4d76421c13ff2cd28f73c81c5784d5b34f2bf1aef1901cac841de08240e8402f",
    "vendor/mldsa-native/SOURCE.json": "19d5cd67692758d1315312b7e27e7c57dab470971ec18ea92faa383dbb8e1165",
}
EXPECTED_EXPORTS = {
    "pqbtc_mldsa44_key_" + name
    for name in (
        "runtime_init",
        "generate",
        "import_seed",
        "public",
        "export_seed",
        "sign_hedged",
        "verify_strict",
        "destroy",
    )
}
MODULE_FILES = (
    "key_lifecycle.c",
    "key_lifecycle.h",
    "key_lifecycle_test.h",
    "key_lifecycle_smoke.c",
    "exports.map",
    "run_key_lifecycle_tests.py",
    "key_runtime.c",
    "key_runtime_probe.c",
    "run_key_runtime_tests.py",
)
CONTROL_HASHES = {
    "contrib/ml-dsa-engineering/backend_admission.json": "8c786b4a33596323f05100b102d46963445c3c0f6f9430c6459f680cae91ed97",
    "contrib/ml-dsa-ref/review_baseline_commit.txt": "05e72b9f3368e3c3c43c51efb97cc9a957733bdb405f9850899e85372281d5c6",
    "contrib/shrincs/manifest.json": "c7b492c46e99cda50f2cc6f3c69dba454ca2841fdc7a152141c071ba11e7e990",
}
METADATA_FILES = (
    "ci/test/test_ml_dsa_key_lifecycle.py",
    ".github/workflows/ml-dsa-44-key-lifecycle.yml",
    "docs/ML_DSA_44_KEY_LIFECYCLE.md",
)
ACVP_PUBLIC_HASH = "451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34"


class HarnessError(RuntimeError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path, root):
    # Check every component before opening: Path.is_file alone follows symlinks.
    for part in (path, *path.parents):
        if part.is_symlink():
            raise HarnessError(f"symlink source input: {path.relative_to(root)}")
        if part == root:
            break
    if not path.is_file():
        raise HarnessError(f"missing source file: {path.relative_to(root)}")
    return path.read_bytes()


def validate_sources(root):
    root = Path(root)
    for relative, expected in SOURCE_HASHES.items():
        if sha256(regular_bytes(root / WRAPPER / relative, root)) != expected:
            raise HarnessError(f"frozen source mismatch: {relative}")
    capsule = root / WRAPPER / "vendor/mldsa-native"
    manifest = json.loads(regular_bytes(capsule / "SOURCE.json", root))
    actual = []
    for path in capsule.rglob("*"):
        if path.is_symlink():
            raise HarnessError("symlink capsule input")
        if path.is_file() and path != capsule / "SOURCE.json":
            actual.append(path.relative_to(capsule).as_posix())
    actual.sort()
    if actual != manifest["files"]:
        raise HarnessError("capsule file set mismatch")
    lines = []
    for name in actual:
        lines.append(f"{sha256(regular_bytes(capsule / name, root))}  ./{name}\n")
    digest = sha256("".join(lines).encode())
    if digest != CAPSULE_HASH:
        raise HarnessError("frozen source capsule mismatch")
    for name, expected in CONTROL_HASHES.items():
        if sha256(regular_bytes(root / name, root)) != expected:
            raise HarnessError("frozen control mismatch: " + name)
    owned = root / "contrib/ml-dsa-key-lifecycle"
    actual_owned = []
    for path in owned.rglob("*"):
        if path.is_symlink():
            raise HarnessError("symlink owned module input")
        if path.is_file() and "__pycache__" not in path.parts:
            actual_owned.append(path.relative_to(owned).as_posix())
    if sorted(actual_owned) != sorted(MODULE_FILES):
        raise HarnessError("owned module file inventory mismatch")
    return {
        "result": "PASS",
        "capsule_sha256": digest,
        "native_commit": manifest["commit"],
        "capsule_files": len(actual),
    }


def require_exports(actual):
    if actual != EXPECTED_EXPORTS:
        raise HarnessError(f"symbol surface mismatch: {sorted(actual)}")


def source_hashes():
    paths = [HERE / name for name in MODULE_FILES]
    paths += [ROOT / WRAPPER / name for name in SOURCE_HASHES]
    paths += [ROOT / name for name in (*CONTROL_HASHES, *METADATA_FILES)]
    return {
        p.relative_to(ROOT).as_posix(): sha256(regular_bytes(p, ROOT)) for p in paths
    }


def runtime_identity(expected):
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True
    )
    if head.returncode:
        if expected:
            raise HarnessError("cannot establish expected runtime checkout")
        return {"commit": None, "worktree": "unavailable; source hashes only"}
    status = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    commit = head.stdout.strip()
    if expected and (commit != expected or status):
        raise HarnessError("runtime checkout mismatch or dirty source")
    return {"commit": commit, "worktree": "dirty" if status else "clean"}


def symbols(output):
    return {line.split()[-1] for line in output.splitlines() if line.split()}


def smoke_result(output, expected):
    if output != f"key lifecycle smoke: PASS ({expected} checks)\n":
        raise HarnessError("incomplete or unexpected native smoke observations")
    return {"result": "PASS", "checks": expected}


def runtime_reader():
    path = HERE / "run_key_runtime_tests.py"
    regular_bytes(path, ROOT)
    spec = importlib.util.spec_from_file_location("owned_runtime_reader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_wipe_rejection(code, error):
    try:
        runtime_reader().require_runtime_control("wipe", code, error)
    except RuntimeError as problem:
        raise HarnessError(
            "missing observed cleanup failure for omitted-wipe control"
        ) from problem


def require_alias_rejection(kind, code, error):
    markers = {
        "constructor": "pqbtc_mldsa44_key_import_seed(&alias.owner, alias.seed, sizeof(alias.seed)) == -1",
        "allocation-tail": "pqbtc_mldsa44_key_public(key, (uint8_t*)key + public_offsets[i], 1312) == -1",
    }
    if kind not in markers or code != 1 or markers[kind] not in error:
        raise HarnessError("missing observed alias-boundary failure: " + kind)


def acvp_identity(library):
    # Published synthetic ACVP fixture only, never a wallet secret or key import.
    lib = ctypes.CDLL(str(library))
    lib.pqbtc_mldsa44_key_runtime_init.argtypes = []
    lib.pqbtc_mldsa44_key_runtime_init.restype = ctypes.c_int
    if lib.pqbtc_mldsa44_key_runtime_init() != 0:
        raise HarnessError("ACVP caller protected runtime initialization failed")
    owner = ctypes.c_void_p()
    seed = (ctypes.c_ubyte * 32).from_buffer_copy(
        bytes.fromhex(
            "d71361c000f9a7bc99dfb425bcb6bb27c32c36ab444ff3708b2d93b4e66d5b5b"
        )
    )
    public = (ctypes.c_ubyte * 1312)()
    lib.pqbtc_mldsa44_key_import_seed.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    lib.pqbtc_mldsa44_key_import_seed.restype = ctypes.c_int
    lib.pqbtc_mldsa44_key_public.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    lib.pqbtc_mldsa44_key_public.restype = ctypes.c_int
    lib.pqbtc_mldsa44_key_destroy.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.pqbtc_mldsa44_key_destroy.restype = None
    try:
        if lib.pqbtc_mldsa44_key_import_seed(ctypes.byref(owner), seed, 32) != 0:
            raise HarnessError("ACVP seed import failed")
        if lib.pqbtc_mldsa44_key_public(owner, public, 1312) != 0:
            raise HarnessError("ACVP public export failed")
        digest = sha256(bytes(public))
        if digest != ACVP_PUBLIC_HASH:
            raise HarnessError("official ACVP public key identity mismatch")
        return digest
    finally:
        lib.pqbtc_mldsa44_key_destroy(ctypes.byref(owner))


def prove(compiler, expected_commit):
    preflight = validate_sources(ROOT)
    identity = runtime_identity(expected_commit)
    frozen = source_hashes()
    print(
        "key-lifecycle-preflight: "
        + json.dumps({"runtime": identity, **preflight}, sort_keys=True),
        flush=True,
    )
    transcript = []

    def run(command, env=None, expected_status=0):
        completed = subprocess.run(
            [str(s) for s in command],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
        )
        transcript.append(
            {
                "command": [str(s) for s in command],
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        if completed.returncode != expected_status:
            raise HarnessError(
                f"native command failed: {command[0]}\n{completed.stdout}{completed.stderr}"
            )
        return completed.stdout

    if not sys.platform.startswith("linux"):
        raise HarnessError("native proof currently supports isolated Linux only")
    if not shutil.which(compiler) or not shutil.which("nm"):
        raise HarnessError("compiler and nm are required")
    version = run([compiler, "--version"]).splitlines()[0]
    flags = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unknown-pragmas",
        "-pthread",
        "-fvisibility=hidden",
        f"-I{ROOT / WRAPPER}",
        f"-I{HERE}",
    ]
    with tempfile.TemporaryDirectory(prefix="pqbtc-key-lifecycle-") as tmp:
        build = Path(tmp)
        library = build / "key.so"
        common = [*flags, "-O2", "-fPIC", "-shared", HERE / "key_lifecycle.c"]
        run([*common, f"-Wl,--version-script={HERE / 'exports.map'}", "-o", library])
        exported = symbols(run(["nm", "-D", "--defined-only", library]))
        require_exports(exported)
        # A real unfiltered library must fail the same gate: no always-green audit.
        unfiltered = build / "unfiltered.so"
        run([*common, "-o", unfiltered])
        bad = symbols(run(["nm", "-D", "--defined-only", unfiltered]))
        try:
            require_exports(bad)
        except HarnessError:
            pass
        else:
            raise HarnessError("unfiltered symbol negative control was accepted")
        official_hash = acvp_identity(library)

        # The allocation is now a protected mapping. Its actual omitted-wipe
        # control observes the normal product path at munmap, without a testing
        # callback in that path, alongside all optimized release builds.
        def capture(command, env=None, expected_status=0):
            combined = os.environ.copy()
            combined.update(env or {})
            run(command, combined, expected_status)
            return transcript[-1]

        try:
            protected = runtime_reader().prove_runtime(compiler, build, capture)
        except RuntimeError as problem:
            raise HarnessError(str(problem)) from problem
        disassembly = protected.pop("disassembly")
        protected["disassembly_sha256"] = {
            name: sha256(text.encode()) for name, text in disassembly.items()
        }
        original = (HERE / "key_lifecycle.c").read_text(encoding="utf8")
        # These compiled mutations calibrated the review repair: the old smoke
        # accepted both. Expanded boundary tests must reject the corresponding
        # unsafe behavior, not merely crash or fail an unrelated check.
        constructor_guard = (
            "seed_size != PQBTC_MLDSA44_KEY_SEED_BYTES ||\n"
            "        RangesOverlap((const uint8_t*)out, sizeof(*out), seed, seed_size)"
        )
        output_guard = (
            "RangesOverlap(output, size, (const uint8_t*)key, key->body_size)"
        )
        mutants = {
            "constructor": (
                constructor_guard,
                "seed_size != PQBTC_MLDSA44_KEY_SEED_BYTES",
            ),
            "allocation-tail": (
                output_guard,
                "RangesOverlap(output, size, (const uint8_t*)key, sizeof(key->seed))",
            ),
        }
        for kind, (needle, replacement) in mutants.items():
            if original.count(needle) != 1:
                raise HarnessError("cannot construct scoped alias control: " + kind)
            source = build / (kind + ".c")
            source.write_text(original.replace(needle, replacement), encoding="utf8")
            exe = build / kind
            run(
                [
                    *flags,
                    "-O2",
                    "-DPQBTC_MLDSA44_TESTING=1",
                    source,
                    HERE / "key_lifecycle_smoke.c",
                    "-o",
                    exe,
                ]
            )
            run([exe], expected_status=1)
            require_alias_rejection(
                kind, transcript[-1]["returncode"], transcript[-1]["stderr"]
            )
        observations = {}
        for injected in (True, False):
            for sanitized in (False, True):
                mode = ("injected" if injected else "os-entropy") + (
                    "-asan-ubsan" if sanitized else "-normal"
                )
                exe = build / mode
                options = ["-DPQBTC_MLDSA44_TESTING=1"] if injected else []
                options += (
                    [
                        "-O1",
                        "-g",
                        "-fsanitize=address,undefined",
                        "-fno-omit-frame-pointer",
                        "-fno-sanitize-recover=all",
                    ]
                    if sanitized
                    else ["-O2"]
                )
                run(
                    [
                        *flags,
                        *options,
                        HERE / "key_lifecycle.c",
                        HERE / "key_lifecycle_smoke.c",
                        "-o",
                        exe,
                    ]
                )
                env = os.environ.copy()
                env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
                env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
                observations[mode] = smoke_result(
                    run([exe], env), 119 if injected else 52
                )
        if source_hashes() != frozen or validate_sources(ROOT) != preflight:
            raise HarnessError("source changed during native proof")
        if runtime_identity(expected_commit) != identity:
            raise HarnessError("runtime checkout changed during native proof")
        report = {
            "schema": 2,
            "result": "PASS",
            "scope": "isolated Linux ML-DSA-44 entropy/owned-key readiness only",
            "production_backend": "NONE",
            "release_hold": True,
            "trust": "EXACT_CLEAN_CHECKOUT"
            if expected_commit
            else "LOCAL_SOURCE_HASHES_ONLY",
            "runtime": identity,
            "preflight": preflight,
            "source_sha256": frozen,
            "platform": {
                "sys": sys.platform,
                "machine": os.uname().machine,
                "compiler": version,
                "kernel": os.uname().release,
                "libc": platform.libc_ver(),
            },
            "normal_exports": sorted(exported),
            "unfiltered_exports_rejected": sorted(bad),
            "acvp_public_sha256": official_hash,
            "observations": observations,
            "omitted_allocation_wipe_rejected": True,
            "protected_runtime": protected,
            "alias_mutants_rejected": sorted(mutants),
        }
        return report, transcript, disassembly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--expect-commit")
    args = parser.parse_args()
    try:
        if args.preflight_only:
            print(json.dumps(validate_sources(ROOT), indent=2, sort_keys=True))
            return 0
        if args.expect_commit and not re.fullmatch(r"[0-9a-f]{40}", args.expect_commit):
            raise HarnessError("expected commit must be a full lowercase SHA")
        report, transcript, disassembly = prove(args.cc, args.expect_commit)
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=False)
            for name, data in (
                ("key-lifecycle-report.json", report),
                ("native-transcript.json", transcript),
            ):
                (args.output_dir / name).write_text(
                    json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf8"
                )
            for name, text in disassembly.items():
                (args.output_dir / name).write_text(text, encoding="utf8")
            lines = [
                f"{sha256(p.read_bytes())}  {p.name}\n"
                for p in sorted(args.output_dir.iterdir())
            ]
            (args.output_dir / "evidence-sha256.txt").write_text(
                "".join(lines), encoding="utf8"
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"key lifecycle proof FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
