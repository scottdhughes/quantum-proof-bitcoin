#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained Linux proof. --preflight-only is data-only, never builds/loads C."""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARCHIVE_SHA = "a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98"
CAPSULE_SHA = "e07f0f6a9bb46fd9afcbe7699f95f1ce43e6fcf48623d6de7b3e95ed405023cb"
FIXTURE_SHA = "919274349faf698e32052f75e07e4f7e6fbb997f45ca9895902623fe40b46506"
KEY_HASHES = {
    "key_lifecycle.c": "0314cc2ac67b8646fdd7925092652770f016d0efab60922ce1ca57bc10a05c42",
    "key_lifecycle.h": "7ea8b8e5fcd6b389334b6b9a9d24c442ae3e9a79964bfce40aa7cdd2d5fc2b64",
    "key_lifecycle_test.h": "05f6893a3f86e990804d7df4f05d0e397dbdd88be7a0fead56a83316855f03a6",
    "key_lifecycle_smoke.c": "eafa74db19a55eaa89494f4c46e5d9deaf0e89337ff5645c9adab315a5878099",
    "exports.map": "3696587b7350eaec149cf82e5785c1828e9201128d01ab0f93ac2ead8583666e",
    "run_key_lifecycle_tests.py": "b6e833ef417f4b7d69e86c66ac39823e0c2ffe096d42be3f0f8b71a7f9c86a5d",
    "key_runtime.c": "8baccccc889000bf9022f44bd0bd692f6570449c806e5b792041b025e97f9b86",
    "key_runtime_probe.c": "17c03a3c66b05257fed1def93dcccf34bf8aa4ae219d693c72f5379530b3203c",
    "run_key_runtime_tests.py": "9640534a315765d66894f620b0d923c66465e380899b9037ab11eefe2f79ae0d",
}
CONTROL_HASHES = {
    "contrib/ml-dsa-engineering/backend_admission.json": "0a0a349ab822373484db4b08412660d142bd09bc0507038b257593e53d3411c0",
    "contrib/ml-dsa-ref/review_baseline_commit.txt": "2133fca644808b95c8e5d7f6b62c1fb11367ef3e46b0fdee79674452de8cba24",
    "contrib/shrincs/manifest.json": "c7b492c46e99cda50f2cc6f3c69dba454ca2841fdc7a152141c071ba11e7e990",
}
MODULE_FILES = (
    "backup.c",
    "backup.h",
    "backup_test.h",
    "backup_smoke.c",
    "backup_file.c",
    "backup_file.h",
    "backup_file_smoke.c",
    "pilot_demo.c",
    "process_demo_test.py",
    "fixture_reference.py",
    "exports.map",
    "build_openssl.sh",
    "run_backup_tests.py",
)
METADATA_FILES = (
    "ci/test/test_ml_dsa_wallet_backup.py",
    ".github/workflows/ml-dsa-44-wallet-backup.yml",
    "docs/ML_DSA_44_WALLET_BACKUP.md",
    "docs/ML_DSA_44_WALLET_BACKUP_DESIGN.md",
)
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
EXPECTED_EXPORTS |= {
    "pqbtc_backup_create",
    "pqbtc_backup_restore",
    "pqbtc_pilot_intent",
    "pqbtc_pilot_sign",
    "pqbtc_pilot_verify",
}


class HarnessError(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, root):
    path, root = Path(path), Path(root)
    for part in (path, *path.parents):
        if part.is_symlink():
            raise HarnessError("symlink input: " + str(path))
        if part == root:
            break
    if not path.is_file():
        raise HarnessError("missing source input: " + str(path))
    return path.read_bytes()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_sources(root):
    root = Path(root)
    for name, want in KEY_HASHES.items():
        if digest(regular(root / "contrib/ml-dsa-key-lifecycle" / name, root)) != want:
            raise HarnessError("frozen key module mismatch: " + name)
    for name, want in CONTROL_HASHES.items():
        if digest(regular(root / name, root)) != want:
            raise HarnessError("frozen control mismatch: " + name)
    # Verify this Python reader itself before importing its data-only functions.
    reader = load(
        root / "contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py",
        "frozen_key_reader",
    )
    try:
        proof = reader.validate_sources(root)
    except Exception as error:
        raise HarnessError("frozen wrapper/capsule mismatch: " + str(error)) from error
    if proof["capsule_sha256"] != CAPSULE_SHA:
        raise HarnessError("unexpected source capsule")
    return {
        "result": "PASS",
        "capsule_sha256": CAPSULE_SHA,
        "key_module_files": 9,
        "controls_frozen": True,
    }


def source_hashes():
    actual = []
    for path in HERE.rglob("*"):
        if path.is_symlink():
            raise HarnessError("symlink module input")
        if path.is_file() and "__pycache__" not in path.parts:
            actual.append(path.relative_to(HERE).as_posix())
    if sorted(actual) != sorted(MODULE_FILES):
        raise HarnessError("unexpected module file inventory")
    paths = [HERE / name for name in MODULE_FILES]
    paths += [ROOT / "contrib/ml-dsa-key-lifecycle" / name for name in KEY_HASHES]
    paths += [ROOT / name for name in CONTROL_HASHES] + [
        ROOT / name for name in METADATA_FILES
    ]
    reader = load(
        ROOT / "contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py",
        "frozen_key_reader",
    )
    paths += [ROOT / reader.WRAPPER / name for name in reader.SOURCE_HASHES]
    paths += [ROOT / name for name in reader.METADATA_FILES]
    return {
        path.relative_to(ROOT).as_posix(): digest(regular(path, ROOT)) for path in paths
    }


def runtime_identity(expected, root=ROOT):
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if head.returncode:
        if expected:
            raise HarnessError("cannot establish expected runtime source")
        return {"commit": None, "worktree": "unavailable; source hashes only"}
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if expected and (head.stdout.strip() != expected or status):
        raise HarnessError("wrong or dirty expected runtime")
    return {"commit": head.stdout.strip(), "worktree": "dirty" if status else "clean"}


def require_exports(actual):
    if set(actual) != EXPECTED_EXPORTS:
        raise HarnessError("normal export surface mismatch")


def smoke_result(text, kind):
    if kind == "file" and text == "backup file smoke: PASS (1034 checks)\n":
        return {"result": "PASS", "checks": 1034}
    prefix = "backup crypto runtime: OpenSSL 3.6.5 29 Sep 2026\nbackup smoke: PASS (1376 checks)\n"
    if kind != "codec" or not text.startswith(prefix):
        raise HarnessError("incomplete/wrong runtime native observations")
    pairwise = strict_json(text[len(prefix) :])
    if (
        not isinstance(pairwise, dict)
        or set(pairwise) != {"pairwise_random_distinct", "pairwise_identity_equal"}
        or any(value is not True for value in pairwise.values())
    ):
        raise HarnessError("missing/false pairwise real-random recovery observation")
    return {"result": "PASS", "checks": 1376, **pairwise}


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise HarnessError("duplicate observation field")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (TypeError, ValueError) as error:
        raise HarnessError("invalid observation JSON") from error


def backup_runtime_result(text):
    value = strict_json(text)
    expected = {
        "schema": 1,
        "scenario": "backup-runtime",
        "checks": 24,
        "child_checks": 7,
        "core_zero": True,
        "dump_zero_before_drift": True,
        "origin_rejected": True,
        "public_verify_child": True,
        "drift_rejected": True,
        "parent_destroyed": True,
        "result": "PASS",
    }
    if (
        not isinstance(value, dict)
        or set(value) != set(expected)
        or any(
            type(value[key]) is not type(want) or value[key] != want
            for key, want in expected.items()
        )
    ):
        raise HarnessError("incomplete/wrong composed runtime observations")
    return value


CONTROL_MARKERS = {
    "wipe": "pqbtc_backup_test_clean()==1",
    "authentication": "restore(&restored,package)==PQBTC_BACKUP_AUTH && restored==NULL",
    "aad": "memcmp(hash,want_package_hash,32)==0",
    "policy": "pqbtc_pilot_verify(policy_signature,2420,public_key,1312,intent,112,challenge)==PQBTC_BACKUP_AUTH",
}


def require_control(kind, code, error):
    if (
        kind not in CONTROL_MARKERS
        or code != 1
        or not re.search(
            r"^FAIL: [^\n]+:\d+: " + re.escape(CONTROL_MARKERS[kind]) + r"$",
            error,
            re.MULTILINE,
        )
    ):
        raise HarnessError("unqualified behavioral negative control: " + kind)


def validate_openssl(prefix):
    prefix = Path(prefix)
    if regular(prefix / "source-archive.sha256", prefix) != (
        (ARCHIVE_SHA + "\n").encode()
    ):
        raise HarnessError("wrong OpenSSL archive marker")
    archive = digest(regular(prefix / "lib/libcrypto.a", prefix))
    cli = prefix / "bin/openssl"
    cli_hash = digest(regular(cli, prefix))
    result = subprocess.run(
        [str(cli), "version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if not result.startswith("OpenSSL 3.6.5 "):
        raise HarnessError("wrong OpenSSL runtime version")
    return {
        "archive_sha256": ARCHIVE_SHA,
        "static_libcrypto_sha256": archive,
        "cli_sha256": cli_hash,
        "cli_version": result,
        "origin_limit": "marker joined to checksum-verified build step; arbitrary library authenticity is a build obligation",
    }


def process_result(text):
    result = json.loads(text)
    if result.get("result") != "PASS" or result.get("checks") != 16:
        raise HarnessError("incomplete process proof")
    phases = result.get("phases", [])
    commands = result.get("commands", [])
    if [p.get("phase") for p in phases] != [
        "challenge",
        "produce",
        "restore-sign",
        "verify",
    ] or len(commands) != 16:
        raise HarnessError("missing process phases/commands")
    if (
        any(
            type(p.get("pid")) is not int
            or p["pid"] <= 0
            or p.get("zero_value_only") is not True
            for p in phases
        )
        or len({p["pid"] for p in phases}) != 4
    ):
        raise HarnessError("unqualified process identity")
    phase_index = 0
    actions = (
        ["challenge", "produce", "produce", "restore-sign", "verify"]
        + ["verify"] * 9
        + ["restore-sign", "produce"]
    )
    for i, cmd in enumerate(commands):
        success = i in (0, 1, 3, 4)
        if cmd.get("returncode") != (0 if success else 1) or cmd.get("stderr") != (
            "" if success else "zero-value pilot phase rejected\n"
        ):
            raise HarnessError("wrong phase outcome")
        if len(cmd.get("command", [])) != 3 or cmd["command"][1] != actions[i]:
            raise HarnessError("wrong phase command")
        if success:
            try:
                actual = json.loads(cmd.get("stdout", ""))
            except ValueError as error:
                raise HarnessError("missing native phase stdout") from error
            if actual != phases[phase_index]:
                raise HarnessError("phase stdout disagrees with process summary")
            phase_index += 1
        elif cmd.get("stdout") != "":
            raise HarnessError("unexpected rejected phase stdout")
    return {"result": "PASS", "checks": 16, "phases": phases}


def prove(compiler, prefix, expected, allow_source_only):
    if sys.platform != "linux":
        raise HarnessError("new native proof is contained Linux only")
    if not expected and not allow_source_only:
        raise HarnessError(
            "native proof needs --expect-commit or explicit --allow-source-only"
        )
    frozen = validate_sources(ROOT)
    hashes = source_hashes()
    identity = runtime_identity(expected)
    crypto = validate_openssl(prefix)
    prefix = Path(prefix)
    print(
        "backup-preflight: "
        + json.dumps(
            {"runtime": identity, "source_hashes": hashes, "openssl": crypto, **frozen},
            sort_keys=True,
        ),
        flush=True,
    )
    records = []

    def run(command, status=0, env=None):
        environment = dict(os.environ)
        environment["OPENSSL_CONF"] = "/dev/null"
        environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        environment.update(env or {})
        child = subprocess.run(
            [str(x) for x in command],
            text=True,
            capture_output=True,
            env=environment,
            timeout=600,
        )
        records.append(
            {
                "command": [str(x) for x in command],
                "returncode": child.returncode,
                "stdout": child.stdout,
                "stderr": child.stderr,
            }
        )
        if child.returncode != status or (status == 0 and child.stderr):
            raise HarnessError(
                "native command failed/diagnostic: "
                + str(command[0])
                + "\n"
                + child.stdout
                + child.stderr
            )
        return child.stdout

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
        "-I" + str(ROOT / "contrib/ml-dsa-engineering"),
        "-I" + str(HERE),
        "-I" + str(prefix / "include"),
    ]
    link = [prefix / "lib/libcrypto.a", "-ldl", "-pthread"]
    observations = {}
    controls = {}
    with tempfile.TemporaryDirectory(prefix="pqbtc-backup-proof-") as tmp:
        tmp = Path(tmp)
        runtime_reader = load(
            ROOT / "contrib/ml-dsa-key-lifecycle/run_key_runtime_tests.py",
            "owned_runtime_reader",
        )

        def runtime_run(command, env=None, expected_status=0):
            run(command, expected_status, env)
            return records[-1]

        protected = runtime_reader.prove_runtime(compiler, tmp, runtime_run)
        disassembly = protected.pop("disassembly")
        protected["disassembly_sha256"] = {
            name: digest(text.encode()) for name, text in disassembly.items()
        }
        library = tmp / "backup.so"
        run(
            [
                *flags,
                "-O2",
                "-fPIC",
                "-shared",
                HERE / "backup.c",
                *link,
                "-Wl,--version-script=" + str(HERE / "exports.map"),
                "-o",
                library,
            ]
        )
        exports = {
            line.split()[-1]
            for line in run(["nm", "-D", "--defined-only", library]).splitlines()
            if line.split()
        }
        require_exports(exports)
        unfiltered = tmp / "unfiltered.so"
        run(
            [
                *flags,
                "-O2",
                "-fPIC",
                "-shared",
                HERE / "backup.c",
                *link,
                "-o",
                unfiltered,
            ]
        )
        try:
            require_exports(
                {
                    line.split()[-1]
                    for line in run(
                        ["nm", "-D", "--defined-only", unfiltered]
                    ).splitlines()
                    if line.split()
                }
            )
        except HarnessError:
            controls["unfiltered_exports"] = "REJECTED"
        else:
            raise HarnessError("unfiltered export control accepted")
        reference = load(HERE / "fixture_reference.py", "public_fixture_reference")
        expected_package, gcrypt_version = reference.fixture()
        if digest(expected_package) != FIXTURE_SHA:
            raise HarnessError("independent public fixture changed")
        for sanitized in (False, True):
            label = "sanitized" if sanitized else "normal"
            mode = (
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
            smoke = tmp / ("smoke-" + label)
            files = tmp / ("files-" + label)
            run(
                [
                    *flags,
                    *mode,
                    "-DPQBTC_MLDSA44_TESTING=1",
                    HERE / "backup.c",
                    HERE / "backup_smoke.c",
                    *link,
                    "-o",
                    smoke,
                ]
            )
            observed = bytes.fromhex(run([smoke, "--fixture"]).strip())
            if observed != expected_package:
                raise HarnessError("native fixture differs from independent oracle")
            observations[label + "_codec"] = smoke_result(run([smoke]), "codec")
            observations[label + "_runtime"] = backup_runtime_result(
                run([smoke, "--runtime-contract"])
            )
            if run([smoke, "--padding-contract"]) != "backup padding: PASS\n":
                raise HarnessError("missing composed padding alias proof")
            run(
                [
                    *flags,
                    *mode,
                    "-DPQBTC_BACKUP_FILE_TESTING=1",
                    HERE / "backup_file.c",
                    HERE / "backup_file_smoke.c",
                    *link,
                    "-o",
                    files,
                ]
            )
            observations[label + "_files"] = smoke_result(run([files]), "file")
            demo = tmp / ("demo-" + label)
            verifier = tmp / ("verifier-" + label)
            for executable, extra in (
                (demo, []),
                (verifier, ["-DPQBTC_PILOT_VERIFY_ONLY=1"]),
            ):
                run(
                    [
                        *flags,
                        *mode,
                        *extra,
                        HERE / "backup.c",
                        HERE / "backup_file.c",
                        HERE / "pilot_demo.c",
                        *link,
                        "-o",
                        executable,
                    ]
                )
            observations[label + "_process"] = process_result(
                run([sys.executable, HERE / "process_demo_test.py", demo, verifier])
            )
            print(
                "backup observed: "
                + json.dumps(
                    {
                        label: {
                            k: v for k, v in observations.items() if k.startswith(label)
                        }
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        original = (HERE / "backup.c").read_text()
        mutations = {
            "wipe": (
                "    pqbtc_mldsa44_zeroize(scratch,sizeof(*scratch));",
                "    (void)scratch;",
            ),
            "authentication": (
                "if(EVP_DecryptFinal_ex(ctx,scratch.plaintext+n,&tail)!=1 || tail!=0) goto done;",
                "(void)tail;",
            ),
            "aad": ("EVP_EncryptUpdate(ctx,NULL,&n,scratch.package,96)!=1 ||", "0 ||"),
            "policy": (
                "if(pk==NULL || pk_size!=1312 || !ValidIntent(intent,size,pk,challenge)) return PQBTC_BACKUP_AUTH;",
                "(void)challenge; if(pk==NULL || pk_size!=1312) return PQBTC_BACKUP_AUTH;",
            ),
        }
        for kind, (needle, replacement) in mutations.items():
            if original.count(needle) != 1:
                raise HarnessError("cannot build scoped negative control")
            source = original.replace(needle, replacement).replace(
                '#include "../ml-dsa-key-lifecycle/key_lifecycle.c"',
                '#include "'
                + str(ROOT / "contrib/ml-dsa-key-lifecycle/key_lifecycle.c")
                + '"',
            )
            mutant = tmp / (kind + ".c")
            mutant.write_text(source)
            executable = tmp / kind
            run(
                [
                    *flags,
                    "-O2",
                    "-DPQBTC_MLDSA44_TESTING=1",
                    mutant,
                    HERE / "backup_smoke.c",
                    *link,
                    "-o",
                    executable,
                ]
            )
            run([executable], 1)
            require_control(kind, records[-1]["returncode"], records[-1]["stderr"])
            controls[kind] = "REJECTED_AT_EXPECTED_ASSERTION"
    if source_hashes() != hashes or runtime_identity(expected) != identity:
        raise HarnessError("source changed during native proof")
    report = {
        "schema_version": 2,
        "result": "PASS",
        "runtime": identity,
        "trust": "exact clean checkout" if expected else "LOCAL_SOURCE_HASHES_ONLY",
        "source_hashes": hashes,
        "frozen": frozen,
        "compiler": version,
        "platform": {
            "sys": sys.platform,
            "machine": platform.machine(),
            "kernel": platform.release(),
            "libc": platform.libc_ver(),
        },
        "protected_runtime": protected,
        "openssl": crypto,
        "exports": sorted(exports),
        "observations": observations,
        "negative_controls": controls,
        "fixture": {
            "sha256": FIXTURE_SHA,
            "reference": "hashlib.scrypt + libgcrypt AES256GCM",
            "libgcrypt_version": gcrypt_version,
            "public_synthetic_only": True,
        },
        "limits": "zero-value contrib prototype; not wallet/node/consensus integration, cryptographic/whole-system erasure/platform or production qualification; backend/hold unchanged",
    }
    return report, records, disassembly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--cc", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--openssl-prefix", type=Path)
    parser.add_argument("--expect-commit")
    parser.add_argument("--allow-source-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.preflight_only:
            result = validate_sources(ROOT)
            source_hashes()
            print(json.dumps(result, sort_keys=True))
            return 0
        if (
            args.output_dir is None
            or args.output_dir.exists()
            or args.openssl_prefix is None
        ):
            raise HarnessError("new --output-dir and pinned --openssl-prefix required")
        report, records, disassembly = prove(
            args.cc, args.openssl_prefix, args.expect_commit, args.allow_source_only
        )
        args.output_dir.mkdir(mode=0o700)
        for name, value in (
            ("backup-report.json", report),
            ("native-transcript.json", records),
        ):
            (args.output_dir / name).write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n"
            )
        for name, text in disassembly.items():
            (args.output_dir / name).write_text(text, encoding="utf8")
        checksums = "".join(
            digest(path.read_bytes()) + "  " + path.name + "\n"
            for path in sorted(args.output_dir.iterdir())
        )
        (args.output_dir / "evidence-sha256.txt").write_text(checksums)
        print("backup evidence: PASS " + str(args.output_dir), flush=True)
        return 0
    except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("backup proof failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
