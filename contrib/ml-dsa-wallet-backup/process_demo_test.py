#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained native integration test. Imports are data-only, calls execute C."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

PROCESS_HELPER = Path(__file__).resolve().parents[1] / "ml-dsa-qualification/native_process.py"
PROCESS_HELPER_SHA = "dddab1d1543f17d113a043780b00c83a480aee6fe63876861cf271b4a2cd1bff"


def process_helper():
    # This nested CLI must independently verify its executable Python dependency.
    if any(part.is_symlink() for part in (PROCESS_HELPER, *PROCESS_HELPER.parents)) or not PROCESS_HELPER.is_file():
        raise RuntimeError("missing or symlink process helper")
    if hashlib.sha256(PROCESS_HELPER.read_bytes()).hexdigest() != PROCESS_HELPER_SHA:
        raise RuntimeError("changed process helper")
    spec = importlib.util.spec_from_file_location("backup_phase_native_process", PROCESS_HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_phase(process, command, success, *, deadline=None):
    timeout = 90 if deadline is None else min(90, deadline - time.monotonic())
    if timeout <= 0:
        raise RuntimeError("process campaign aggregate deadline expired before phase launch")
    environment = dict(os.environ)
    environment["OPENSSL_CONF"] = "/dev/null"
    environment["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    result = process.capture(command, env=environment, timeout=timeout, fail_on_stderr=success)
    record = {"command": command, "returncode": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr,
              "capture": result.capture_details}
    if (result.returncode != (0 if success else 1)
            or result.stderr != ("" if success else "zero-value pilot phase rejected\n")
            or (not success and result.stdout)):
        raise RuntimeError("unexpected native phase result: " + str(record))
    return result, record


def exercise(demo, verifier, *, deadline=None):
    if sys.platform != "linux":
        raise RuntimeError("native process proof requires contained Linux")
    deadline = time.monotonic() + 600 if deadline is None else deadline
    process = process_helper()
    commands, phases = [], []
    checks = 0

    def phase(executable, action, directory, success=True):
        nonlocal checks
        command = [str(executable), action, str(directory)]
        result, record = run_phase(process, command, success, deadline=deadline)
        commands.append(record)
        checks += 1
        if success:
            observed = json.loads(result.stdout)
            if (
                set(observed) != {"phase", "pid", "zero_value_only"}
                or observed["phase"] != action
                or observed["zero_value_only"] is not True
            ):
                raise RuntimeError("invalid phase observation")
            phases.append(observed)
        return result

    with tempfile.TemporaryDirectory(
        prefix="pqbtc-pilot-owned-"
    ) as owned, tempfile.TemporaryDirectory(prefix="pqbtc-pilot-public-") as public:
        owned, public = Path(owned), Path(public)
        phase(verifier, "challenge", public)
        shutil.copyfile(public / "challenge.bin", owned / "challenge.bin")
        phase(demo, "produce", owned)
        package = (owned / "wallet.bak").read_bytes()
        original_public = (owned / "public.bin").read_bytes()
        if len(package) != 176 or len(original_public) != 1312:
            raise RuntimeError("wrong persisted output lengths")
        phase(demo, "produce", owned, False)
        if (owned / "wallet.bak").read_bytes() != package or (
            owned / "public.bin"
        ).read_bytes() != original_public:
            raise RuntimeError("existing recovery data overwritten")
        phase(demo, "restore-sign", owned)
        for name, size in (
            ("public.bin", 1312),
            ("intent.bin", 112),
            ("signature.bin", 2420),
        ):
            if (owned / name).stat().st_size != size:
                raise RuntimeError("incomplete public phase output")
            shutil.copyfile(owned / name, public / name)
        if set(p.name for p in public.iterdir()) != {
            "challenge.bin",
            "public.bin",
            "intent.bin",
            "signature.bin",
        }:
            raise RuntimeError("verifier directory contains private recovery inputs")
        phase(verifier, "verify", public)
        if len(set(item["pid"] for item in phases)) != 4:
            raise RuntimeError("phase processes are not distinct")
        for name, offset in (
            ("intent.bin", 8),
            ("intent.bin", 40),
            ("intent.bin", 72),
            ("intent.bin", 111),
            ("challenge.bin", 0),
            ("public.bin", 0),
            ("signature.bin", 19),
        ):
            path = public / name
            original = path.read_bytes()
            changed = bytearray(original)
            changed[offset] ^= 1
            path.write_bytes(changed)
            phase(verifier, "verify", public, False)
            path.write_bytes(original)
        for suffix in (b"", b"\0\0"):
            intent = (public / "intent.bin").read_bytes()
            (public / "intent.bin").write_bytes(intent[:-1] + suffix)
            phase(verifier, "verify", public, False)
            (public / "intent.bin").write_bytes(intent)
        corrupted = bytearray(package)
        corrupted[-1] ^= 1
        (owned / "wallet.bak").write_bytes(corrupted)
        phase(demo, "restore-sign", owned, False)
        phase(
            verifier, "produce", public, False
        )  # public-only executable has no producer mode
    return {"result": "PASS", "checks": checks, "phases": phases, "commands": commands}


if __name__ == "__main__":
    print(json.dumps(exercise(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
