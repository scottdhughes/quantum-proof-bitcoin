#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained native integration test. Imports are data-only, calls execute C."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def exercise(demo, verifier):
    if sys.platform != "linux":
        raise RuntimeError("native process proof requires contained Linux")
    commands, phases = [], []
    checks = 0

    def phase(executable, action, directory, success=True):
        nonlocal checks
        command = [str(executable), action, str(directory)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        commands.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        checks += 1
        if result.returncode != (0 if success else 1):
            raise RuntimeError("unexpected native phase result: " + str(commands[-1]))
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
