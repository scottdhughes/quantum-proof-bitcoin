#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Native public CLI boundary tests; run inside the contained Linux demo."""
if not __debug__:
    raise RuntimeError("optimized Python is not permitted for demo evidence")
import argparse
import json
import os
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    assert os.uname().sysname == "Linux" and os.geteuid() != 0
    spec = "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126"
    base = [args.binary, "--valueless-demo", "/tmp/absent-demo-signer/socket", "1000", spec, "5"]
    cases = [(base, b"z\n", 9), (base, b"0\n", 9), (base, b"00\r\n", 9),
             (base, b"00\n\n", 9), (base[:-1] + ["6"], b"", 9),
             (base[:3] + ["0"] + base[4:], b"", 4),
             (base[:3] + ["1000junk"] + base[4:], b"", 9),
             (base[:4] + ["AA" * 32] + base[5:], b"", 9),
             (base, b"00" * (1048576 + 1), 9), (base, b"", 4),
             (base + ["--network", "test"], b"", 4),
             (base + ["--network", "regtest"], b"", 4),
             (base + ["--network", "main"], b"", 7),
             (base + ["--network", "unknown"], b"", 7),
             (base + ["--network", "test", "--network", "regtest"], b"", 9),
             (base[:4] + ["00" * 32] + base[5:] + ["--network", "test"], b"", 3),
             (base[:4] + ["00" * 32] + base[5:], b"", 4)]
    for command, body, code in cases:
        result = subprocess.run(command, input=body, capture_output=True, timeout=10)
        assert result.returncode == 1 and result.stdout == b"", (command, result.returncode)
        assert result.stderr == f"MLDSA_CLIENT_ERROR {code}\n".encode("ascii"), result.stderr
    print(json.dumps({"result": "PASS", "public_cli_adverse_cases": len(cases)}))


if __name__ == "__main__":
    main()
