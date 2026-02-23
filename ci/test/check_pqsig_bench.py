#!/usr/bin/env python3
"""Validate PQSig bench acceptance envelopes."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_VERIFY_COMPRESSIONS = 1292
EXPECTED_SIGN_HASHES = 6027717
EXPECTED_SIGN_COMPRESSIONS = 6869634
EXPECTED_OUTER_SEARCH_ITERS = 244170
EXPECTED_PER_BYTE = EXPECTED_VERIFY_COMPRESSIONS / 4480.0

LINE_RE = re.compile(
    r"PQSIG_BENCH_ENVELOPE\s+"
    r"verify_compressions=(?P<verify>\d+)\s+"
    r"verify_compressions_per_byte=(?P<per_byte>[0-9]+(?:\.[0-9]+)?)\s+"
    r"sign_hashes=(?P<sign_hashes>\d+)\s+"
    r"sign_compressions=(?P<sign_compressions>\d+)\s+"
    r"outer_search_iters=(?P<outer>\d+)"
)


def fail(msg: str, output: str | None = None) -> int:
    print(f"check_pqsig_bench.py: {msg}", file=sys.stderr)
    if output:
        print("--- bench output ---", file=sys.stderr)
        print(output, file=sys.stderr)
        print("--------------------", file=sys.stderr)
    return 1


def run_bench(bench_exe: str) -> tuple[dict[str, float | int], str]:
    cmd = [bench_exe, "-filter=PQSigBenchEnvelope", "-min-time=1"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")

    if proc.returncode != 0:
        raise RuntimeError(f"bench command failed with exit code {proc.returncode}\n{output}")

    match = LINE_RE.search(output)
    if not match:
        raise RuntimeError(f"envelope line not found in bench output\n{output}")

    verify = int(match.group("verify"))
    per_byte = float(match.group("per_byte"))
    sign_hashes = int(match.group("sign_hashes"))
    sign_compressions = int(match.group("sign_compressions"))
    outer = int(match.group("outer"))
    envelope = {
        "verify_compressions": verify,
        "verify_compressions_per_byte": per_byte,
        "sign_hashes": sign_hashes,
        "sign_compressions": sign_compressions,
        "outer_search_iters": outer,
    }
    return envelope, output


def validate_envelope(envelope: dict[str, float | int], output: str) -> int:
    verify = int(envelope["verify_compressions"])
    per_byte = float(envelope["verify_compressions_per_byte"])
    sign_hashes = int(envelope["sign_hashes"])
    sign_compressions = int(envelope["sign_compressions"])
    outer = int(envelope["outer_search_iters"])
    if verify != EXPECTED_VERIFY_COMPRESSIONS:
        return fail(f"verify_compressions mismatch: expected {EXPECTED_VERIFY_COMPRESSIONS}, got {verify}", output)
    if sign_hashes != EXPECTED_SIGN_HASHES:
        return fail(f"sign_hashes mismatch: expected {EXPECTED_SIGN_HASHES}, got {sign_hashes}", output)
    if sign_compressions != EXPECTED_SIGN_COMPRESSIONS:
        return fail(f"sign_compressions mismatch: expected {EXPECTED_SIGN_COMPRESSIONS}, got {sign_compressions}", output)
    if outer != EXPECTED_OUTER_SEARCH_ITERS:
        return fail(f"outer_search_iters mismatch: expected {EXPECTED_OUTER_SEARCH_ITERS}, got {outer}", output)
    if not math.isclose(per_byte, EXPECTED_PER_BYTE, rel_tol=0.0, abs_tol=1e-6):
        return fail(f"verify_compressions_per_byte mismatch: expected {EXPECTED_PER_BYTE}, got {per_byte}", output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check PQSig bench envelopes")
    parser.add_argument("--bench", required=True, help="Path to bench_pqbtc executable")
    parser.add_argument("--repeat", type=int, default=1, help="Number of repeated bench envelope checks")
    parser.add_argument("--baseline-out", help="Optional output path for JSON baseline summary")
    args = parser.parse_args()

    if args.repeat < 1:
        return fail(f"--repeat must be >= 1 (got {args.repeat})")

    envelopes: list[dict[str, float | int]] = []
    for _ in range(args.repeat):
        try:
            envelope, output = run_bench(args.bench)
        except RuntimeError as exc:
            return fail(str(exc))
        result = validate_envelope(envelope, output)
        if result != 0:
            return result
        envelopes.append(envelope)

    if args.baseline_out:
        baseline_path = Path(args.baseline_out)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline = {
            "bench": args.bench,
            "repeat": args.repeat,
            "expected": {
                "verify_compressions": EXPECTED_VERIFY_COMPRESSIONS,
                "verify_compressions_per_byte": EXPECTED_PER_BYTE,
                "sign_hashes": EXPECTED_SIGN_HASHES,
                "sign_compressions": EXPECTED_SIGN_COMPRESSIONS,
                "outer_search_iters": EXPECTED_OUTER_SEARCH_ITERS,
            },
            "runs": envelopes,
        }
        baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"PQSIG bench envelope check passed ({args.repeat} run(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
