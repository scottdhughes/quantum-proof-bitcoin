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

DEFAULT_POLICY_PATH = Path(__file__).with_name("pqsig_bench_policy.json")

LINE_RE = re.compile(
    r"PQSIG_BENCH_ENVELOPE\s+"
    r"verify_compressions=(?P<verify>\d+)\s+"
    r"verify_compressions_per_byte=(?P<per_byte>[0-9]+(?:\.[0-9]+)?)\s+"
    r"sign_hashes=(?P<sign_hashes>\d+)\s+"
    r"sign_compressions=(?P<sign_compressions>\d+)\s+"
    r"outer_search_iters=(?P<outer>\d+)"
)
NS_PER_OP_RE = re.compile(
    r"\|\s*(?P<ns>[0-9][0-9,]*(?:\.[0-9]+)?)\s*\|"
    r"[^\n]*\|\s*`PQSigBenchEnvelope`"
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
    ns_match = NS_PER_OP_RE.search(output)
    if ns_match:
        envelope["ns_per_op"] = float(ns_match.group("ns").replace(",", ""))
    return envelope, output


def load_policy(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "exact_counters" not in data:
        raise RuntimeError(f"policy file missing exact_counters: {path}")
    if "variance_bands" not in data:
        data["variance_bands"] = {}
    return data


def validate_envelope(envelope: dict[str, float | int], policy: dict[str, object], output: str) -> int:
    exact_counters = policy["exact_counters"]
    assert isinstance(exact_counters, dict)
    variance_bands = policy.get("variance_bands", {})
    assert isinstance(variance_bands, dict)

    for key, expected in exact_counters.items():
        if key not in envelope:
            return fail(f"bench output missing required metric {key}", output)
        actual = envelope[key]
        if isinstance(expected, float):
            if not math.isclose(float(actual), expected, rel_tol=0.0, abs_tol=1e-6):
                return fail(f"{key} mismatch: expected {expected}, got {actual}", output)
        else:
            if int(actual) != int(expected):
                return fail(f"{key} mismatch: expected {expected}, got {actual}", output)

    for key, bounds in variance_bands.items():
        if key not in envelope:
            return fail(f"bench output missing variance metric {key}", output)
        if not isinstance(bounds, dict):
            return fail(f"variance band for {key} must be an object", output)
        lower = bounds.get("min")
        upper = bounds.get("max")
        actual = float(envelope[key])
        if lower is not None and actual < float(lower):
            return fail(f"{key} below minimum: min {lower}, got {actual}", output)
        if upper is not None and actual > float(upper):
            return fail(f"{key} above maximum: max {upper}, got {actual}", output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check PQSig bench envelopes")
    parser.add_argument("--bench", required=True, help="Path to bench_pqbtc executable")
    parser.add_argument("--repeat", type=int, default=1, help="Number of repeated bench envelope checks")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY_PATH), help="Path to checked-in bench policy JSON")
    parser.add_argument("--baseline-out", help="Optional output path for JSON baseline summary")
    args = parser.parse_args()

    if args.repeat < 1:
        return fail(f"--repeat must be >= 1 (got {args.repeat})")

    try:
        policy = load_policy(Path(args.policy))
    except RuntimeError as exc:
        return fail(str(exc))

    envelopes: list[dict[str, float | int]] = []
    for _ in range(args.repeat):
        try:
            envelope, output = run_bench(args.bench)
        except RuntimeError as exc:
            return fail(str(exc))
        result = validate_envelope(envelope, policy, output)
        if result != 0:
            return result
        envelopes.append(envelope)

    if args.baseline_out:
        baseline_path = Path(args.baseline_out)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline = {
            "bench": args.bench,
            "policy": args.policy,
            "repeat": args.repeat,
            "expected": policy,
            "runs": envelopes,
        }
        baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"PQSIG bench envelope check passed ({args.repeat} run(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
