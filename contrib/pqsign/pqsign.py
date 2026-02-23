#!/usr/bin/env python3
"""Deterministic PQBTC v1 signer (test/tooling only)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REF_DIR = REPO_ROOT / "contrib" / "pqsig-ref"
if str(REF_DIR) not in sys.path:
    sys.path.insert(0, str(REF_DIR))

from pqsig_ref import MSG32_SIZE, PK_SCRIPT_SIZE, SIG_SIZE, pqsig_sign  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="PQBTC v1 deterministic test signer")
    parser.add_argument("--msg32", required=True, help="32-byte message digest in hex")
    parser.add_argument("--pk-script33", required=True, help="33-byte script pubkey in hex")
    parser.add_argument("--sk-seed", required=True, help="secret seed in hex")
    parser.add_argument("--max-counter", type=int, default=1048576, help="maximum grinding attempts")
    parser.add_argument("--out", help="optional output file path (hex)")
    args = parser.parse_args()

    msg32 = bytes.fromhex(args.msg32)
    pk_script33 = bytes.fromhex(args.pk_script33)
    sk_seed = bytes.fromhex(args.sk_seed)

    if len(msg32) != MSG32_SIZE:
        raise ValueError("msg32 must be exactly 32 bytes")
    if len(pk_script33) != PK_SCRIPT_SIZE:
        raise ValueError("pk-script33 must be exactly 33 bytes")

    sig = pqsig_sign(msg32, sk_seed, pk_script33, args.max_counter)
    if len(sig) != SIG_SIZE:
        raise RuntimeError("internal error: generated signature is not 4480 bytes")

    sig_hex = sig.hex()
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(sig_hex + "\n", encoding="utf-8")
    else:
        print(sig_hex)


if __name__ == "__main__":
    main()
