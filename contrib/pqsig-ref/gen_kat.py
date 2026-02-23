#!/usr/bin/env python3
"""Generate frozen PQSig v1 KAT vectors."""

from __future__ import annotations

import json
from pathlib import Path

from pqsig_ref import derive_pk_script, pqsig_sign


def make_vector(name: str, sk_seed_hex: str, msg_hex: str) -> dict[str, str]:
    sk_seed = bytes.fromhex(sk_seed_hex)
    msg = bytes.fromhex(msg_hex)
    pk_script = derive_pk_script(sk_seed)
    sig = pqsig_sign(msg, sk_seed, pk_script)
    return {
        "name": name,
        "sk_seed": sk_seed.hex(),
        "msg32": msg.hex(),
        "pk_script33": pk_script.hex(),
        "sig4480": sig.hex(),
    }


def main() -> None:
    vectors = [
        make_vector("kat_01", "1f" * 32, "42" * 32),
        make_vector("kat_02", "2a" * 32, "11" * 32),
        make_vector("kat_03", "3b" * 32, "00" * 31 + "7f"),
    ]
    out = {
        "profile": "pqsig-v1-2^40-4480",
        "vectors": vectors,
    }

    root = Path(__file__).resolve().parents[2]
    dest = root / "src" / "test" / "data" / "pqsig" / "kat_v1.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
