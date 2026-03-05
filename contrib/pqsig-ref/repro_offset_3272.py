#!/usr/bin/env python3
"""Reproduce the accepted layer-2 WOTS mutation at offset 3272."""

from __future__ import annotations

import json
from pathlib import Path

from pqsig_ref import HT_AUTH_SIZE, HT_LAYER_SIZE, HT_OFFSET, pqsig_verify


OFFSET = 3272
TARGET_NAME = "kat_01"


def load_kat() -> dict[str, str]:
    kat_path = Path(__file__).resolve().parents[2] / "src/test/data/pqsig/kat_v1.json"
    root = json.loads(kat_path.read_text())
    vectors = root if isinstance(root, list) else root["vectors"]
    for entry in vectors:
        if entry["name"] == TARGET_NAME:
            return entry
    raise KeyError(f"missing KAT vector {TARGET_NAME}")


def main() -> None:
    layer = (OFFSET - HT_OFFSET) // HT_LAYER_SIZE
    layer_offset = (OFFSET - HT_OFFSET) % HT_LAYER_SIZE
    kat = load_kat()

    msg = bytes.fromhex(kat["msg32"])
    pk = bytes.fromhex(kat["pk_script33"])
    sig = bytearray.fromhex(kat["sig4480"])
    mutated = bytearray(sig)
    mutated[OFFSET] ^= 0x01

    print(f"kat={TARGET_NAME}")
    print(f"offset={OFFSET}")
    print(f"formula=HT_OFFSET + 2 * HT_LAYER_SIZE + HT_AUTH_SIZE")
    print(f"ht_offset={HT_OFFSET}")
    print(f"ht_layer_size={HT_LAYER_SIZE}")
    print(f"ht_auth_size={HT_AUTH_SIZE}")
    print(f"layer={layer}")
    print(f"layer_offset={layer_offset}")
    print(f"region=layer-2-wots-first-byte")
    print(f"original_verify={pqsig_verify(bytes(sig), msg, pk)}")
    print(f"mutated_verify={pqsig_verify(bytes(mutated), msg, pk)}")
    print("root_cause=final acceptance remains gated by final_digest[0] == pk_root[0]")


if __name__ == "__main__":
    main()
