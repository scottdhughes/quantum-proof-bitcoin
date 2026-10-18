"""Synthetic deep FXMSS recovery tests, not full-SHRINCS signing KATs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import check_stateful_fxmss as stateful


def exercise(reference, verify):
    rows = ((1, 1), (8, 255), (9, 511), (63, (1 << 63) - 1),
            (64, (1 << 64) - 1), (65, (1 << 64) - 1), (255, (1 << 64) - 1))
    observations = []
    for depth, index in rows:
        height, width = 255 - depth, (min(depth, 64) + 7) // 8
        seed = hashlib.sha256(b"pqbtc-v1-boundary/" + bytes([depth])).digest()
        secret_seed, public_seed = seed[:16], seed[16:]
        digest = bytes(32)  # Test-only fixture fixes H_msg_sf, not native Merkle SHA.
        leaf_signature = reference.wots_c_sign(
            digest, secret_seed, public_seed, height, index, True, depth)
        stateful.require(leaf_signature is not None, "boundary WOTS signing failed")
        auth = hashlib.shake_256(b"pqbtc-v1-auth/" + bytes([depth])).digest(depth * 16)
        component = leaf_signature + auth
        root = reference.fxmss_pubkey_from_sig(index, height, component, digest, public_seed)
        stateful.require(root is not None, "reference boundary recovery failed")
        key = public_seed + bytes(16) + root
        signature = bytes([height]) + bytes(16) + index.to_bytes(width, "big") + component
        stateful.require(stateful.verify_with_c(verify, key, signature, b"", b""),
                         f"native synthetic FXMSS recovery disagrees at depth {depth}")
        bad_key = key[:-1] + bytes([key[-1] ^ 1])
        stateful.require(not stateful.verify_with_c(verify, bad_key, signature, b"", b""),
                         "synthetic boundary accepted wrong root")
        stateful.require(not stateful.verify_with_c(verify, key, signature + b"\0", b"", b""),
                         "synthetic boundary accepted trailing byte")
        observations.append({"depth": depth, "leaf_index": index, "index_bytes": width,
                             "signature_bytes": len(signature),
                             "public_key_sha256": hashlib.sha256(key).hexdigest(),
                             "signature_sha256": hashlib.sha256(signature).hexdigest()})
    return observations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--libshrincs", type=Path, required=True)
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = stateful.load_manifest(stateful.DEFAULT_MANIFEST)
    stateful.validate_pins(manifest, args.shrincs_bip, args.libshrincs)
    reference = stateful.load_module(args.shrincs_bip / "impl/shrincs.py", "boundary_reference")
    rows = exercise(reference, stateful.load_verifier(args.library))
    result = {"result": "PASS", "profile": "pqbtc-shrincs-v1",
              "scope": "SYNTHETIC_FXMSS_RECOVERY_FIXED_MESSAGE_DIGEST_NOT_FULL_SIGNING_KATS",
              "draft_commit": manifest["upstream"]["draft_specification"]["commit"],
              "libshrincs_commit": manifest["upstream"]["libshrincs_wotsc"]["commit"],
              "valid_component_cases": len(rows), "negative_cases": 2 * len(rows),
              "observations": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "observations"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
