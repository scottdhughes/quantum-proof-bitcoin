#!/usr/bin/env python3
"""Deterministically derive network identity and genesis constants for PQBTC."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


COIN = 100_000_000


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def dsha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def ser_compact_size(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def bits_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        raise ValueError("Invalid compact bits with sign bit set")
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def le_hex(b: bytes) -> str:
    return b[::-1].hex()


@dataclass
class NetworkConstants:
    name: str
    message_start: list[int]
    p2p_port: int
    rpc_port: int
    bech32_hrp: str
    base58_pubkey: int
    base58_script: int
    base58_secret: int
    ext_public_key: list[int]
    ext_secret_key: list[int]
    bits: int
    time: int
    nonce: int
    version: int
    merkle_root: str
    genesis_hash: str


def mine_genesis(seed: str, name: str, p2p_port: int, rpc_port: int, hrp: str) -> NetworkConstants:
    id_digest = sha256(f"{seed}|{name}|identity".encode())
    msg_start = [id_digest[0] | 0x80, id_digest[1] | 0x80, id_digest[2] | 0x80, id_digest[3] | 0x80]

    # Derive non-overlapping base58 prefixes in a deterministic way.
    b58 = sha256(f"{seed}|{name}|base58".encode())
    pubkey_prefix = b58[0]
    script_prefix = b58[1]
    secret_prefix = b58[2]
    ext_public = [b58[3], b58[4], b58[5], b58[6]]
    ext_secret = [b58[7], b58[8], b58[9], b58[10]]

    psz_timestamp = f"The Times 22/Feb/2026 PQBTC {name} genesis".encode()
    pubkey = bytes.fromhex(
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
        "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    )
    pubkey_script = bytes([len(pubkey)]) + pubkey + b"\xac"

    script_sig = (
        bytes.fromhex("04ffff001d0104")
        + bytes([len(psz_timestamp)])
        + psz_timestamp
    )

    tx = bytearray()
    tx += struct.pack("<I", 1)
    tx += b"\x01"  # vin count
    tx += b"\x00" * 32
    tx += struct.pack("<I", 0xFFFFFFFF)
    tx += ser_compact_size(len(script_sig))
    tx += script_sig
    tx += struct.pack("<I", 0xFFFFFFFF)
    tx += b"\x01"  # vout count
    tx += struct.pack("<Q", 50 * COIN)
    tx += ser_compact_size(len(pubkey_script))
    tx += pubkey_script
    tx += struct.pack("<I", 0)

    merkle = dsha256(bytes(tx))

    bits = 0x207FFFFF  # intentionally easy for deterministic mining in this tooling stage
    target = bits_to_target(bits)

    time_seed = sha256(f"{seed}|{name}|time".encode())
    block_time = 1_772_057_600 + int.from_bytes(time_seed[:2], "little")

    nonce_seed = sha256(f"{seed}|{name}|nonce".encode())
    nonce = int.from_bytes(nonce_seed[:4], "little")

    while True:
        header = bytearray()
        header += struct.pack("<I", 1)
        header += b"\x00" * 32
        header += merkle
        header += struct.pack("<I", block_time)
        header += struct.pack("<I", bits)
        header += struct.pack("<I", nonce)
        h = dsha256(bytes(header))
        if int.from_bytes(h, "little") <= target:
            return NetworkConstants(
                name=name,
                message_start=msg_start,
                p2p_port=p2p_port,
                rpc_port=rpc_port,
                bech32_hrp=hrp,
                base58_pubkey=pubkey_prefix,
                base58_script=script_prefix,
                base58_secret=secret_prefix,
                ext_public_key=ext_public,
                ext_secret_key=ext_secret,
                bits=bits,
                time=block_time,
                nonce=nonce,
                version=1,
                merkle_root=le_hex(merkle),
                genesis_hash=le_hex(h),
            )
        nonce = (nonce + 1) & 0xFFFFFFFF


def generate(seed: str) -> dict:
    return {
        "seed": seed,
        "networks": [
            asdict(mine_genesis(seed, "main", 22833, 22832, "pq")),
            asdict(mine_genesis(seed, "test", 23833, 23832, "tq")),
            asdict(mine_genesis(seed, "regtest", 24833, 24832, "rq")),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic PQBTC network/genesis constants")
    parser.add_argument("--seed", required=True, help="Seed phrase")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    out_data = generate(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
