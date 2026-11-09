#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""PUBLIC fixture derivation/record framing only. Never use for real custody."""

import hashlib
import hmac
import struct

from protocol_v1 import ProtocolError, binding, integer, octets


def hkdf_sha256(ikm, salt, info, length):
    integer(length, 1, 255 * 32)
    prk = hmac.new(octets(salt), octets(ikm), hashlib.sha256).digest()
    result, previous = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + octets(info) + bytes([counter]), hashlib.sha256).digest()
        result += previous
    return result[:length]


def derive_seed(root, network, branch, index):
    octets(root, 32)
    integer(branch, 0, 1)
    integer(index, 0, 2**31 - 1)
    return hkdf_sha256(root, b"PQBTC/MLDSA44/wallet-root/v1" + binding(network),
                       b"PQBTC/MLDSA44/keygen-seed/v1" + struct.pack(">II", branch | 0x80000000, index | 0x80000000), 32)


def wallet_id(root, network):
    return hmac.new(octets(root, 32), b"PQBTC/MLDSA44/wallet-id/v1" + binding(network), hashlib.sha256).digest()[:16]


def reserve_index(next_index):
    """Arithmetic only: caller MUST commit the new counter before publication."""
    integer(next_index, 0, 2**31 - 1)
    return next_index, next_index + 1


def record_header(network, identity, generation, salt, nonce):
    integer(generation, 1, 2**64 - 1)
    return (b"PQWMLD1\x00\x01\x00" + binding(network) + octets(identity, 16) +
            struct.pack("<QBIII", generation, 1, 131072, 8, 1) + octets(salt, 16) + octets(nonce, 12))


def parse_record(record, network):
    """Return untrusted framing, NOT decrypted data or an authentication result."""
    octets(record, 167)
    if record[:10] != b"PQWMLD1\x00\x01\x00" or record[10:46] != binding(network):
        raise ProtocolError("wallet format/network")
    generation, kdf, n, r, p = struct.unpack("<QBIII", record[62:83])
    if generation == 0 or (kdf, n, r, p) != (1, 131072, 8, 1):
        raise ProtocolError("wallet generation/KDF")
    return {"authenticated": False, "aad": record[:111], "wallet_id": record[46:62],
            "generation": generation, "salt": record[83:99], "nonce": record[99:111],
            "ciphertext": record[111:151], "tag": record[151:]}
