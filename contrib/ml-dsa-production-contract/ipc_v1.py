#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded public IPC byte model; no socket, authentication or signer service."""

import struct

from protocol_v1 import (MAX_BYTES, MAX_ITEMS, ProtocolError, Reader, binding,
                         compact, decode_unsigned, encode_unsigned, integer,
                         octets, varbytes)


def encode_frame(kind, request_id, body):
    integer(kind, 0, 255)
    if kind not in (1, 2, 3, 4, 5, 129, 130, 131, 132, 133):
        raise ProtocolError("IPC kind")
    octets(request_id, 16)
    if not any(request_id):
        raise ProtocolError("zero request id")
    octets(body)
    if len(body) > MAX_BYTES:
        raise ProtocolError("IPC body bound")
    return b"PQMSIPC1" + struct.pack("<HBB", 1, kind, 0) + request_id + struct.pack("<I", len(body)) + body


def decode_frame(frame):
    octets(frame)
    if not 32 <= len(frame) <= MAX_BYTES + 32 or frame[:10] != b"PQMSIPC1\x01\x00" or frame[11] != 0:
        raise ProtocolError("IPC header")
    kind, identity, body = frame[10], frame[12:28], frame[32:]
    if int.from_bytes(frame[28:32], "little") != len(body):
        raise ProtocolError("IPC length")
    encode_frame(kind, identity, body)
    return kind, identity, body


def hello(network, spec_hash):
    return binding(network) + octets(spec_hash, 32)


def encode_sign_request(identity, tx, paths):
    wire = encode_unsigned(tx)
    if type(paths) is not list or len(paths) != len(tx["inputs"]):
        raise ProtocolError("path count")
    parts = [octets(identity, 16), varbytes(wire), compact(len(paths))]
    for entry, path in zip(tx["inputs"], paths):
        if type(path) not in (tuple, list) or len(path) != 2:
            raise ProtocolError("path shape")
        branch, index = integer(path[0], 0, 1), integer(path[1], 0, 2**31 - 1)
        parts.append(struct.pack("<Q", entry["amount"]) + varbytes(bytes.fromhex(entry["script_pubkey"])) + struct.pack("<BI", branch, index))
    body = b"".join(parts)
    if len(body) > MAX_BYTES:
        raise ProtocolError("sign request bound")
    return body


def decode_sign_request(body):
    reader = Reader(body)
    identity, wire = reader.take(16), reader.blob(MAX_BYTES)
    prevouts, paths = [], []
    for _ in range(reader.count(MAX_ITEMS)):
        prevouts.append((reader.number(8), reader.blob(10000).hex()))
        paths.append((reader.number(1), reader.number(4)))
    reader.end()
    tx = decode_unsigned(wire, prevouts)
    encode_sign_request(identity, tx, paths)
    return identity, tx, paths


def response_body(status, payload):
    integer(status, 0, 13)
    octets(payload)
    if (status != 0 and payload) or len(payload) > MAX_BYTES - 2:
        raise ProtocolError("response payload")
    return struct.pack("<H", status) + payload
