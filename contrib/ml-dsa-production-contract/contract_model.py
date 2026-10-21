#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Draft serialization vectors only: no signing, secret handling or node wire."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


SCHEMA = "PQBTC-MLDSA44-DRAFT-0"
PREFIX = b"PQBTC-MLDSA44-DRAFT0\x00"
CONTEXT = b"PQBTC/tx-signature/draft-0"
PUBLIC_KEY_BYTES = 1312
MAX_MONEY = 2100000000000000
# Model bounds, not consensus or resource-admission thresholds.
MAX_ITEMS = 100
MAX_SCRIPT_BYTES = 10000
MAX_ENVELOPE_BYTES = 2100000
MAX_JSON_CHARS = 4300000
NETWORKS = {
    "main": ("8592a7ad", "2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4"),
    "test": ("a7e29cf7", "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979"),
    "regtest": ("96bd87e9", "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"),
}


class ContractError(ValueError):
    """Malformed or inconsistent input to the draft model."""


def _members(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ContractError("unknown or missing object members")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ContractError("integer type or range")
    return value


def _hex(value, size=None, maximum=None):
    if type(value) is not str or len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise ContractError("hex must be lowercase, even and without whitespace")
    if size is not None and len(value) != size * 2:
        raise ContractError("hex length")
    if maximum is not None and len(value) > maximum * 2:
        raise ContractError("hex exceeds model bound")
    return bytes.fromhex(value)


def _binding(network):
    if type(network) is not str or network not in NETWORKS:
        raise ContractError("unknown network")
    magic, genesis = NETWORKS[network]
    return bytes.fromhex(magic) + bytes.fromhex(genesis)[::-1]


def _entries(value):
    if type(value) is not list or not 1 <= len(value) <= MAX_ITEMS:
        raise ContractError("empty or over-bound item count")
    return value


def _validate(request):
    _members(request, ("schema", "network", "transaction", "input_index", "public_key"))
    if request["schema"] != SCHEMA:
        raise ContractError("unknown draft schema")
    _binding(request["network"])
    _hex(request["public_key"], size=PUBLIC_KEY_BYTES)
    tx = request["transaction"]
    _members(tx, ("version", "inputs", "outputs", "lock_time"))
    _integer(tx["version"], -(2**31), 2**31 - 1)
    _integer(tx["lock_time"], 0, 2**32 - 1)
    inputs, outputs = _entries(tx["inputs"]), _entries(tx["outputs"])
    _integer(request["input_index"], 0, len(inputs) - 1)
    seen = set()
    for entry in inputs:
        _members(entry, ("prev_txid", "prev_index", "sequence", "amount", "script_pubkey"))
        _hex(entry["prev_txid"], size=32)
        _integer(entry["prev_index"], 0, 2**32 - 1)
        _integer(entry["sequence"], 0, 2**32 - 1)
        _integer(entry["amount"], 0, MAX_MONEY)
        _hex(entry["script_pubkey"], maximum=MAX_SCRIPT_BYTES)
        outpoint = (entry["prev_txid"], entry["prev_index"])
        if outpoint == ("00" * 32, 2**32 - 1) or outpoint in seen:
            raise ContractError("coinbase or duplicate outpoint")
        seen.add(outpoint)
    for entry in outputs:
        _members(entry, ("amount", "script_pubkey"))
        _integer(entry["amount"], 0, MAX_MONEY)
        _hex(entry["script_pubkey"], maximum=MAX_SCRIPT_BYTES)
    incoming = sum(entry["amount"] for entry in inputs)
    outgoing = sum(entry["amount"] for entry in outputs)
    if incoming > MAX_MONEY or outgoing > MAX_MONEY or outgoing > incoming:
        raise ContractError("aggregate amount range or unfunded outputs")


def _compact_size(value):
    if value < 253:
        return bytes((value,))
    if value <= 65535:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 4294967295:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def _script(value):
    data = bytes.fromhex(value)
    return _compact_size(len(data)) + data


def encode_request(request):
    """Encode the draft signing envelope, never a network transaction."""
    _validate(request)
    tx = request["transaction"]
    parts = [PREFIX, _binding(request["network"]),
             struct.pack("<iBI", tx["version"], 1, request["input_index"]),
             bytes.fromhex(request["public_key"]), _compact_size(len(tx["inputs"]))]
    for entry in tx["inputs"]:
        parts.extend((bytes.fromhex(entry["prev_txid"])[::-1],
                      struct.pack("<IIQ", entry["prev_index"], entry["sequence"], entry["amount"]),
                      _script(entry["script_pubkey"])))
    parts.append(_compact_size(len(tx["outputs"])))
    for entry in tx["outputs"]:
        parts.extend((struct.pack("<Q", entry["amount"]), _script(entry["script_pubkey"])))
    parts.append(struct.pack("<I", tx["lock_time"]))
    return b"".join(parts)


class _Reader:
    def __init__(self, data):
        if type(data) is not bytes or len(data) > MAX_ENVELOPE_BYTES:
            raise ContractError("binary type or model bound")
        self.data = data
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise ContractError("truncated envelope")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def number(self, size, signed=False):
        return int.from_bytes(self.take(size), "little", signed=signed)

    def count(self, maximum):
        first = self.number(1)
        if first < 253:
            value = first
        else:
            size, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 4294967296)}[first]
            value = self.number(size)
            if value < minimum:
                raise ContractError("nonminimal CompactSize")
        if value > maximum:
            raise ContractError("length exceeds model bound")
        return value

    def script(self):
        return self.take(self.count(MAX_SCRIPT_BYTES)).hex()


def decode_request(data):
    """Strictly decode the draft envelope, including cross-field checks."""
    reader = _Reader(data)
    if reader.take(len(PREFIX)) != PREFIX:
        raise ContractError("unknown envelope prefix")
    binding = reader.take(36)
    network = next((name for name in NETWORKS if _binding(name) == binding), None)
    if network is None:
        raise ContractError("unknown network/genesis binding")
    version = reader.number(4, signed=True)
    if reader.number(1) != 1:
        raise ContractError("unsupported sighash selector")
    index = reader.number(4)
    public_key = reader.take(PUBLIC_KEY_BYTES).hex()
    inputs = []
    for _ in range(reader.count(MAX_ITEMS)):
        inputs.append({"prev_txid": reader.take(32)[::-1].hex(),
                       "prev_index": reader.number(4), "sequence": reader.number(4),
                       "amount": reader.number(8), "script_pubkey": reader.script()})
    outputs = []
    for _ in range(reader.count(MAX_ITEMS)):
        outputs.append({"amount": reader.number(8), "script_pubkey": reader.script()})
    request = {"schema": SCHEMA, "network": network,
               "transaction": {"version": version, "inputs": inputs, "outputs": outputs,
                               "lock_time": reader.number(4)},
               "input_index": index, "public_key": public_key}
    if reader.offset != len(data):
        raise ContractError("trailing envelope bytes")
    _validate(request)
    return request


def _tagged_hash(tag, data):
    digest = hashlib.sha256(tag).digest()
    return hashlib.sha256(digest + digest + data).digest()


def signing_message(request):
    return _tagged_hash(b"PQBTC/MLDSA44/draft-0/sighash-all", encode_request(request))


def signer_input(request):
    """Return (message, context) for the future pure external signing boundary."""
    return signing_message(request), CONTEXT


def key_commitment(network, public_key):
    if type(public_key) is not bytes or len(public_key) != PUBLIC_KEY_BYTES:
        raise ContractError("public key must be exactly1312 bytes")
    return _tagged_hash(b"PQBTC/MLDSA44/draft-0/key", _binding(network) + public_key)


def _object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ContractError("duplicate JSON member")
        value[key] = entry
    return value


def _constant(_):
    raise ContractError("nonfinite JSON number")


def _json(text):
    if type(text) is not str or len(text) > MAX_JSON_CHARS:
        raise ContractError("JSON type or model bound")
    try:
        return json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ContractError("invalid JSON") from error


def read_request(text):
    request = _json(text)
    _validate(request)
    return request


def verify_vectors(path):
    vector = _json(Path(path).read_text(encoding="utf8"))
    _members(vector, ("schema", "request", "envelope_hex", "signing_message_hex", "context_hex",
                      "key_commitment_hex", "reject_overrides", "reject_binary_hex"))
    if vector["schema"] != "PQBTC-MLDSA44-DRAFT-VECTORS-0":
        raise ContractError("unknown vector schema")
    request = vector["request"]
    raw = _hex(vector["envelope_hex"], maximum=MAX_ENVELOPE_BYTES)
    if encode_request(request) != raw or decode_request(raw) != request:
        raise ContractError("literal envelope mismatch")
    message, context = signer_input(request)
    if message != _hex(vector["signing_message_hex"], size=32):
        raise ContractError("literal signing message mismatch")
    if context != _hex(vector["context_hex"], size=len(CONTEXT)):
        raise ContractError("literal context mismatch")
    if key_commitment(request["network"], _hex(request["public_key"], size=PUBLIC_KEY_BYTES)) != _hex(vector["key_commitment_hex"], size=32):
        raise ContractError("literal key commitment mismatch")
    if type(vector["reject_overrides"]) is not list or type(vector["reject_binary_hex"]) is not list:
        raise ContractError("reject corpus must be arrays")
    rejected = 0
    for override in vector["reject_overrides"]:
        if type(override) is not dict or not override:
            raise ContractError("invalid request override")
        bad = copy.deepcopy(request)
        bad.update(override)
        try:
            encode_request(bad)
        except ContractError:
            rejected += 1
        else:
            raise ContractError("negative request unexpectedly accepted")
    for encoded in vector["reject_binary_hex"]:
        bad = _hex(encoded, maximum=MAX_ENVELOPE_BYTES)
        try:
            decode_request(bad)
        except ContractError:
            rejected += 1
        else:
            raise ContractError("negative envelope unexpectedly accepted")
    return {"scope": "DRAFT_SERIALIZATION_ONLY", "result": "PASS",
            "positive_vectors": 1, "rejected_vectors": rejected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify_vectors(args.vectors)
    except (ContractError, OSError, UnicodeError) as error:
        print(f"draft contract vectors: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
