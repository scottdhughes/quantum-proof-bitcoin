#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Public byte model of CONTRACT-1, NOT an active node/signing implementation."""

import hashlib
import re
import struct


MAX_BYTES = 1048576
MAX_ITEMS = 100
MAX_MONEY = 2100000000000000
CONTEXT = b"PQBTC/MLDSA44/tx/v1"
NETWORKS = {
    "main": ("pq", "8592a7ad", "2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4"),
    "test": ("tq", "a7e29cf7", "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979"),
    "regtest": ("rq", "96bd87e9", "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"),
}
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class ProtocolError(ValueError):
    """Malformed or over-bound public model input."""


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError("integer type/range")
    return value


def octets(value, size=None):
    if type(value) is not bytes or (size is not None and len(value) != size):
        raise ProtocolError("byte type/length")
    return value


def unhex(value, size=None):
    if type(value) is not str or len(value) > 20000 or len(value) % 2 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise ProtocolError("noncanonical hex")
    return octets(bytes.fromhex(value), size)


def binding(network):
    if type(network) is not str or network not in NETWORKS:
        raise ProtocolError("network")
    _, magic, genesis = NETWORKS[network]
    return bytes.fromhex(magic) + bytes.fromhex(genesis)[::-1]


def compact(value):
    integer(value, 0, 2**64 - 1)
    if value < 253:
        return bytes([value])
    for prefix, size in [(253, 2), (254, 4), (255, 8)]:
        if value < 2**(8 * size):
            return bytes([prefix]) + value.to_bytes(size, "little")
    raise ProtocolError("CompactSize range")


def varbytes(data):
    octets(data)
    return compact(len(data)) + data


class Reader:
    def __init__(self, data):
        octets(data)
        if len(data) > MAX_BYTES:
            raise ProtocolError("byte bound")
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise ProtocolError("truncated bytes")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def number(self, size, signed=False):
        return int.from_bytes(self.take(size), "little", signed=signed)

    def count(self, maximum):
        first = self.number(1)
        if first < 253:
            value = first
        else:
            size, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 2**32)}[first]
            value = self.number(size)
            if value < minimum:
                raise ProtocolError("nonminimal CompactSize")
        if value > maximum:
            raise ProtocolError("count bound")
        return value

    def blob(self, maximum):
        return self.take(self.count(maximum))

    def end(self):
        if self.offset != len(self.data):
            raise ProtocolError("trailing bytes")


def _members(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ProtocolError("object members")


def validate_tx(tx):
    _members(tx, ("version", "inputs", "outputs", "lock_time"))
    integer(tx["version"], -(2**31), 2**31 - 1)
    integer(tx["lock_time"], 0, 2**32 - 1)
    for name in ["inputs", "outputs"]:
        if type(tx[name]) is not list or not 1 <= len(tx[name]) <= MAX_ITEMS:
            raise ProtocolError("item count")
    seen, incoming, outgoing = set(), 0, 0
    for entry in tx["inputs"]:
        _members(entry, ("prev_txid", "prev_index", "sequence", "amount", "script_pubkey"))
        unhex(entry["prev_txid"], 32)
        integer(entry["prev_index"], 0, 2**32 - 1)
        integer(entry["sequence"], 0, 2**32 - 1)
        unhex(entry["script_pubkey"])
        incoming += integer(entry["amount"], 0, MAX_MONEY)
        point = (entry["prev_txid"], entry["prev_index"])
        if point in seen or point == ("00" * 32, 2**32 - 1):
            raise ProtocolError("duplicate/coinbase input")
        seen.add(point)
    for entry in tx["outputs"]:
        _members(entry, ("amount", "script_pubkey"))
        unhex(entry["script_pubkey"])
        outgoing += integer(entry["amount"], 0, MAX_MONEY)
    if incoming > MAX_MONEY or outgoing > MAX_MONEY or outgoing > incoming:
        raise ProtocolError("aggregate money")


def _outpoint(entry):
    return bytes.fromhex(entry["prev_txid"])[::-1] + struct.pack("<I", entry["prev_index"])


def _output(entry):
    return struct.pack("<Q", entry["amount"]) + varbytes(bytes.fromhex(entry["script_pubkey"]))


def encode_unsigned(tx):
    validate_tx(tx)
    data = (struct.pack("<i", tx["version"]) + compact(len(tx["inputs"])) +
            b"".join(_outpoint(i) + b"\x00" + struct.pack("<I", i["sequence"]) for i in tx["inputs"]) +
            compact(len(tx["outputs"])) + b"".join(_output(o) for o in tx["outputs"]) +
            struct.pack("<I", tx["lock_time"]))
    if len(data) > MAX_BYTES:
        raise ProtocolError("unsigned byte bound")
    return data


def decode_unsigned(data, prevouts):
    reader = Reader(data)
    version = reader.number(4, signed=True)
    count = reader.count(MAX_ITEMS)
    if type(prevouts) is not list or len(prevouts) != count:
        raise ProtocolError("prevout count")
    inputs = []
    for amount_script in prevouts:
        if type(amount_script) not in (tuple, list) or len(amount_script) != 2:
            raise ProtocolError("prevout metadata")
        txid, index = reader.take(32)[::-1].hex(), reader.number(4)
        if reader.blob(10000):
            raise ProtocolError("nonempty scriptSig")
        inputs.append({"prev_txid": txid, "prev_index": index, "sequence": reader.number(4),
                       "amount": amount_script[0], "script_pubkey": amount_script[1]})
    outputs = [{"amount": reader.number(8), "script_pubkey": reader.blob(10000).hex()}
               for _ in range(reader.count(MAX_ITEMS))]
    tx = {"version": version, "inputs": inputs, "outputs": outputs, "lock_time": reader.number(4)}
    reader.end()
    validate_tx(tx)
    return tx


def encode_signed(tx, witnesses):
    unsigned = encode_unsigned(tx)
    if type(witnesses) is not list or len(witnesses) != len(tx["inputs"]):
        raise ProtocolError("witness count")
    stacks = []
    for pair in witnesses:
        if type(pair) not in (tuple, list) or len(pair) != 2:
            raise ProtocolError("witness shape")
        stacks.append(b"\x02" + varbytes(octets(pair[0], 2420)) + varbytes(octets(pair[1], 1312)))
    return unsigned[:4] + b"\x00\x01" + unsigned[4:-4] + b"".join(stacks) + unsigned[-4:]


def _tagged(tag, data):
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash * 2 + data).digest()


def key_commitment(network, public_key):
    return _tagged(b"PQBTC/MLDSA44/key/v1", binding(network) + octets(public_key, 1312))


def script_pubkey(program):
    return b"\x52\x20" + octets(program, 32)


def signing_message(network, tx, index):
    encode_unsigned(tx)
    integer(index, 0, len(tx["inputs"]) - 1)
    ins, outs = tx["inputs"], tx["outputs"]
    parts = [b"".join(_outpoint(i) for i in ins),
             b"".join(struct.pack("<Q", i["amount"]) for i in ins),
             b"".join(varbytes(bytes.fromhex(i["script_pubkey"])) for i in ins),
             b"".join(struct.pack("<I", i["sequence"]) for i in ins),
             b"".join(_output(o) for o in outs)]
    preimage = (binding(network) + struct.pack("<iIBII", tx["version"], tx["lock_time"], 1, len(ins), len(outs)) +
                b"".join(hashlib.sha256(p).digest() for p in parts) + struct.pack("<I", index))
    return _tagged(b"PQBTC/MLDSA44/sighash/v1", preimage)


def _polymod(values):
    result = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for value in values:
        top = result >> 25
        result = (result & 0x1ffffff) << 5 ^ value
        for bit, generator in enumerate(generators):
            if top >> bit & 1:
                result ^= generator
    return result


def _expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32m_decode(address):
    if type(address) is not str or not 8 <= len(address) <= 90 or any(not 33 <= ord(c) <= 126 for c in address):
        raise ProtocolError("Bech32m characters/length")
    if address != address.lower() and address != address.upper():
        raise ProtocolError("mixed case")
    address = address.lower()
    split = address.rfind("1")
    if split < 1 or split + 7 > len(address) or any(c not in CHARSET for c in address[split + 1:]):
        raise ProtocolError("Bech32m separator/data")
    hrp = address[:split]
    data = [CHARSET.index(c) for c in address[split + 1:]]
    if _polymod(_expand(hrp) + data) != 0x2bc830a3:
        raise ProtocolError("Bech32m checksum")
    return hrp, data[:-6]


def _convert(values, source, target, pad):
    accumulator, bits, result = 0, 0, []
    for value in values:
        integer(value, 0, (1 << source) - 1)
        accumulator = ((accumulator << source) | value) & ((1 << (source + target - 1)) - 1)
        bits += source
        while bits >= target:
            bits -= target
            result.append((accumulator >> bits) & ((1 << target) - 1))
    if pad and bits:
        result.append((accumulator << (target - bits)) & ((1 << target) - 1))
    elif not pad and (bits >= source or (accumulator << (target - bits)) & ((1 << target) - 1)):
        raise ProtocolError("address padding")
    return result


def encode_address(network, program):
    binding(network)
    hrp = NETWORKS[network][0]
    data = [2] + _convert(octets(program, 32), 8, 5, True)
    checksum = _polymod(_expand(hrp) + data + [0] * 6) ^ 0x2bc830a3
    return hrp + "1" + "".join(CHARSET[v] for v in data + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


def decode_address(network, address):
    binding(network)
    hrp, data = bech32m_decode(address)
    if hrp != NETWORKS[network][0] or not data or data[0] != 2:
        raise ProtocolError("address network/version")
    return octets(bytes(_convert(data[1:], 5, 8, False)), 32)
