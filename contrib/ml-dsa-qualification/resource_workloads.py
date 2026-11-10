#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Isolated, PUBLIC-KEY-FIXTURE-only native resource workload construction.

This deliberately uses the existing test wrapper's known synthetic seed. It is
not a wallet or service-signing API. Large fixtures exceed the local service's
100-output bound without changing that bound or the shipped signer. Only the
frozen valueless TEST binding is supported; never fund this public fixture key.
"""

import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/functional"))
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase  # noqa: E402
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_compact_size  # noqa: E402
from test_framework.script import CScript, OP_RETURN  # noqa: E402

SCOPE = "PUBLIC_SYNTHETIC_KEY_RESOURCE_FIXTURE_ONLY"
TEST_BINDING = bytes.fromhex("a7e29cf7") + bytes.fromhex(
    "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979")[::-1]
CONTEXT = b"PQBTC/MLDSA44/tx/v1"
MAX_BLOCK_WEIGHT = 4_000_000


def tagged_hash(tag, value):
    digest = hashlib.sha256(tag).digest()
    return hashlib.sha256(digest * 2 + value).digest()


def varbytes(value):
    return ser_compact_size(len(value)) + value


def compile_fixture_library(compiler, directory):
    """Build only current-source test-wrapper code, in a caller-owned directory."""
    output = Path(directory) / "libmldsa44-resource-fixture.so"
    if output.exists():
        raise ValueError("fixture-library output must be new")
    subprocess.run([str(compiler), "-std=c11", "-O2", "-fPIC", "-shared", "-pthread",
                    "-DPQBTC_MLDSA44_TESTING=1", "-Wno-unused-function",
                    "-I", str(ROOT / "contrib/ml-dsa-engineering"),
                    str(ROOT / "contrib/ml-dsa-engineering/pqbtc_mldsa44.c"),
                    "-o", str(output)], check=True, timeout=120)
    return output


class FixtureSigner:
    def __init__(self, library, *, scope):
        if scope != SCOPE or sys.platform != "linux":
            raise ValueError("explicit isolated Linux public-fixture scope required")
        self.library = ctypes.CDLL(str(Path(library).resolve()))
        pointer = ctypes.POINTER(ctypes.c_ubyte)
        self.library.pqbtc_mldsa44_test_keypair_from_seed.argtypes = [pointer] * 3
        self.library.pqbtc_mldsa44_test_keypair_from_seed.restype = ctypes.c_int
        self.library.pqbtc_mldsa44_test_sign_fixed_randomizer.argtypes = [
            pointer, pointer, pointer, ctypes.c_size_t, pointer, ctypes.c_size_t, pointer]
        self.library.pqbtc_mldsa44_test_sign_fixed_randomizer.restype = ctypes.c_int
        self.public = (ctypes.c_ubyte * 1312)()
        self.secret = (ctypes.c_ubyte * 2560)()
        # PUBLIC fixture seed, unrelated to all operator/public-wallet custody.
        seed = self.array(hashlib.sha256(b"PQBTC public resource fixture 20261110").digest())
        code = self.library.pqbtc_mldsa44_test_keypair_from_seed(self.public, self.secret, seed)
        if code != 0:
            raise RuntimeError(f"fixture keygen failed: {code}")
        self.script = b"\x52\x20" + tagged_hash(b"PQBTC/MLDSA44/key/v1", TEST_BINDING + bytes(self.public))

    @staticmethod
    def array(value):
        return (ctypes.c_ubyte * len(value)).from_buffer_copy(value)

    def sign(self, transaction, coins):
        """Sign only inputs to this known fixture key, from caller-supplied Coins."""
        if not 1 <= len(coins) == len(transaction.vin) <= 129 or not 1 <= len(transaction.vout) <= 30_000:
            raise ValueError("fixture bounds")
        if any(coin["script"] != self.script for coin in coins):
            raise ValueError("fixture signer refuses another key's Coin")
        for txin, coin in zip(transaction.vin, coins):
            if (txin.prevout.hash, txin.prevout.n) != (int(coin["txid"], 16), coin["vout"]) or txin.scriptSig:
                raise ValueError("fixture outpoint metadata mismatch")
        inputs = transaction.vin
        parts = [b"".join(item.prevout.serialize() for item in inputs),
                 b"".join(struct.pack("<Q", item["amount"]) for item in coins),
                 b"".join(varbytes(item["script"]) for item in coins),
                 b"".join(struct.pack("<I", item.nSequence) for item in inputs),
                 b"".join(item.serialize() for item in transaction.vout)]
        preimage = (TEST_BINDING + struct.pack("<iIBII", transaction.version, transaction.nLockTime,
                                             1, len(inputs), len(transaction.vout)) +
                    b"".join(hashlib.sha256(part).digest() for part in parts))
        transaction.wit.vtxinwit = []
        for index in range(len(inputs)):
            message = tagged_hash(b"PQBTC/MLDSA44/sighash/v1", preimage + struct.pack("<I", index))
            signature = (ctypes.c_ubyte * 2420)()
            code = self.library.pqbtc_mldsa44_test_sign_fixed_randomizer(
                signature, self.secret, self.array(message), len(message),
                self.array(CONTEXT), len(CONTEXT), self.array(bytes(32)))
            if code != 0:
                raise RuntimeError(f"fixture signature failed: {code}")
            witness = CTxInWitness()
            witness.scriptWitness.stack = [bytes(signature), bytes(self.public)]
            transaction.wit.vtxinwit.append(witness)
        return transaction

    def spend(self, coins, *, fee=20_000, output_count=1, output_value=None, lock_time=0):
        tx = CTransaction()
        tx.version, tx.nLockTime = 2, lock_time
        tx.vin = [CTxIn(COutPoint(int(item["txid"], 16), item["vout"])) for item in coins]
        incoming = sum(item["amount"] for item in coins)
        value = (incoming - fee) // output_count if output_value is None else output_value
        if value <= 0 or value * output_count + fee > incoming:
            raise ValueError("fixture transaction funding")
        tx.vout = [CTxOut(value, self.script) for _ in range(output_count)]
        return self.sign(tx, coins)


def coin(txid, vout, amount, script):
    return {"txid": txid, "vout": vout, "amount": amount, "script": script}


def block_for(rpc, signer, transactions, *, full_weight=False):
    """Construct a valid native coinbase; full-weight padding is fixture-only."""
    height = rpc.getblockcount() + 1
    previous = rpc.getblockheader(rpc.getbestblockhash())
    coinbase = create_coinbase(height, script_pubkey=signer.script, halving_period=210_000)
    block = create_block(int(previous["hash"], 16), coinbase, previous["time"] + 1, txlist=transactions)
    add_witness_commitment(block)
    if full_weight:
        # Add zero-valued native outputs to coinbase, where there is no service
        # signing request. Account for the output CompactSize transition first.
        count = (MAX_BLOCK_WEIGHT - block.get_weight()) // 172
        coinbase.vout += [CTxOut(0, signer.script) for _ in range(count)]
        while block.get_weight() > MAX_BLOCK_WEIGHT - 44:
            coinbase.vout.pop()
        remaining = MAX_BLOCK_WEIGHT - block.get_weight()
        if remaining % 4:
            raise ValueError("fixture full block has non-four-byte padding remainder")
        payload_size = remaining // 4 - 11
        if not 0 <= payload_size <= 80:
            raise ValueError("fixture full block padding bound")
        coinbase.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x42" * payload_size])))
        if block.get_weight() != MAX_BLOCK_WEIGHT:
            raise ValueError("fixture full block weight mismatch")
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block
