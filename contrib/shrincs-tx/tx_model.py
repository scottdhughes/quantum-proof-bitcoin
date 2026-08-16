"""Consensus-disabled transaction-envelope model for PQBTC SHRINCS v0.

This module is a design and vector-generation aid. It does not change or
implement node consensus behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Iterable, Sequence

PUBLIC_KEY_BYTES = 48
STATEFUL_SIGNATURE_MIN = 554
STATEFUL_SIGNATURE_MAX = 4618
STATEFUL_SIGNATURE_BASE = 538
STATEFUL_SIGNATURE_STEP = 16
STATELESS_SIGNATURE_BYTES = 5776
PROGRAM_BYTES = 32
PROPOSED_WITNESS_VERSION = 2
SIGHASH_ALL = 1
SIG_HASH_EPOCH = 0
SPEND_TYPE = 0
SHRINCS_CONTEXT = b"PQBTC/SHRINCS/TXSIG/v0"
OUTPUT_TAG = b"PQBTC/SHRINCS/OUTPUT/v0"
SIGHASH_TAG = b"PQBTC/SHRINCS/TXSIG/v0"
TEST_CHAIN_ID = hashlib.sha256(b"PQBTC-SHRINCS-TX-V0-TEST-CHAIN").digest()


class TxModelError(ValueError):
    """Raised when a transaction-envelope input is not canonical."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TxModelError(message)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: bytes, message: bytes) -> bytes:
    tag_hash = sha256(tag)
    return sha256(tag_hash + tag_hash + message)


def compact_size(value: int) -> bytes:
    require(0 <= value <= 0xFFFFFFFFFFFFFFFF, "CompactSize value out of range")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def ser_u32(value: int) -> bytes:
    require(0 <= value <= 0xFFFFFFFF, "uint32 out of range")
    return value.to_bytes(4, "little")


def ser_i32(value: int) -> bytes:
    require(-(1 << 31) <= value < (1 << 31), "int32 out of range")
    return value.to_bytes(4, "little", signed=True)


def ser_u64(value: int) -> bytes:
    require(0 <= value <= 0xFFFFFFFFFFFFFFFF, "uint64 out of range")
    return value.to_bytes(8, "little")


def ser_bytes(value: bytes) -> bytes:
    return compact_size(len(value)) + value


@dataclass(frozen=True)
class OutPoint:
    txid: bytes
    index: int

    def __post_init__(self) -> None:
        require(len(self.txid) == 32, "outpoint txid must be 32 bytes")
        require(0 <= self.index <= 0xFFFFFFFF, "outpoint index out of range")

    def serialize(self) -> bytes:
        # txid is supplied in canonical wire-serialization byte order.
        return self.txid + ser_u32(self.index)


@dataclass(frozen=True)
class SpentInput:
    prevout: OutPoint
    amount: int
    script_pubkey: bytes
    sequence: int

    def __post_init__(self) -> None:
        require(0 <= self.amount <= 21_000_000 * 100_000_000, "input amount out of range")
        require(len(self.script_pubkey) <= 10_000, "input scriptPubKey too large")
        require(0 <= self.sequence <= 0xFFFFFFFF, "input sequence out of range")

    def serialize_stripped(self) -> bytes:
        # Version zero admits native witness inputs only, so scriptSig is empty.
        return self.prevout.serialize() + b"\x00" + ser_u32(self.sequence)


@dataclass(frozen=True)
class TxOutput:
    amount: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        require(0 <= self.amount <= 21_000_000 * 100_000_000, "output amount out of range")
        require(len(self.script_pubkey) <= 10_000, "output scriptPubKey too large")

    def serialize(self) -> bytes:
        return ser_u64(self.amount) + ser_bytes(self.script_pubkey)


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[SpentInput, ...]
    outputs: tuple[TxOutput, ...]
    lock_time: int

    def __post_init__(self) -> None:
        require(self.inputs, "transaction must contain at least one input")
        require(self.outputs, "transaction must contain at least one output")
        require(0 <= self.lock_time <= 0xFFFFFFFF, "lock time out of range")

    def serialize_stripped(self) -> bytes:
        return (
            ser_i32(self.version)
            + compact_size(len(self.inputs))
            + b"".join(txin.serialize_stripped() for txin in self.inputs)
            + compact_size(len(self.outputs))
            + b"".join(txout.serialize() for txout in self.outputs)
            + ser_u32(self.lock_time)
        )


def output_commitment(public_key: bytes) -> bytes:
    require(len(public_key) == PUBLIC_KEY_BYTES, "SHRINCS public key must be 48 bytes")
    return tagged_hash(OUTPUT_TAG, public_key)


def script_pubkey(public_key: bytes) -> bytes:
    # Candidate native witness-v2 program: OP_2 PUSH32 commitment.
    return bytes([0x50 + PROPOSED_WITNESS_VERSION, PROGRAM_BYTES]) + output_commitment(public_key)


def classify_signature(signature: bytes) -> str:
    size = len(signature)
    if size == STATELESS_SIGNATURE_BYTES:
        return "stateless"
    delta = size - STATEFUL_SIGNATURE_BASE
    if (
        STATEFUL_SIGNATURE_MIN <= size <= STATEFUL_SIGNATURE_MAX
        and delta % STATEFUL_SIGNATURE_STEP == 0
    ):
        depth = delta // STATEFUL_SIGNATURE_STEP
        require(1 <= depth <= 255, "stateful signature depth out of range")
        return "stateful"
    raise TxModelError("non-canonical SHRINCS signature length")


def parse_witness(witness: Sequence[bytes], expected_program: bytes) -> tuple[bytes, bytes, str]:
    require(len(expected_program) == PROGRAM_BYTES, "witness program must be 32 bytes")
    require(len(witness) == 2, "SHRINCS witness must contain exactly two items")
    signature, public_key = witness
    require(len(public_key) == PUBLIC_KEY_BYTES, "SHRINCS witness public key must be 48 bytes")
    require(output_commitment(public_key) == expected_program, "SHRINCS public-key commitment mismatch")
    return signature, public_key, classify_signature(signature)


def _aggregate(items: Iterable[bytes]) -> bytes:
    return sha256(b"".join(items))


def transaction_surface_mutations(tx: Transaction) -> dict[str, Transaction]:
    """Return deterministic mutations spanning every aggregated tx surface.

    This helper is test-only design machinery. It deliberately mutates both
    existing inputs and outputs and also their count and order.
    """

    require(len(tx.inputs) >= 2, "mutation corpus requires at least two inputs")
    require(len(tx.outputs) >= 2, "mutation corpus requires at least two outputs")
    first, second = tx.inputs[0], tx.inputs[1]
    output0, output1 = tx.outputs[0], tx.outputs[1]

    first_txid = bytearray(first.prevout.txid)
    first_txid[0] ^= 1
    second_txid = bytearray(second.prevout.txid)
    second_txid[-1] ^= 1

    third_input = SpentInput(
        prevout=OutPoint(sha256(b"prevout-2"), 7),
        amount=50_000,
        script_pubkey=bytes.fromhex("0014") + sha256(b"third-input")[:20],
        sequence=0xFFFFFFFC,
    )
    third_output = TxOutput(1_000, bytes.fromhex("6a05") + b"EXTRA")

    return {
        "version": replace(tx, version=tx.version + 1),
        "lock_time": replace(tx, lock_time=tx.lock_time + 1),
        "input0_prevout_txid": replace(
            tx,
            inputs=(
                replace(first, prevout=replace(first.prevout, txid=bytes(first_txid))),
                second,
            ),
        ),
        "input0_prevout_index": replace(
            tx,
            inputs=(
                replace(first, prevout=replace(first.prevout, index=first.prevout.index + 1)),
                second,
            ),
        ),
        "input0_amount": replace(tx, inputs=(replace(first, amount=first.amount + 1), second)),
        "input0_script": replace(
            tx,
            inputs=(replace(first, script_pubkey=first.script_pubkey + b"\x00"), second),
        ),
        "input0_sequence": replace(tx, inputs=(replace(first, sequence=first.sequence - 1), second)),
        "input1_prevout_txid": replace(
            tx,
            inputs=(first, replace(second, prevout=replace(second.prevout, txid=bytes(second_txid)))),
        ),
        "input1_prevout_index": replace(
            tx,
            inputs=(
                first,
                replace(second, prevout=replace(second.prevout, index=second.prevout.index + 1)),
            ),
        ),
        "input1_amount": replace(tx, inputs=(first, replace(second, amount=second.amount + 1))),
        "input1_script": replace(
            tx,
            inputs=(first, replace(second, script_pubkey=second.script_pubkey + b"\x00")),
        ),
        "input1_sequence": replace(tx, inputs=(first, replace(second, sequence=second.sequence - 1))),
        "input_order": replace(tx, inputs=(second, first)),
        "input_removed": replace(tx, inputs=(first,)),
        "input_added": replace(tx, inputs=tx.inputs + (third_input,)),
        "output0_amount": replace(tx, outputs=(replace(output0, amount=output0.amount + 1), output1)),
        "output0_script": replace(
            tx,
            outputs=(replace(output0, script_pubkey=output0.script_pubkey + b"\x00"), output1),
        ),
        "output1_amount": replace(tx, outputs=(output0, replace(output1, amount=output1.amount + 1))),
        "output1_script": replace(
            tx,
            outputs=(output0, replace(output1, script_pubkey=output1.script_pubkey + b"\x00")),
        ),
        "output_order": replace(tx, outputs=(output1, output0)),
        "output_removed": replace(tx, outputs=(output0,)),
        "output_added": replace(tx, outputs=tx.outputs + (third_output,)),
    }


def transaction_sighash(tx: Transaction, input_index: int, chain_id: bytes) -> bytes:
    """Return the proposed fixed-SIGHASH_ALL digest for one input.

    `chain_id` is a 32-byte network-specific constant to be frozen with the
    network genesis. No production chain ID is selected by this model.
    """

    require(len(chain_id) == 32, "chain_id must be 32 bytes")
    require(0 <= input_index < len(tx.inputs), "input index out of range")

    hash_prevouts = _aggregate(txin.prevout.serialize() for txin in tx.inputs)
    hash_amounts = _aggregate(ser_u64(txin.amount) for txin in tx.inputs)
    hash_scriptpubkeys = _aggregate(ser_bytes(txin.script_pubkey) for txin in tx.inputs)
    hash_sequences = _aggregate(ser_u32(txin.sequence) for txin in tx.inputs)
    hash_outputs = _aggregate(txout.serialize() for txout in tx.outputs)

    message = (
        bytes([SIG_HASH_EPOCH, SIGHASH_ALL])
        + chain_id
        + ser_i32(tx.version)
        + ser_u32(tx.lock_time)
        + hash_prevouts
        + hash_amounts
        + hash_scriptpubkeys
        + hash_sequences
        + hash_outputs
        + bytes([SPEND_TYPE])
        + ser_u32(input_index)
    )
    return tagged_hash(SIGHASH_TAG, message)


def stateful_depth(signature_bytes: int) -> int:
    require(
        STATEFUL_SIGNATURE_MIN <= signature_bytes <= STATEFUL_SIGNATURE_MAX,
        "stateful size out of range",
    )
    delta = signature_bytes - STATEFUL_SIGNATURE_BASE
    require(delta % STATEFUL_SIGNATURE_STEP == 0, "non-canonical stateful size")
    depth = delta // STATEFUL_SIGNATURE_STEP
    require(1 <= depth <= 255, "stateful depth out of range")
    return depth


def transaction_verifier_compressions(signature_bytes: int) -> int:
    """Worst-case portable SHA-256 compressions for the fixed tx context."""

    if signature_bytes == STATELESS_SIGNATURE_BYTES:
        return 5534
    depth = stateful_depth(signature_bytes)
    return 497 + 2 * depth


def stripped_size_one_input_two_outputs() -> int:
    # Empty scriptSig and two 34-byte P2SHRINCS outputs.
    return 4 + 1 + 41 + 1 + 2 * 43 + 4


def transaction_weight_one_input_two_outputs(signature_bytes: int) -> int:
    # Only the length classification matters here.
    if signature_bytes == STATELESS_SIGNATURE_BYTES:
        pass
    else:
        stateful_depth(signature_bytes)
    stripped = stripped_size_one_input_two_outputs()
    witness = 1 + len(compact_size(signature_bytes)) + signature_bytes + 1 + PUBLIC_KEY_BYTES
    marker_flag = 2
    return 4 * stripped + marker_flag + witness


def signature_bytes_exceed_verifier_compressions() -> bool:
    for depth in range(1, 256):
        signature_bytes = STATEFUL_SIGNATURE_BASE + STATEFUL_SIGNATURE_STEP * depth
        if transaction_verifier_compressions(signature_bytes) > signature_bytes:
            return False
    return transaction_verifier_compressions(STATELESS_SIGNATURE_BYTES) <= STATELESS_SIGNATURE_BYTES


def build_design_transaction(public_key: bytes) -> Transaction:
    candidate_script = script_pubkey(public_key)
    input0 = SpentInput(
        prevout=OutPoint(sha256(b"prevout-0"), 3),
        amount=125_000,
        script_pubkey=candidate_script,
        sequence=0xFFFFFFFD,
    )
    input1 = SpentInput(
        prevout=OutPoint(sha256(b"prevout-1"), 1),
        amount=75_000,
        script_pubkey=bytes.fromhex("0014") + sha256(b"witness-input")[:20],
        sequence=0xFFFFFFFE,
    )
    outputs = (
        TxOutput(150_000, candidate_script),
        TxOutput(49_000, bytes.fromhex("6a04") + b"PQV0"),
    )
    return Transaction(version=2, inputs=(input0, input1), outputs=outputs, lock_time=840_000)


def vector_payload() -> dict[str, object]:
    public_key = bytes(range(PUBLIC_KEY_BYTES))
    program = output_commitment(public_key)
    candidate_script = script_pubkey(public_key)
    tx = build_design_transaction(public_key)

    return {
        "profile": "pqbtc-shrincs-tx-v0-design-vector",
        "chain_id": TEST_CHAIN_ID.hex(),
        "context": SHRINCS_CONTEXT.hex(),
        "public_key": public_key.hex(),
        "output_commitment": program.hex(),
        "script_pubkey": candidate_script.hex(),
        "stripped_transaction": tx.serialize_stripped().hex(),
        "input_digests": [
            transaction_sighash(tx, index, TEST_CHAIN_ID).hex()
            for index in range(len(tx.inputs))
        ],
        "weights": {
            str(size): transaction_weight_one_input_two_outputs(size)
            for size in (STATEFUL_SIGNATURE_MIN, STATEFUL_SIGNATURE_MAX, STATELESS_SIGNATURE_BYTES)
        },
        "verifier_compressions": {
            str(size): transaction_verifier_compressions(size)
            for size in (STATEFUL_SIGNATURE_MIN, STATEFUL_SIGNATURE_MAX, STATELESS_SIGNATURE_BYTES)
        },
        "signature_bytes_exceed_verifier_compressions": (
            signature_bytes_exceed_verifier_compressions()
        ),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = vector_payload()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
