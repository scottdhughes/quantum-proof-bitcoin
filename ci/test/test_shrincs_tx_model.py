"""Tests for the consensus-disabled PQBTC SHRINCS transaction model."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "contrib" / "shrincs-tx" / "tx_model.py"
VECTOR_PATH = REPO_ROOT / "contrib" / "shrincs-tx" / "vector.json"
INTERPRETER_PATH = REPO_ROOT / "src" / "script" / "interpreter.cpp"
SPEC = importlib.util.spec_from_file_location("shrincs_tx_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class ShrincsTxModelTests(unittest.TestCase):
    def test_committed_vector_matches_model(self) -> None:
        committed = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        self.assertEqual(committed, MODEL.vector_payload())

    def test_pre_activation_node_does_not_enforce_candidate_version(self) -> None:
        source = INTERPRETER_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            source,
            re.compile(
                r"Other version/size/p2sh combinations return true for future softfork "
                r"compatibility\s*return true;"
            ),
        )
        self.assertEqual(MODEL.PROPOSED_WITNESS_VERSION, 2)

    def test_context_and_candidate_program_are_frozen(self) -> None:
        self.assertEqual(MODEL.SHRINCS_CONTEXT, b"PQBTC/SHRINCS/TXSIG/v0")
        public_key = bytes(range(48))
        script = MODEL.script_pubkey(public_key)
        self.assertEqual(len(script), 34)
        self.assertEqual(script[:2], bytes([0x52, 0x20]))
        self.assertEqual(script[2:], MODEL.output_commitment(public_key))

    def test_public_key_commitment_is_bit_sensitive(self) -> None:
        public_key = bytes(range(48))
        mutated = bytearray(public_key)
        mutated[17] ^= 1
        self.assertNotEqual(
            MODEL.output_commitment(public_key),
            MODEL.output_commitment(bytes(mutated)),
        )

    def test_canonical_signature_lengths(self) -> None:
        self.assertEqual(MODEL.classify_signature(bytes(554)), "stateful")
        self.assertEqual(MODEL.classify_signature(bytes(4618)), "stateful")
        self.assertEqual(MODEL.classify_signature(bytes(5776)), "stateless")
        for size in (0, 553, 555, 4619, 5775, 5777):
            with self.subTest(size=size), self.assertRaises(MODEL.TxModelError):
                MODEL.classify_signature(bytes(size))

    def test_witness_is_exactly_signature_and_public_key(self) -> None:
        public_key = bytes(range(48))
        program = MODEL.output_commitment(public_key)
        signature = bytes(554)
        parsed = MODEL.parse_witness([signature, public_key], program)
        self.assertEqual(parsed, (signature, public_key, "stateful"))
        with self.assertRaisesRegex(MODEL.TxModelError, "exactly two"):
            MODEL.parse_witness([signature], program)
        with self.assertRaisesRegex(MODEL.TxModelError, "exactly two"):
            MODEL.parse_witness([signature, public_key, b"extra"], program)
        bad_key = bytearray(public_key)
        bad_key[0] ^= 1
        with self.assertRaisesRegex(MODEL.TxModelError, "commitment mismatch"):
            MODEL.parse_witness([signature, bytes(bad_key)], program)

    def test_nonempty_scriptsig_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODEL.TxModelError, "empty scriptSig"):
            MODEL.SpentInput(
                prevout=MODEL.OutPoint(bytes(32), 0),
                amount=1,
                script_pubkey=b"",
                sequence=0,
                script_sig=b"\x51",
            )

    def test_sighash_commits_to_every_transaction_surface(self) -> None:
        public_key = bytes(range(48))
        tx = MODEL.build_design_transaction(public_key)
        chain_id = MODEL.TEST_CHAIN_ID
        digest = MODEL.transaction_sighash(tx, 0, chain_id)

        mutations = MODEL.transaction_surface_mutations(tx)
        self.assertEqual(len(mutations), 22)
        for name, mutated in mutations.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(digest, MODEL.transaction_sighash(mutated, 0, chain_id))

        changed_chain = bytearray(chain_id)
        changed_chain[-1] ^= 1
        self.assertNotEqual(digest, MODEL.transaction_sighash(tx, 0, bytes(changed_chain)))
        self.assertNotEqual(digest, MODEL.transaction_sighash(tx, 1, chain_id))

    def test_fixed_sighash_all_has_no_appended_mode_byte(self) -> None:
        tx = MODEL.build_design_transaction(bytes(range(48)))
        digest = MODEL.transaction_sighash(tx, 0, MODEL.TEST_CHAIN_ID)
        self.assertEqual(len(digest), 32)
        self.assertEqual(MODEL.SIGHASH_ALL, 1)

    def test_weight_and_verifier_bounds(self) -> None:
        self.assertEqual(MODEL.transaction_weight_one_input_two_outputs(554), 1157)
        self.assertEqual(MODEL.transaction_weight_one_input_two_outputs(4618), 5221)
        self.assertEqual(MODEL.transaction_weight_one_input_two_outputs(5776), 6379)
        self.assertEqual(MODEL.transaction_verifier_compressions(554), 499)
        self.assertEqual(MODEL.transaction_verifier_compressions(4618), 1007)
        self.assertEqual(MODEL.transaction_verifier_compressions(5776), 5534)
        self.assertTrue(MODEL.signature_bytes_exceed_verifier_compressions())

    def test_stateful_signature_byte_margin_is_strict_at_every_depth(self) -> None:
        for depth in range(1, 256):
            signature_bytes = 538 + 16 * depth
            compressions = MODEL.transaction_verifier_compressions(signature_bytes)
            self.assertEqual(signature_bytes - compressions, 41 + 14 * depth)
            self.assertLess(compressions, signature_bytes)


if __name__ == "__main__":
    unittest.main()
