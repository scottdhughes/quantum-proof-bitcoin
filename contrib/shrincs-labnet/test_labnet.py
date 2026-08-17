#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("shrincs_labnet", HERE / "labnet.py")
assert SPEC is not None and SPEC.loader is not None
labnet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = labnet
SPEC.loader.exec_module(labnet)


class FakeReference:
    FXMSS_SHAPE_UNBALANCED = 0

    def __init__(self):
        self.fail_states: set[int] = set()

    @staticmethod
    def shrincs_sf_leaf_select(structure: bytes, state_counter: int | None):
        if state_counter is None:
            return None
        return (1, 254 - state_counter) if 0 <= state_counter < 5 else None

    def shrincs_sign(
        self,
        message: bytes,
        context: bytes,
        secret_key: bytes,
        state_counter: int | None,
        opt_rand: bytes | None,
    ) -> bytes:
        del secret_key, opt_rand
        if state_counter is not None and state_counter in self.fail_states:
            raise RuntimeError("injected signer failure")
        mode = b"S" if state_counter is not None else b"R"
        counter = bytes([state_counter]) if state_counter is not None else b"-"
        return mode + counter + hashlib.sha256(message + context).digest()

    @staticmethod
    def shrincs_verify(
        message: bytes, signature: bytes, context: bytes, public_key: bytes
    ) -> bool:
        del public_key
        return signature[2:] == hashlib.sha256(message + context).digest()


class NodeConfigTests(unittest.TestCase):
    def test_network_bindings_live_under_regtest_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layout = labnet.Layout(root / "state", root / "build")
            text = layout.node0.config_text()

        global_settings, regtest_settings = text.split("[regtest]\n", 1)
        self.assertIn("regtest=1\n", global_settings)
        for setting in (
            "port=19444",
            "rpcport=19443",
            "rpcbind=127.0.0.1",
            "rpcallowip=127.0.0.1",
        ):
            with self.subTest(setting=setting):
                self.assertNotIn(setting, global_settings)
                self.assertIn(setting, regtest_settings)


class SignerStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.sqlite3"
        self.store = labnet.SignerStore(self.path)
        self.reference = FakeReference()
        self.store.create(bytes(range(82)), bytes(range(48)), bytes([0, 4]))

    def test_capacity_matches_frozen_unbalanced_profile(self):
        self.assertEqual(labnet.SignerStore.stateful_capacity(bytes([0, 4])), 5)
        self.assertEqual(labnet.SignerStore.stateful_capacity(bytes([1, 4])), 16)

    def test_reservation_precedes_signature_and_broadcast_is_recorded(self):
        signature, state = self.store.sign_stateful(
            self.reference, b"digest-0", labnet.SIGNER_CONTEXT
        )
        self.assertEqual(state, 0)
        status = self.store.status()
        self.assertEqual(status["next_state"], 1)
        self.assertEqual(status["reservations"], {"signed": 1})

        self.store.record_broadcast(
            state_counter=state, signature=signature, txid="01" * 32
        )
        status = self.store.status()
        self.assertEqual(status["reservations"], {"broadcast": 1})

    def test_failed_signing_burns_reserved_state(self):
        self.reference.fail_states.add(0)
        with self.assertRaisesRegex(RuntimeError, "injected signer failure"):
            self.store.sign_stateful(
                self.reference, b"digest-fail", labnet.SIGNER_CONTEXT
            )
        status = self.store.status()
        self.assertEqual(status["next_state"], 1)
        self.assertEqual(status["stateful_remaining"], 4)
        self.assertEqual(status["reservations"], {"failed": 1})

        signature, state = self.store.sign_stateful(
            self.reference, b"digest-next", labnet.SIGNER_CONTEXT
        )
        self.assertEqual(state, 1)
        self.assertTrue(signature)

    def test_exhaustion_never_falls_back_silently(self):
        for counter in range(5):
            _, used = self.store.sign_stateful(
                self.reference,
                f"digest-{counter}".encode(),
                labnet.SIGNER_CONTEXT,
            )
            self.assertEqual(used, counter)
        with self.assertRaisesRegex(labnet.LabnetError, "exhausted"):
            self.store.sign_stateful(
                self.reference, b"digest-exhausted", labnet.SIGNER_CONTEXT
            )
        status = self.store.status()
        self.assertEqual(status["next_state"], 5)
        self.assertEqual(status["stateful_remaining"], 0)

    def test_stateless_signing_does_not_consume_state(self):
        signature = self.store.sign_stateless(
            self.reference, b"recovery", labnet.SIGNER_CONTEXT
        )
        self.store.record_broadcast(
            state_counter=None, signature=signature, txid="02" * 32
        )
        status = self.store.status()
        self.assertEqual(status["next_state"], 0)
        self.assertEqual(status["stateless_signatures"], 1)


if __name__ == "__main__":
    unittest.main()
