#!/usr/bin/env python3
"""Tests for bounded registered peer recovery."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "contrib/ml-dsa-console/public_peer_recovery.py"
spec = importlib.util.spec_from_file_location("peer_recovery", PATH)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.endpoint = "127.0.0.1:23833"
        self.policy = {
            "schema": "PQBTC-MLDSA44-PUBLIC-PEER-POLICY-1",
            "profile_sha256": recovery.runtime.PROFILE,
            "network": "test",
            "network_active": True,
            "endpoints": [self.endpoint],
        }
        self.write_policy()
        self.node = FakeNode(self.endpoint)

    def write_policy(self):
        path = self.state / "peer-policy.json"
        path.write_text(json.dumps(self.policy))
        path.chmod(0o600)

    def run_recovery(self, budget=2):
        return recovery.renew(self.node, self.state, self.endpoint, budget)

    def test_policy_guards_and_off(self):
        self.policy["network_active"] = False
        self.write_policy()
        with self.assertRaises(Exception):
            self.run_recovery()
        self.policy["network_active"] = True
        self.write_policy()
        (self.state / "peer-policy.tmp").touch()
        with self.assertRaises(Exception):
            self.run_recovery()
        (self.state / "peer-policy.tmp").unlink()
        (self.state / "peer-policy.json").chmod(0o644)
        with self.assertRaises(Exception):
            self.run_recovery()
        (self.state / "peer-policy.json").unlink()
        os.symlink("/dev/null", self.state / "peer-policy.json")
        with self.assertRaises(Exception):
            self.run_recovery()

    def test_policy_rejects_hardlink_oversize_and_duplicate_members(self):
        path = self.state / "peer-policy.json"
        link = self.state / "hardlink"
        os.link(path, link)
        with self.assertRaises(Exception):
            self.run_recovery()
        link.unlink()
        path.write_bytes(b" " * 4097)
        with self.assertRaises(Exception):
            self.run_recovery()
        path.write_text('{"network_active":true,"network_active":true}')
        with self.assertRaises(Exception):
            self.run_recovery()
        self.assertEqual(self.node.mutations, [])

    def test_absent_peer_uses_native_default(self):
        self.node.phase = 1
        result = self.run_recovery()
        self.assertEqual(result["old_peer_ids"], [])
        self.assertEqual(self.node.mutations[0], ("addnode", self.endpoint, "onetry"))

    def test_unknown_unregistered_and_native_off(self):
        self.policy["endpoints"] = []
        self.write_policy()
        with self.assertRaises(Exception):
            self.run_recovery()
        self.policy["endpoints"] = [self.endpoint]
        self.write_policy()
        self.node.registered = False
        with self.assertRaises(Exception):
            self.run_recovery()
        self.node.registered = True
        self.node.active = False
        with self.assertRaises(Exception):
            self.run_recovery()
        self.assertEqual(self.node.mutations, [])

    def test_ambiguous_and_exhausted(self):
        self.node.ambiguous = True
        with self.assertRaises(Exception):
            self.run_recovery()
        with self.assertRaises(Exception):
            self.run_recovery(0)
        self.assertEqual(self.node.mutations, [])

    def test_renewal_proves_new_id_and_fresh_ping(self):
        result = self.run_recovery()
        self.assertEqual(result["old_peer_ids"], [1])
        self.assertEqual(result["new_peer_id"], 2)
        self.assertTrue(result["fresh_pong"])
        self.assertEqual(
            self.node.mutations,
            [
                ("disconnectnode", "", 1),
                ("addnode", self.endpoint, "onetry", True),
                ("ping",),
            ],
        )

    def test_stale_pong_and_same_id_are_not_success(self):
        self.node.stale = True
        with self.assertRaises(Exception):
            self.run_recovery(0.02)
        self.node.stale = False
        self.node.same_id = True
        self.node.phase = 0
        with self.assertRaises(Exception):
            self.run_recovery(0.02)


class FakeNode:
    def __init__(self, endpoint):
        self.endpoint, self.registered, self.active = endpoint, True, True
        self.ambiguous = self.stale = self.same_id = False
        self.phase = 0
        self.mutations = []

    def rpc(self, *, timeout):
        return self

    def getnetworkinfo(self):
        return {"networkactive": self.active}

    def getaddednodeinfo(self, endpoint):
        return (
            [{"addednode": endpoint, "connected": True, "addresses": []}]
            if self.registered
            else []
        )

    def getpeerinfo(self):
        if self.phase == 1:
            return []
        peer = {
            "id": 1 if self.phase == 0 or self.same_id else 2,
            "addr": self.endpoint,
            "version": 70016,
            "relaytxes": True,
            "connection_type": "manual",
            "transport_protocol_type": "v2",
            "bytessent_per_msg": {"ping": 10},
            "bytesrecv_per_msg": {"pong": 10 if self.phase < 3 or self.stale else 20},
        }
        if self.phase >= 3 and not self.stale:
            peer["bytessent_per_msg"]["ping"] = 20
        return [peer, dict(peer, id=3)] if self.ambiguous else [peer]

    def disconnectnode(self, *args):
        self.mutations.append(("disconnectnode", *args))
        self.phase = 1

    def addnode(self, *args):
        self.mutations.append(("addnode", *args))
        self.phase = 2

    def ping(self):
        self.mutations.append(("ping",))
        self.phase = 3


class ControllerTests(unittest.TestCase):
    def test_renew_action_does_not_forward_to_worker(self):
        path = ROOT / "contrib/ml-dsa-console/public_controller.py"
        spec = importlib.util.spec_from_file_location("recovery_controller", path)
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        instance = object.__new__(controller.PublicController)
        import threading

        instance._mutex = threading.RLock()
        instance._reconcile_handles = Mock()
        instance._request = Mock(side_effect=AssertionError("worker forwarding"))
        instance._renew_peer = Mock(return_value={"renewed": True})
        result = instance.action(
            "renew_peer",
            {"endpoint": "127.0.0.1:23833", "budget_seconds": 1},
            include_status=False,
        )
        self.assertTrue(result["result"]["renewed"])
        instance._request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
