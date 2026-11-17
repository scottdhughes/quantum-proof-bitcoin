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

    def test_elapsed_startup_deadline_prevents_mutation(self):
        import time

        with self.assertRaises(Exception) as caught:
            recovery.renew(
                self.node,
                self.state,
                self.endpoint,
                1,
                deadline=time.monotonic() - 0.01,
            )
        self.assertNotIsInstance(caught.exception, TypeError)
        self.assertEqual(self.node.mutations, [])

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


class HostPathTests(unittest.TestCase):
    def setUp(self):
        import copy
        import hashlib
        import threading
        from types import SimpleNamespace
        from unittest.mock import patch

        self.copy, self.patch, self.namespace = copy, patch, SimpleNamespace
        path = ROOT / "contrib/ml-dsa-console/public_controller.py"
        spec = importlib.util.spec_from_file_location("host_path_controller", path)
        self.control = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.control)
        c = self.control
        manifest = {
            "schema": "PQBTC-MLDSA44-SOURCE-BUILD-1",
            "source_head": "1" * 40,
            "source_tree": "2" * 40,
            "compiler": "gcc",
            "architecture": "x86_64",
            "sha256": {key: "a" * 64 for key in c.source.REQUIRED_HASHES},
        }
        self.descriptor = {
            "schema": c.source.DESCRIPTOR_SCHEMA,
            "image": "sha256:" + "a" * 64,
            "manifest": manifest,
            "manifest_sha256": hashlib.sha256(c.source.canonical(manifest)).hexdigest(),
        }
        self.manager = object.__new__(c.PublicManager)
        self.manager.descriptor, self.manager.container = (
            self.descriptor,
            "pqbtc-mldsa-public-test",
        )
        self.manager.volume, self.manager.port = (
            self.manager.container + "-data-v1",
            23833,
        )
        self.controller = object.__new__(c.PublicController)
        self.controller.manager, self.controller.descriptor = (
            self.manager,
            self.descriptor,
        )
        self.controller._mutex = threading.RLock()
        self.controller._request = Mock(side_effect=AssertionError("worker invoked"))
        self.identity = "b" * 64
        self.layout = {
            "Id": self.identity,
            "Image": self.descriptor["image"],
            "Config": {
                "Labels": self.manager.container_labels(),
                "Cmd": ["sleep", "infinity"],
                "User": "",
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "NetworkMode": "bridge",
                "Memory": 1073741824,
                "NanoCpus": 2000000000,
                "PidsLimit": 256,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges"],
                "Privileged": False,
                "Tmpfs": c.TMPFS,
                "RestartPolicy": {"Name": "unless-stopped"},
                "PortBindings": {
                    "23833/tcp": [{"HostIp": "127.0.0.1", "HostPort": "23833"}]
                },
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": self.manager.volume,
                    "Destination": c.DATA,
                    "RW": True,
                }
            ],
            "State": {"Running": True},
        }
        self.proof = {
            "endpoint": "127.0.0.1:23833",
            "renewed": True,
            "network_active": True,
            "old_peer_ids": [1],
            "new_peer_id": 2,
            "transport_protocol_type": "v2",
            "fresh_pong": True,
            "ping_sent_before": 10,
            "ping_sent_after": 20,
            "pong_received_before": 10,
            "pong_received_after": 20,
        }
        self.calls = []
        self.before, self.after = self.layout, self.layout
        self.clock = 100.0
        self.delays = [1.0, 2.0, 1.0]
        self.exec_returncode = 0
        self.exception = None
        self.manager.run = self.run_docker
        self.manager.docker = ("docker",)

    def run_docker(self, args, **kwargs):
        self.calls.append((args, kwargs))
        index = len(self.calls) - 1
        self.clock += self.delays[index]
        payload = self.before if index == 0 else self.after
        return self.namespace(
            returncode=0, stdout=json.dumps(payload).encode(), stderr=b""
        )

    def start_docker(self, args, **kwargs):
        self.calls.append((args[1:], kwargs))
        test = self

        class Process:
            def __init__(self):
                read, write = os.pipe()
                os.write(write, b"READY\n")
                os.close(write)
                self.stdout = os.fdopen(read, "rb", buffering=0)
                self.returncode = None

            def communicate(self, input=None, timeout=None):
                test.handshake = (input, timeout)
                test.clock += test.delays[1]
                self.returncode = test.exec_returncode
                self.stdout.close()
                if test.exception:
                    raise test.exception
                return json.dumps(test.proof).encode(), b"secret-auth-stderr"

            def poll(self):
                return self.returncode

            def kill(self):
                self.returncode = -9

        return Process()

    def invoke(self, budget=10):
        with self.patch.object(
            self.control.time, "monotonic", side_effect=lambda: self.clock
        ), self.patch.object(
            self.control.subprocess, "Popen", side_effect=self.start_docker
        ):
            return self.controller.action(
                "renew_peer",
                {"endpoint": self.proof["endpoint"], "budget_seconds": budget},
                include_status=False,
            )

    def test_remote_watchdog_covers_delayed_launch_and_contained_work(self):
        import signal
        import subprocess
        import sys
        import time

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "mutation"
            payload = (
                "import time\ntime.sleep(.3)\n"
                "open(" + repr(str(marker)) + ", 'w').write('mutation')\n"
            ).encode()
            bootstrap = self.control.peer_recovery_bootstrap(payload)
            wrapper = "import time;time.sleep(.12);exec(" + repr(bootstrap) + ")"
            deadline = time.monotonic() + 0.28
            process = subprocess.Popen(
                [sys.executable, "-c", wrapper],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                self.assertEqual(process.stdout.readline(), b"READY\n")
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                process.communicate(input=(repr(remaining) + "\n").encode(), timeout=2)
                self.assertEqual(process.returncode, -signal.SIGALRM)
                self.assertFalse(marker.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_contended_mutex_refuses_within_budget(self):
        import threading
        import time

        ready = threading.Event()
        release = threading.Event()

        def hold():
            with self.controller._mutex:
                ready.set()
                release.wait(2)

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(ready.wait(1))
        start = time.monotonic()
        try:
            with self.assertRaises(Exception):
                self.controller.action(
                    "renew_peer",
                    {"endpoint": self.proof["endpoint"], "budget_seconds": 0.05},
                    include_status=False,
                )
            self.assertLess(time.monotonic() - start, 0.3)
            self.assertTrue(thread.is_alive())
            self.assertEqual(self.calls, [])
        finally:
            release.set()
            thread.join(1)

    def test_full_path_uses_verified_id_and_streams_helper_with_shared_budget(self):
        class Lock:
            def acquire(inner, timeout):
                self.clock += 2
                return True

            def release(inner):
                pass

        self.controller._mutex = Lock()
        value = self.invoke()["result"]
        self.assertEqual(value, self.proof)
        self.assertEqual(self.calls[0][1]["timeout"], 8)
        self.assertEqual(self.calls[2][1]["timeout"], 5)
        args, _ = self.calls[1]
        self.assertEqual(args[4], self.identity)
        self.assertIn(repr(PATH.read_bytes()), args[-2])
        self.assertEqual(self.handshake, (b"7.0\n", 7))
        self.assertNotIn("Env", self.calls[0][0][3])
        self.controller._request.assert_not_called()

    def test_bad_layout_and_descriptor_never_execute(self):
        for field in ("image", "layout", "id", "descriptor"):
            with self.subTest(field=field):
                self.calls.clear()
                self.before = self.copy.deepcopy(self.layout)
                self.controller.descriptor = self.copy.deepcopy(self.descriptor)
                if field == "image":
                    self.before["Image"] = "sha256:" + "f" * 64
                if field == "layout":
                    self.before["HostConfig"]["Privileged"] = True
                if field == "id":
                    self.before["Id"] = "not-a-container-id"
                if field == "descriptor":
                    self.controller.descriptor["manifest_sha256"] = "f" * 64
                with self.assertRaises(Exception):
                    self.invoke()
                self.assertFalse(any(call[0][0] == "exec" for call in self.calls))
                self.clock = 100

    def test_changed_identity_after_execution_fails(self):
        self.after = self.copy.deepcopy(self.layout)
        self.after["Id"] = "c" * 64
        with self.assertRaises(Exception):
            self.invoke()

    def test_malformed_or_stale_proof_fails_closed(self):
        variants = [
            {"fresh_pong": False},
            {"fresh_pong": "yes"},
            {"new_peer_id": 1},
            {"ping_sent_after": 10},
            {"pong_received_after": 10},
            {"old_peer_ids": "1"},
            {"transport_protocol_type": "detecting"},
            {"unexpected": "private"},
        ]
        for change in variants:
            with self.subTest(change=change):
                original = self.proof
                self.proof = {**original, **change}
                self.calls.clear()
                self.clock = 100
                with self.assertRaises(Exception):
                    self.invoke()
                self.proof = original

    def test_budget_expired_during_lock_or_probe_skips_execution(self):
        class Lock:
            def acquire(inner, timeout):
                self.clock += 10
                return True

            def release(inner):
                pass

        self.controller._mutex = Lock()
        with self.assertRaises(Exception):
            self.invoke()
        self.assertEqual(self.calls, [])
        import threading

        self.controller._mutex = threading.RLock()
        self.clock = 100
        self.delays = [10, 0, 0]
        with self.assertRaises(Exception):
            self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_budget_exhaustion_and_errors_are_sanitized(self):
        import subprocess

        self.delays = [9, 2, 0]
        with self.assertRaises(Exception):
            self.invoke()
        self.assertEqual(len(self.calls), 2)
        self.calls.clear()
        self.clock = 100
        self.delays = [1, 1, 1]
        self.exception = subprocess.TimeoutExpired(
            "sensitive-auth-argv", 1, stderr=b"secret-auth-stderr"
        )
        with self.assertRaises(Exception) as caught:
            self.invoke()
        self.assertNotIn("sensitive-auth", str(caught.exception))
        self.assertNotIn("secret-auth", str(caught.exception))
        self.calls.clear()
        self.clock = 100
        self.exception = None
        self.exec_returncode = 1
        with self.assertRaises(Exception) as caught:
            self.invoke()
        self.assertNotIn("secret-auth", str(caught.exception))
        for budget in (0, 11, float("nan"), True):
            with self.assertRaises(Exception):
                self.invoke(budget)


if __name__ == "__main__":
    unittest.main()
