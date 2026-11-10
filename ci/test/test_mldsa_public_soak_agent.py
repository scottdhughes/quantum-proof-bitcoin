"""Control framing and public-only reporting for the two-host soak agent."""
import importlib.util
from pathlib import Path
import unittest
import os
import time
import threading
import json

PATH = Path(__file__).resolve().parents[2] / "contrib/ml-dsa-qualification/public_soak_agent.py"
SPEC = importlib.util.spec_from_file_location("public_soak_agent_tests", PATH)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class PublicSoakAgentTests(unittest.TestCase):
    def test_deadline_stops_only_the_inspected_immutable_container_id(self):
        calls = []
        inspected = "ab" * 32
        replacement = "cd" * 32
        class Result:
            returncode = 0
            stdout = json.dumps({"Id": inspected, "Name": "/pqbtc-mldsa-public-unit",
                                 "State": {"Running": True}, "Config": {"Labels": {
                                 "org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": agent.PROFILE,
                                 "org.pqbtc.console.build": "source-1"}}}).encode()
        class Manager:
            container = "pqbtc-mldsa-public-unit"
            current_identity = inspected
            def run(self, args, **kwargs):
                calls.append(args)
                if args[0] == "inspect":
                    self.current_identity = replacement  # The name is reused after inspection.
                else:
                    self.assert_stopped_id = args[-1]
                    if args[-1] != inspected:
                        raise AssertionError("The unvalidated replacement was stopped")
                return Result()
        manager = Manager()
        agent.stop_owned_public(manager)
        self.assertEqual(manager.current_identity, replacement)
        self.assertEqual(calls[-1], ["stop", "--time", "1", inspected])

    def test_docker_unavailable_is_not_misreported_as_no_running_node(self):
        class Result:
            returncode = 1
            stderr = b"Cannot connect to the Docker daemon"
        class Manager:
            container = "pqbtc-mldsa-public-unit"
            def run(self, args, **kwargs): return Result()
        with self.assertRaisesRegex(ValueError, "liveness"):
            agent.stop_owned_public(Manager())

    def test_deadline_guard_runs_cleanup_while_main_action_is_blocked(self):
        stopped = threading.Event()
        guard = agent.DeadlineGuard(time.time() + 0.1, time.monotonic() + 0.1, stopped.set)
        guard.start()
        try:
            self.assertTrue(stopped.wait(1), "A blocked owner action prevented deadline cleanup")
            self.assertTrue(guard.expired)
        finally:
            guard.cancel()

    def test_deadline_cleanup_cannot_stop_an_unrelated_container(self):
        class Result:
            returncode = 0
            stdout = b'{"Name":"/pqbtc-mldsa-public-unit","Config":{"Labels":{"org.pqbtc.console.schema":"unrelated"}}}'
        class Manager:
            container = "pqbtc-mldsa-public-unit"
            def run(self, args, **kwargs):
                if args[0] != "inspect":
                    raise AssertionError("An unrelated container was targeted")
                return Result()
        with self.assertRaisesRegex(ValueError, "ownership"):
            agent.stop_owned_public(Manager())

    def test_unread_output_pipe_cannot_block_shutdown_deadline(self):
        read_fd, write_fd = os.pipe()
        try:
            before = time.monotonic()
            self.assertFalse(agent.write_control_response(write_fd, b'x' * 131072,
                                                          time.time() + 0.15, time.monotonic() + 0.15))
            self.assertLess(time.monotonic() - before, 1)
        finally:
            os.close(write_fd)
            os.close(read_fd)

    def test_partial_open_pipe_cannot_block_independent_shutdown(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"id":0,"action":')
            before = time.monotonic()
            reader = agent.ControlInput(read_fd)
            self.assertIsNone(reader.line(time.time() + 0.15, time.monotonic() + 0.15))
            self.assertLess(time.monotonic() - before, 1)
        finally:
            os.close(write_fd)
            os.close(read_fd)

    def test_incremental_reader_handles_buffered_lines_and_refuses_overlong_input(self):
        read_fd, write_fd = os.pipe()
        try:
            reader = agent.ControlInput(read_fd)
            os.write(write_fd, b'first\nsecond\n')
            end = time.monotonic() + 1
            self.assertEqual(reader.line(time.time() + 1, end), b'first\n')
            self.assertEqual(reader.line(time.time() + 1, end), b'second\n')
            reader.pending = bytearray(b'x' * (agent.MAX_REQUEST + 1))
            with self.assertRaisesRegex(ValueError, "request bound"):
                reader.line(time.time() + 1, end)
        finally:
            os.close(write_fd)
            os.close(read_fd)

    def test_control_rejects_ambiguous_truncated_and_unbounded_requests(self):
        self.assertEqual(agent.request(b'{"id":0,"action":"status","params":{}}\n')["action"], "status")
        for raw in (b'{"id":0,"id":1,"action":"status","params":{}}\n',
                    b'{"id":true,"action":"status","params":{}}\n',
                    b'{"id":0,"action":"status","params":{}}', b'{}\n', b'x' * (agent.MAX_REQUEST + 1)):
            with self.subTest(raw=raw[:70]), self.assertRaises(ValueError):
                agent.request(raw)

    def test_public_status_preserves_agreement_and_floors_without_key_inventory(self):
        value = {"phase": "running", "ready": True, "scope": agent.SCOPE,
                 "nodes": [{"height": 3, "tip": "aa" * 32, "utxo_hash": "bb" * 32}],
                 "wallet": {"wallet_id": "cc" * 16, "next_receive": 12, "next_change": 20,
                            "addresses": [{"public_key": "synthetic"}] * 12, "utxos": [1, 2]}}
        compact = agent.compact_status(value)
        self.assertEqual(compact["nodes"], value["nodes"])
        self.assertEqual(compact["wallet"]["next_change"], 20)
        self.assertEqual(compact["wallet"]["addresses_count"], 12)
        self.assertEqual(compact["wallet"]["utxos_count"], 2)
        self.assertNotIn("addresses", compact["wallet"])

    def test_response_recursively_refuses_operator_or_ciphertext_fields(self):
        for key in ("password", "passphrase", "secret", "ciphertext", "operator_input"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                agent.public_result({"nested": [{key: "public-unit-test-marker"}]})
        self.assertEqual(agent.public_result({"txid": "aa" * 32}), {"txid": "aa" * 32})


if __name__ == "__main__":
    unittest.main()
