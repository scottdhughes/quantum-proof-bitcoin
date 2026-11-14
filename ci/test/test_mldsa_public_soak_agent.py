"""Control framing and public-only reporting for the two-host soak agent."""
import importlib.util
from pathlib import Path
import unittest
import os
import time
import threading
import json
import tempfile
import subprocess
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / "contrib/ml-dsa-qualification/public_soak_agent.py"
SPEC = importlib.util.spec_from_file_location("public_soak_agent_tests", PATH)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class PublicSoakAgentTests(unittest.TestCase):
    def bridge_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name)
        manager = SimpleNamespace(docker=["unit-docker-must-not-run"], container="pqbtc-mldsa-public-unit",
                                  inspect=lambda: {"Id": "ab" * 32, "State": {"Running": True, "StartedAt": "unit-generation"}})
        value = agent.Agent(SimpleNamespace(manager=manager), state, time.time() + 120)
        params = {"hostname": "public.example.org", "public_ips": ["1.1.1.1"], "port": 443,
                  "until_utc": datetime.fromtimestamp(time.time() + 60, timezone.utc).isoformat()}
        processes = []
        original_popen, real_clock, real_sleep = subprocess.Popen, time.monotonic, time.sleep

        def cleanup():
            for child in processes:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=3)
            if value.bridge_log is not None:
                value.bridge_log.close()
        self.addCleanup(cleanup)

        def spawn(mode, command, **kwargs):
            ready = {"event": "bridge_started", "hostname": params["hostname"], "loopback_port": 23834,
                     "public_ips": params["public_ips"], "until_utc": params["until_utc"]}
            if mode == "wrong_host": ready["hostname"] = "foreign.example.org"
            if mode == "wrong_port": ready["loopback_port"] = 23835
            if mode == "float_port": ready["loopback_port"] = 23834.0
            if mode == "wrong_ips": ready["public_ips"] = ["8.8.8.8"]
            if mode == "wrong_deadline": ready["until_utc"] = "2000-01-01T00:00:00+00:00"
            script = '''import json,os,pathlib,sys,time
print(json.dumps({'bridge_pid':os.getpid(),'instance_id':sys.argv[1]}),flush=True)
mode=sys.argv[2]
if mode=='exit': sys.exit(7)
if mode=='gated':
 while not pathlib.Path(sys.argv[4]).exists(): time.sleep(.01)
if mode=='no_ready': time.sleep(30)
elif mode=='malformed': print('{not-json',flush=True)
elif mode=='oversize': print('x'*4097,flush=True)
elif mode=='log_flood': print('x'*9000,flush=True)
elif mode=='duplicate': print('{"event":"bridge_started","event":"bridge_started"}',flush=True)
else: print(sys.argv[3],flush=True)
if mode=='ready_exit': sys.exit(7)
time.sleep(30)
'''
            child = original_popen([sys.executable, "-u", "-c", script,
                                    command[command.index("--instance-id") + 1], mode, json.dumps(ready), str(state / "ready-gate")],
                                   **kwargs)
            processes.append(child)
            # Ensure the real child has published its PID before a controlled
            # test clock can consume the whole readiness deadline.
            deadline = real_clock() + 2
            while real_clock() < deadline:
                with next(state.glob("public-transport-*.jsonl")).open("rb") as log:
                    if log.readline().endswith(b"\n"):
                        break
                real_sleep(.005)
            else:
                self.fail("Unit bridge child did not publish its PID")
            if mode == "ready_exit":
                child.wait(timeout=2)
            return child

        # A real script launch adds this directory to sys.path automatically.
        self.enterContext(patch.object(sys, "path", [str(PATH.parent), *sys.path]))
        return value, params, state, processes, spawn

    def test_bridge_does_not_acknowledge_pid_until_matching_listener_readiness(self):
        value, params, state, processes, spawn = self.bridge_fixture()
        result, errors = [], []

        def start():
            try:
                result.append(value.bridge_start(params))
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=start, daemon=True)
        with patch.object(agent.subprocess, "Popen", side_effect=lambda command, **kwargs: spawn("gated", command, **kwargs)):
            worker.start()
            deadline = time.monotonic() + 2
            while value.bridge_pid is None and worker.is_alive() and time.monotonic() < deadline:
                time.sleep(.01)
            try:
                self.assertEqual(value.bridge_pid, processes[0].pid)
                self.assertTrue(worker.is_alive(), "The PID marker was acknowledged before listener readiness")
            finally:
                (state / "ready-gate").touch()
                worker.join(2)
        self.assertFalse(worker.is_alive())
        if errors:
            raise errors[0]
        self.assertTrue(result[0]["bridge_process_started"])

    def test_bridge_refuses_early_exit_or_invalid_readiness_and_retains_cleanup_pid(self):
        for mode in ("exit", "ready_exit", "malformed", "oversize", "log_flood", "duplicate",
                     "wrong_host", "wrong_port", "float_port", "wrong_ips", "wrong_deadline"):
            with self.subTest(mode=mode):
                value, params, _state, processes, spawn = self.bridge_fixture()
                with patch.object(agent.subprocess, "Popen", side_effect=lambda command, **kwargs: spawn(mode, command, **kwargs)):
                    with self.assertRaises(ValueError):
                        value.bridge_start(params)
                self.assertEqual(value.bridge_pid, processes[0].pid)

    def test_bridge_readiness_deadline_is_bounded_after_the_pid_marker(self):
        value, params, _state, processes, spawn = self.bridge_fixture()
        clock = [0.0]
        with patch.object(agent.subprocess, "Popen", side_effect=lambda command, **kwargs: spawn("no_ready", command, **kwargs)), \
             patch.object(agent.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(agent.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaisesRegex(ValueError, "readiness deadline"):
                value.bridge_start(params)
        self.assertGreaterEqual(clock[0], 15)
        self.assertLess(clock[0], 15.1)
        self.assertEqual(value.bridge_pid, processes[0].pid)

    def owned_manager(self, initialized=True):
        from public_controller import COMPATIBILITY
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name)
        name, identity, volume_id = "pqbtc-mldsa-public-unit", "ab" * 32, "ef" * 16
        retained = {"schema": "PQBTC-MLDSA44-PUBLIC-RUNTIME-1", "compatibility": COMPATIBILITY,
                    "container": name, "volume": name + "-data-v1", "volume_id": volume_id, "port": 23833,
                    "descriptor": {"image": "sha256:" + "11" * 32}, "history": []}
        if initialized:
            path = state / "public-runtime.json"
            path.write_text(json.dumps(retained), encoding="utf8")
            path.chmod(0o600)

        class Manager:
            container, volume = name, name + "-data-v1"
            state_dir = state
            current_identity = identity

            def __init__(self):
                self.calls = []
                self.inspection = {"Id": identity, "Name": "/" + name, "State": {"Running": True},
                                   "Image": "sha256:" + "11" * 32, "HostConfig": {"ReadonlyRootfs": True},
                                   "Config": {"Labels": {"org.pqbtc.console.schema": "public-test-1",
                                   "org.pqbtc.console.profile": agent.PROFILE, "org.pqbtc.console.build": "source-1"}},
                                   "Mounts": [{"Type": "volume", "Name": self.volume,
                                               "Destination": "/var/lib/pqbtc", "RW": True}]}
                self.marker = {"profile_sha256": agent.PROFILE, "volume_id": volume_id}

            def run(self, args, **kwargs):
                self.calls.append(args)
                if args[0] == "inspect":
                    return SimpleNamespace(returncode=0, stdout=json.dumps(self.inspection).encode(), stderr=b"")
                if args[0] == "exec":
                    if identity not in args:
                        raise AssertionError("Public marker was read through a reused container name")
                    return SimpleNamespace(returncode=0, stdout=json.dumps(self.marker).encode(), stderr=b"")
                if args[0] != "stop" or args[-1] != identity:
                    raise AssertionError("An unvalidated container identity was targeted")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        return Manager(), retained

    def test_fresh_state_cannot_stop_an_old_matching_public_container(self):
        manager, _ = self.owned_manager(initialized=False)
        agent.stop_owned_public(manager)
        self.assertFalse(any(args[0] == "stop" for args in manager.calls),
                         "Uninitialized state adopted an old matching project container")

    def test_changed_volume_marker_cannot_authorize_deadline_stop(self):
        manager, _ = self.owned_manager()
        manager.marker["volume_id"] = "99" * 16
        with self.assertRaises(ValueError):
            agent.stop_owned_public(manager)
        self.assertFalse(any(args[0] == "stop" for args in manager.calls))

    def test_deadline_stops_only_the_inspected_immutable_container_id(self):
        manager, _ = self.owned_manager()
        original = manager.run
        inspected = manager.current_identity
        replacement = "cd" * 32

        def run(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == "inspect":
                manager.current_identity = replacement  # The name is reused after inspection.
            return result

        manager.run = run
        agent.stop_owned_public(manager)
        self.assertEqual(manager.current_identity, replacement)
        self.assertEqual(manager.calls[-1], ["stop", "--time", "1", inspected])
        self.assertEqual(manager.calls[1][:4], ["exec", "--user", "1001:1000", inspected])

    def test_same_volume_pending_compatible_replacement_can_be_stopped(self):
        manager, retained = self.owned_manager()
        manager.inspection["Image"] = "sha256:" + "22" * 32
        manager.inspection["Config"]["Labels"]["org.pqbtc.console.manifest"] = "33" * 32
        self.assertNotEqual(manager.inspection["Image"], retained["descriptor"]["image"])
        agent.stop_owned_public(manager)
        self.assertEqual(manager.calls[-1], ["stop", "--time", "1", manager.current_identity])

    def test_foreign_mount_or_writable_root_cannot_supply_ownership_marker(self):
        for field in ("volume", "type", "destination", "extra", "root"):
            with self.subTest(field=field):
                manager, _ = self.owned_manager()
                mount = manager.inspection["Mounts"][0]
                if field == "volume":
                    mount["Name"] = "unrelated-volume"
                elif field == "type":
                    mount["Type"] = "bind"
                elif field == "destination":
                    mount["Destination"] = "/different"
                elif field == "extra":
                    manager.inspection["Mounts"].append(dict(mount))
                else:
                    manager.inspection["HostConfig"]["ReadonlyRootfs"] = False
                with self.assertRaisesRegex(ValueError, "mount"):
                    agent.stop_owned_public(manager)
                self.assertEqual([args[0] for args in manager.calls], ["inspect"])

    def test_malformed_or_foreign_retained_metadata_cannot_authorize_cleanup(self):
        for field in ("schema", "profile", "container", "volume", "volume_id", "mode", "symlink"):
            with self.subTest(field=field):
                manager, retained = self.owned_manager()
                path = manager.state_dir / "public-runtime.json"
                if field == "profile":
                    retained["compatibility"] = {**retained["compatibility"], "profile_sha256": "00" * 32}
                elif field == "mode":
                    path.chmod(0o644)
                elif field == "symlink":
                    path.rename(manager.state_dir / "retained-runtime.json")
                    path.symlink_to(manager.state_dir / "retained-runtime.json")
                else:
                    retained[field] = "invalid"
                if field not in ("mode", "symlink"):
                    path.write_text(json.dumps(retained), encoding="utf8")
                with self.assertRaises(ValueError):
                    agent.stop_owned_public(manager)
                self.assertEqual(manager.calls, [])

    def test_marker_unavailable_does_not_stop_or_claim_cleanup(self):
        manager, _ = self.owned_manager()
        original = manager.run

        def run(args, **kwargs):
            if args[0] == "exec":
                manager.calls.append(args)
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"Cannot connect to the Docker daemon")
            return original(args, **kwargs)

        manager.run = run
        with self.assertRaisesRegex(ValueError, "marker"):
            agent.stop_owned_public(manager)
        self.assertFalse(any(args[0] == "stop" for args in manager.calls))

    def test_original_offline_wallet_name_is_never_a_deadline_target(self):
        manager, _ = self.owned_manager()
        manager.container = "pqbtc-mldsa-local"
        with self.assertRaisesRegex(ValueError, "namespace"):
            agent.stop_owned_public(manager)
        self.assertEqual(manager.calls, [])

    def test_docker_unavailable_is_not_misreported_as_no_running_node(self):
        manager, _ = self.owned_manager()
        class Result:
            returncode = 1
            stderr = b"Cannot connect to the Docker daemon"
        manager.run = lambda *_args, **_kwargs: Result()
        with self.assertRaisesRegex(ValueError, "liveness"):
            agent.stop_owned_public(manager)

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
        manager, _ = self.owned_manager()
        manager.inspection["Config"]["Labels"]["org.pqbtc.console.schema"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "ownership"):
            agent.stop_owned_public(manager)
        self.assertEqual([args[0] for args in manager.calls], ["inspect"])

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
