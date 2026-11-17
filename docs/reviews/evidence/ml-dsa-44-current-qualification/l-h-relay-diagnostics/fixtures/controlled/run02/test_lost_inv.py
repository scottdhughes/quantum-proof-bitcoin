#!/usr/bin/env python3
"""No Docker/native execution: parser, orchestration, ownership and redaction tests."""
import ast
import copy
import hashlib
import json
import importlib
from pathlib import Path
import struct
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import inv_proxy as proxy
import lost_inv as run
import native_rpc


def extracted_client_script():
    if hasattr(run, "CONTROL_CLIENT_SCRIPT"):
        return run.CONTROL_CLIENT_SCRIPT
    tree = ast.parse(Path(run.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if "socket.AF_UNIX" in node.value.value and "sys.stdout.buffer.write(data)" in node.value.value:
                return node.value.value
    raise AssertionError("control adapter script missing")


class ControlAdapterTests(unittest.TestCase):
    def proxy_adapter(self, value):
        tree = ast.parse(Path(run.__file__).read_text())
        parent = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        node = next(node for node in parent.body if isinstance(node, ast.FunctionDef) and node.name == "proxy")
        namespace = dict(vars(run))
        namespace["controllers"] = [None, SimpleNamespace(_invoke=lambda *args, **kwargs: json.dumps(value).encode())]
        exec(compile(ast.Module(body=[node], type_ignores=[]), "actual_proxy_adapter", "exec"), namespace)
        return namespace["proxy"]

    def test_stop_accepts_live_proxy_before_first_connection(self):
        value = {"ok": True, "active_connections": 0, "connections": 0, "dropped": []}
        self.assertEqual(self.proxy_adapter(value)("stop", run.time.monotonic() + 2), value)

    def test_connected_status_refuses_zero_connections(self):
        value = {"ok": True, "active_connections": 0, "connections": 0, "dropped": []}
        with self.assertRaises(run.Refused):
            self.proxy_adapter(value)("status", run.time.monotonic() + 2)

    def test_preconnect_status_accepts_zero_but_arm_still_refuses(self):
        value = {"ok": True, "active_connections": 0, "connections": 0, "dropped": []}
        self.assertEqual(self.proxy_adapter(value)("status", run.time.monotonic() + 2, connected=False), value)
        with self.assertRaises(run.Refused):
            self.proxy_adapter(value)("arm", run.time.monotonic() + 2, connected=False)

    def test_finish_proxy_zero_connections_observes_natural_exit_zero(self):
        calls = []
        class Process:
            returncode = None
            def poll(self):
                return self.returncode
            def communicate(self, *, timeout):
                calls.append(("communicate", timeout))
                self.returncode = 0
                return b"", b""
        def request(op, deadline, *, connected):
            calls.append((op, connected))
            return run.validate_proxy_response({"ok": True, "active_connections": 0, "connections": 0}, op, connected=connected)
        self.assertEqual(run.finish_proxy(Process(), request), {"returncode": 0, "stopped_cleanly": True})
        self.assertEqual(calls, [("stop", False), ("communicate", 5)])

    def request(self, response):
        # Generic host Python + disposable Unix socket only; no native node or Docker.
        with tempfile.TemporaryDirectory(prefix="li-", dir="/tmp") as directory:
            path = str(Path(directory) / "s")
            seen = []
            server = socket.socket(socket.AF_UNIX)
            server.bind(path)
            server.listen(1)
            server.settimeout(2)
            def answer():
                try:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(1)
                        seen.append(connection.recv(513))
                        try:
                            connection.sendall(response)
                        except BrokenPipeError:
                            pass
                finally:
                    server.close()
            thread = threading.Thread(target=answer)
            thread.start()
            result = subprocess.run([sys.executable, "-B", "-c", extracted_client_script(), path, "0.5"],
                                    input=b'{"op":"status"}\n', capture_output=True, timeout=2)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(seen, [b'{"op":"status"}\n'])
            return result

    def test_real_unix_socket_lf_response_succeeds(self):
        response = b'{"ok":true}\n'
        result = self.request(response)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, response)

    def test_eof_truncation_and_oversize_response_are_refused(self):
        for response in (b"", b'{"ok":true}', b"x" * 32769 + b"\n"):
            self.assertNotEqual(self.request(response).returncode, 0)

    def test_proxy_startup_real_unix_socket_has_mode_600_without_tcp(self):
        # Execute actual serve initialization with a real Unix socket, a fake TCP
        # listener, and a fake selector. No TCP/P2P listener or native code runs.
        class StartupComplete(Exception):
            pass
        class FakeTCP:
            def __getattr__(self, name):
                return lambda *args: None
        real_socket, actual_uid = socket.socket, run.os.geteuid()
        sockets, uid_calls, ready = [], [], []
        def create(family=socket.AF_INET, *args, **kwargs):
            sock = real_socket(family, *args, **kwargs) if family == socket.AF_UNIX else FakeTCP()
            sockets.append(sock)
            return sock
        def uid():
            uid_calls.append(True)
            return 1001 if len(uid_calls) == 1 else actual_uid
        with tempfile.TemporaryDirectory(prefix="li-", dir="/tmp") as directory:
            path = str(Path(directory) / "control")
            class Selector:
                def register(self, *args):
                    pass
                def select(self, timeout):
                    ready.append(stat.S_IMODE(run.os.lstat(path).st_mode))
                    raise StartupComplete()
                def close(self):
                    pass
            mask = run.os.umask(0o022)
            try:
                with patch.object(proxy.socket, "socket", side_effect=create), patch.object(proxy.os, "geteuid", side_effect=uid), \
                     patch.object(proxy.selectors, "DefaultSelector", return_value=Selector()):
                    with self.assertRaises(StartupComplete):
                        proxy.serve(path)
                self.assertEqual(ready, [0o600])
            finally:
                run.os.umask(mask)
                for sock in sockets:
                    sock.close()


def frame(command, payload=b""):
    return proxy.MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + proxy.checksum(payload) + payload


def inv(kind=5, digest="12" * 32):
    return b"\x01" + struct.pack("<I", kind) + bytes.fromhex(digest)[::-1]


class ParserTests(unittest.TestCase):
    def test_incremental_and_multiple_frames(self):
        wire = frame("ping", b"12345678") + frame("inv", inv()) + frame("pong", b"abcdefgh")
        parser = proxy.Framer()
        output = []
        for byte in wire:
            output.extend(parser.feed(bytes([byte])))
        self.assertEqual([row[0] for row in output], ["ping", "inv", "pong"])
        self.assertEqual(b"".join(row[2] for row in output), wire)
        self.assertEqual(parser.buffer, b"")

    def test_bad_magic_checksum_and_command(self):
        for wire in (b"xxxx" + frame("ping")[4:], frame("ping", b"x")[:-1] + b"y",
                     frame("ping")[:4] + b"pi\0ng".ljust(12, b"\0") + frame("ping")[16:]):
            with self.assertRaises(ValueError):
                proxy.Framer().feed(wire)

    def test_payload_and_incremental_buffer_bound(self):
        header = frame("tx")[:16] + struct.pack("<I", proxy.MAX_PAYLOAD + 1) + b"1234"
        with self.assertRaisesRegex(ValueError, "PAYLOAD_BOUND"):
            proxy.Framer().feed(header)
        parser = proxy.Framer()
        with self.assertRaisesRegex(ValueError, "BUFFER_BOUND"):
            parser.feed(b"x" * (proxy.MAX_BUFFER + 1))

    def test_compactsize_shape_and_canonical_count(self):
        self.assertEqual(proxy.inventory(inv()), [(5, "12" * 32)])
        self.assertEqual(proxy.inventory(b"\0"), [])
        for bad in (b"", b"\xfd", b"\xfd\x01\x00" + inv()[1:], b"\x01", b"\x00x",
                    b"\xfe\x01\x00\x00\x00", b"\xff" + b"\xff" * 8):
            with self.assertRaises(ValueError):
                proxy.inventory(bad)

    def test_drop_exactly_once_sender_single_transaction(self):
        loss = proxy.DropOnce()
        loss.arm()
        self.assertTrue(loss.forward("receiver_to_sender", "inv", inv()))
        self.assertTrue(loss.forward("sender_to_receiver", "inv", inv(2)))
        self.assertTrue(loss.forward("sender_to_receiver", "inv", b"\x02" + inv()[1:] * 2))
        self.assertFalse(loss.forward("sender_to_receiver", "inv", inv()))
        self.assertTrue(loss.forward("sender_to_receiver", "inv", inv()))
        self.assertEqual(loss.status()["dropped"][0]["hash"], "12" * 32)
        self.assertEqual(len(loss.dropped), 1)
        with self.assertRaises(ValueError):
            loss.arm()

    def test_msg_tx_supported_and_hash_targeting(self):
        loss = proxy.DropOnce()
        loss.arm()
        self.assertFalse(loss.forward("sender_to_receiver", "inv", inv(1)))
        run.target_matches(loss.dropped, {"txid": "12" * 32, "wtxid": "34" * 32})
        with self.assertRaises(run.Refused):
            run.target_matches(loss.dropped, {"txid": "56" * 32})
        with self.assertRaises(run.Refused):
            run.target_matches(loss.dropped * 2, {"txid": "12" * 32})

    def test_control_exact_bound_and_allowlist(self):
        self.assertEqual(proxy.parse_control(b'{"op":"arm"}\n'), "arm")
        self.assertEqual(proxy.parse_control(b'{"op":"status"}\n'), "status")
        for bad in (b'{"op":"arm"}', b'{"op":"arm","op":"status"}\n', b'{"op":"arm","token":"private"}\n',
                    b'{"op":"restart"}\n', b'{"op":false}\n', b"x" * 513 + b"\n", b"\xff\n"):
            with self.assertRaises(ValueError):
                proxy.parse_control(bad)

    def test_control_requires_socket_owner_and_mode(self):
        with patch.object(proxy.os, "lstat", return_value=SimpleNamespace(st_mode=0o140600, st_uid=123)), \
             patch.object(proxy.os, "geteuid", return_value=123):
            proxy.control_permissions("unused")
        with patch.object(proxy.os, "lstat", return_value=SimpleNamespace(st_mode=0o140666, st_uid=123)), \
             patch.object(proxy.os, "geteuid", return_value=123):
            with self.assertRaises(ValueError):
                proxy.control_permissions("unused")

    def test_message_counter_cardinality_bound(self):
        loss = proxy.DropOnce()
        for i in range(128):
            self.assertTrue(loss.forward("sender_to_receiver", str(i), b""))
        with self.assertRaisesRegex(ValueError, "COUNT_BOUND"):
            loss.forward("sender_to_receiver", "new", b"")


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += max(0, seconds)


class FakeTrace:
    def __init__(self):
        self.events = []

    def event(self, event, **data):
        self.events.append({"event": event, **data})


class FakeOps:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.tx = {"txid": "12" * 32, "wtxid": "34" * 32, "raw_transaction_sha256": "56" * 32}
        self.issued = [{"next_receive": 1, "next_change": 2}]

    def ready(self, deadline):
        self.calls.append("ready")
        return [1, 2]

    def arm(self, deadline):
        self.calls.append("arm")

    def send(self, deadline):
        self.calls.append("send")
        self.issued[0]["next_change"] += 1
        return self.tx

    def txmeta(self, txid, deadline):
        return self.tx

    def floors(self):
        return copy.deepcopy(self.issued)

    def proxy(self, deadline):
        return {"dropped": [{"type": 5, "hash": self.tx["wtxid"]}]}

    def present(self, txid, deadline):
        self.clock.value += 0.001
        return False

    def pings(self, ids, deadline):
        self.calls.append("ping")
        self.clock.value += 0.001
        return []

    def reannounce(self, txid, deadline):
        self.calls.append("reannounce")
        return {"raw_transaction_sha256": self.tx["raw_transaction_sha256"], "reissued_payment": False}


class FlowTests(unittest.TestCase):
    def phase(self, ops, clock):
        trace = FakeTrace()
        with patch.object(run.time, "monotonic", clock.now), patch.object(run.time, "sleep", clock.sleep):
            result = run.payment_phase(ops, trace)
        return result, trace

    def test_original_60_seconds_one_send_five_known_reannouncements(self):
        clock = FakeClock()
        ops = FakeOps(clock)
        result, trace = self.phase(ops, clock)
        self.assertEqual(clock.value, 160)
        self.assertEqual(ops.calls.count("send"), 1)
        self.assertEqual(ops.calls.count("arm"), 1)
        self.assertEqual(ops.calls.count("reannounce"), 5)
        self.assertEqual(ops.calls.count("ping"), 10)
        self.assertEqual(result[2], [1, 2])
        times = [e["elapsed_seconds"] for e in trace.events if e["event"] == "same_connection_same_known_rebroadcast"]
        self.assertTrue(all(10 * i <= elapsed < 10 * i + 0.2 for i, elapsed in enumerate(times, 1)))

    def test_ambiguous_reannouncement_is_not_retried(self):
        clock = FakeClock()
        ops = FakeOps(clock)
        def fail(txid, deadline):
            ops.calls.append("ambiguous")
            raise OSError("PRIVATE DETAIL MUST NOT BE LOGGED")
        ops.reannounce = fail
        with self.assertRaises(OSError):
            self.phase(ops, clock)
        self.assertEqual(ops.calls.count("send"), 1)
        self.assertEqual(ops.calls.count("ambiguous"), 1)

    def test_floor_change_or_recipient_delivery_refuses_baseline(self):
        for mode in ("floor", "received"):
            clock = FakeClock()
            ops = FakeOps(clock)
            if mode == "floor":
                def changed(txid, deadline):
                    ops.issued[0]["next_receive"] += 1
                    return False
                ops.present = changed
            else:
                ops.present = lambda *args: True
            with self.assertRaises(run.Refused):
                self.phase(ops, clock)

    def test_fresh_ping_requires_new_counters_and_no_pending_ping(self):
        clock = FakeClock()
        row = {"id": 7, "transport": "v1", "ping_sent": 32, "pong_received": 32, "ping_pending": False}
        calls = []
        def rpc(op, deadline):
            calls.append(op)
            if op == "ping":
                return {}
            value = dict(row)
            if calls.count("peers") >= 3:
                value.update(ping_sent=64, pong_received=64)
            return {"peers": [value]}
        with patch.object(run.time, "monotonic", clock.now), patch.object(run.time, "sleep", clock.sleep):
            value = run.fresh_ping(rpc, 7, 101)
            self.assertGreater(value["pong_received_after"], value["pong_received_before"])
            with self.assertRaises(run.Refused):
                run.fresh_ping(lambda *args: {"peers": [dict(row, ping_pending=True)]}, 7, 100.2)


class RPCAndGuardTests(unittest.TestCase):
    def test_failure_evidence_keeps_only_static_refused_guard_labels(self):
        self.assertEqual(run.failure_evidence(run.Refused("PROXY_START"), "proxy_ready"),
                         {"failure_stage": "proxy_ready", "error_class": "Refused", "guard_label": "PROXY_START"})
        for error in (ValueError("PRIVATE DETAIL"), OSError("PRIVATE DETAIL"), run.Refused("PRIVATE DETAIL"), run.Refused(["PRIVATE DETAIL"])):
            value = run.failure_evidence(error, "PRIVATE STAGE")
            self.assertNotIn("PRIVATE", json.dumps(value))
            self.assertNotIn("guard_label", value)
            self.assertEqual(value["failure_stage"], "unknown_stage")

    def test_all_literal_refused_labels_are_allowlisted(self):
        tree = ast.parse(Path(run.__file__).read_text())
        labels = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("require", "Refused"):
                index = 1 if node.func.id == "require" else 0
                if len(node.args) > index and isinstance(node.args[index], ast.Constant) and type(node.args[index].value) is str:
                    labels.add(node.args[index].value)
        self.assertTrue(labels <= run.SAFE_GUARDS)

    def test_native_rpc_forces_v1_and_returns_no_sensitive_fields(self):
        calls = []
        rpc = SimpleNamespace(addnode=lambda *args: calls.append(args),
                              getpeerinfo=lambda: [{"id": 7, "addr": "1.2.3.4:23834", "transport_protocol_type": "v1",
                                                   "version": 70016, "relaytxes": True, "PRIVATE": "secret",
                                                   "bytessent_per_msg": {"ping": 32}, "bytesrecv_per_msg": {"pong": 32}}])
        node = SimpleNamespace(rpc=lambda **kwargs: rpc)
        native_rpc.dispatch(node, {"op": "connect", "endpoint": "1.2.3.4:23834", "timeout": 1})
        self.assertEqual(calls, [("1.2.3.4:23834", "onetry", False)])
        value = native_rpc.dispatch(node, {"op": "peers", "timeout": 1})
        self.assertNotIn("secret", json.dumps(value))
        self.assertEqual(value["peers"][0]["transport"], "v1")

    def test_native_txmeta_returns_hashes_only(self):
        txid = "12" * 32
        rpc = SimpleNamespace(getrawtransaction=lambda *args: "abcd", decoderawtransaction=lambda raw: {"txid": txid, "hash": "34" * 32})
        value = native_rpc.dispatch(SimpleNamespace(rpc=lambda **kwargs: rpc), {"op": "txmeta", "txid": txid, "timeout": 1})
        self.assertEqual(set(value), {"txid", "wtxid", "raw_transaction_sha256"})
        self.assertEqual(value["raw_transaction_sha256"], hashlib.sha256(bytes.fromhex("abcd")).hexdigest())

    def test_rpc_rejects_arbitrary_methods_and_unknown_members(self):
        for value in ({"op": "stop", "timeout": 1}, {"op": "peers", "timeout": 1, "cookie": "secret"},
                      {"op": "connect", "timeout": 1, "endpoint": "1.2.3.4:23833"}):
            with self.assertRaises(ValueError):
                native_rpc.dispatch(SimpleNamespace(rpc=lambda **kwargs: SimpleNamespace()), value)

    def test_cleanup_targets_immutable_owned_id_and_retains_volume(self):
        identity = "ab" * 32
        calls = []
        value = {"Id": identity, "Name": "/" + run.NAMES[0], "Image": run.IMAGE, "State": {"Running": True, "Pid": 999}}
        manager = SimpleNamespace(container=run.NAMES[0], volume=run.NAMES[0] + "-data-v1", port=run.PORTS[0],
                                  layout=lambda item: None, inspect=lambda: value)
        def invoke(args, **kwargs):
            calls.append(args)
            if args[0] == "stop":
                value["State"] = {"Running": False, "Pid": 0}
            return SimpleNamespace(stdout=json.dumps({"Name": manager.volume, "Labels": {"test": "owned"}}).encode())
        manager.run = invoke
        controller = SimpleNamespace(manager=manager)
        with patch.object(run, "engine_guard"), patch.dict(sys.modules, {"public_controller": SimpleNamespace(LABELS={"test": "owned"})}):
            proof = run.stop_owned(controller, identity)
            self.assertEqual(calls[0], ["stop", "--time", "5", identity])
            self.assertTrue(proof["volume_retained"])
            with self.assertRaises(run.Refused):
                run.stop_owned(controller, "cd" * 32)
        self.assertFalse(any("rm" in call or "prune" in call for call in calls))

    def test_ownership_refuses_other_namespace_port_and_image(self):
        identity = "ab" * 32
        value = {"Id": identity, "Name": "/" + run.NAMES[0], "Image": run.IMAGE}
        manager = SimpleNamespace(container=run.NAMES[0], volume=run.NAMES[0] + "-data-v1", port=run.PORTS[0], layout=lambda value: None)
        controller = SimpleNamespace(manager=manager)
        for field, invalid in (("container", "pqbtc-mldsa-local"), ("port", 8844), ("volume", "original-data")):
            old = getattr(manager, field)
            setattr(manager, field, invalid)
            with self.assertRaises(run.Refused):
                run.ownership_guard(value, controller, identity)
            setattr(manager, field, old)
        with self.assertRaises(run.Refused):
            run.ownership_guard(dict(value, Image="sha256:" + "00" * 32), controller, identity)
        with self.assertRaises(run.Refused):
            run.ownership_guard(dict(value, Name="/unrelated"), controller, identity)

    def test_exact_frozen_source_and_descriptor_read_only(self):
        self.assertEqual(run.source_guard()["image"], run.IMAGE)

    def test_changed_source_and_other_engine_are_refused(self):
        with patch.object(run, "command", return_value=SimpleNamespace(returncode=0, stdout=b"different")):
            with self.assertRaises(run.Refused):
                run.source_guard()
        with patch.dict(run.os.environ, {"DOCKER_CONTEXT": run.CONTEXT}), \
             patch.object(run, "command", return_value=SimpleNamespace(returncode=0, stdout=b'"other-engine"')):
            with self.assertRaises(run.Refused):
                run.engine_guard()

    def test_host_requires_nonroot_macos(self):
        with patch.object(run.sys, "platform", "linux"):
            with self.assertRaises(run.Refused):
                run.host_guard()
        with patch.object(run.os, "geteuid", return_value=0):
            with self.assertRaises(run.Refused):
                run.host_guard()

    def test_host_rejects_occupied_loopback_port(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            with patch.object(run, "PORTS", (occupied.getsockname()[1],)):
                with self.assertRaisesRegex(run.Refused, "HOST_PORT_UNAVAILABLE"):
                    run.host_guard()

    def test_absence_probe_requires_exact_missing_object_error(self):
        name = run.NAMES[0]
        valid = SimpleNamespace(returncode=1, stdout=b"", stderr=("Error: No such object: " + name).encode())
        self.assertTrue(run.inspect_absent(valid, "container", name))
        for result in (SimpleNamespace(returncode=1, stdout=b"", stderr=b"Cannot connect to Docker daemon"),
                       SimpleNamespace(returncode=1, stdout=b"", stderr=b"Error: No such object: unrelated"),
                       SimpleNamespace(returncode=2, stdout=b"", stderr=valid.stderr),
                       SimpleNamespace(returncode=1, stdout=b'{"unexpected":true}', stderr=valid.stderr),
                       SimpleNamespace(returncode=0, stdout=b"", stderr=valid.stderr)):
            self.assertFalse(run.inspect_absent(result, "container", name))

    def test_bound_slot_refuses_changed_immutable_id_without_stop(self):
        calls = []
        name = run.NAMES[0]
        value = {"Id": "cd" * 32, "Name": "/" + name, "Image": run.IMAGE}
        def invoke(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), stderr=b"")
        manager = SimpleNamespace(container=name, volume=name + "-data-v1", port=run.PORTS[0], run=invoke, layout=lambda row: None)
        slot = run.OwnedSlot(SimpleNamespace(manager=manager))
        slot.identity = "ab" * 32
        with patch.object(run, "engine_guard"):
            with self.assertRaises(run.Refused):
                slot.stop()
        self.assertFalse(any(call[0] == "stop" for call in calls))

    def test_fsynced_trace_and_report_contain_public_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            trace = run.Trace(output)
            trace.event("target_broadcast_once", txid="12" * 32)
            run.os.close(trace.fd)
            value = json.loads(trace.path.read_text())
            self.assertEqual(value["txid"], "12" * 32)
            self.assertEqual(trace.path.stat().st_mode & 0o777, 0o600)
            run.write_json(output / "report.json", {"error": "DIAGNOSTIC_FAILED_NO_AMBIGUOUS_ACTION_RETRIED"})
            self.assertNotIn("PRIVATE DETAIL", (output / "report.json").read_text())


class StartupFailureTests(unittest.TestCase):
    def simulated_startup(self, *, invalid_layout=False, daemon_error=False, env_override=None):
        # All Docker calls are replaced. Actual PublicManager.layout validates the fake inspect object.
        sys.path.insert(0, str(run.SOURCE / "contrib/ml-dsa-console"))
        real_controls = importlib.import_module("public_controller")
        descriptor = json.loads(run.DESCRIPTOR.read_bytes())
        calls, controllers = [], []
        class Manager:
            container_labels = real_controls.PublicManager.container_labels
            layout = real_controls.PublicManager.layout

            def __init__(self, container, port):
                self.container, self.port, self.volume = container, port, container + "-data-v1"
                self.descriptor = descriptor
                self.value = None

            def ensure(self, selected):
                self.value = {"Id": "ab" * 32, "Name": "/" + self.container, "Image": run.IMAGE,
                              "Config": {"Labels": self.container_labels(), "Cmd": ["sleep", "infinity"], "User": ""},
                              "HostConfig": {"ReadonlyRootfs": not invalid_layout, "NetworkMode": "bridge", "Memory": 1073741824,
                                             "NanoCpus": 2000000000, "PidsLimit": 256, "CapDrop": ["ALL"], "CapAdd": None,
                                             "SecurityOpt": ["no-new-privileges"], "Privileged": False, "Tmpfs": real_controls.TMPFS,
                                             "RestartPolicy": {"Name": "unless-stopped"},
                                             "PortBindings": {"23833/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]}},
                              "Mounts": [{"Type": "volume", "Name": self.volume, "Destination": real_controls.DATA, "RW": True}],
                              "State": {"Running": True, "Pid": 777}}
                raise OSError("post-create marker probe failed")

            def inspect(self):
                return self.value

            def run(self, args, **kwargs):
                calls.append(args)
                if args[0] == "stop":
                    self.value["State"] = {"Running": False, "Pid": 0}
                if args[0] == "volume":
                    value = {"Name": self.volume, "Labels": real_controls.LABELS}
                else:
                    value = self.value
                return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), stderr=b"")

        class Controller:
            def __init__(self, state, selected, *, container, p2p_port):
                self.manager = Manager(container, p2p_port)
                self._worker = self._signer = None
                self.closed = False
                controllers.append(self)

            def close(self):
                self.closed = True

        fake_controls = SimpleNamespace(PublicController=Controller, LABELS=real_controls.LABELS)
        def probe(args, **kwargs):
            if daemon_error:
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"Cannot connect to Docker daemon")
            kind, target = args[1], args[-1]
            if kind == "container":
                error = "Error response from daemon: No such container: " + target
            else:
                error = "Error response from daemon: get " + target + ": no such volume"
            return SimpleNamespace(returncode=1, stdout=b"", stderr=error.encode() + b"\n")
        with tempfile.TemporaryDirectory(prefix="li-", dir="/tmp") as directory:
            here = Path(directory)
            environment = {"DOCKER_HOST": env_override} if env_override else {}
            with patch.object(run, "HERE", here), patch.object(run, "engine_guard"), patch.object(run, "source_guard", return_value=descriptor), \
                 patch.object(run, "command", side_effect=probe), patch.dict(sys.modules, {"public_controller": fake_controls}), \
                 patch.dict(run.os.environ, environment):
                report = run.run(here / "run-test")
        return report, controllers, calls

    def test_post_create_ensure_failure_stops_owned_id_and_proves_pid_zero(self):
        report, controllers, calls = self.simulated_startup()
        self.assertEqual([call for call in calls if call[0] == "stop"], [["stop", "--time", "5", "ab" * 32]])
        self.assertFalse(controllers[0].manager.value["State"]["Running"])
        self.assertEqual(controllers[0].manager.value["State"]["Pid"], 0)
        self.assertTrue(controllers[0].closed)
        self.assertTrue(report["retained_containers"][0]["volume_retained"])

    def test_post_create_wrong_layout_fails_closed_without_stop(self):
        report, controllers, calls = self.simulated_startup(invalid_layout=True)
        self.assertFalse(any(call[0] == "stop" for call in calls))
        self.assertTrue(controllers[0].manager.value["State"]["Running"])
        self.assertTrue(report["cleanup_errors"])

    def test_daemon_probe_error_refuses_before_controller_creation(self):
        with self.assertRaises(run.Refused):
            self.simulated_startup(daemon_error=True)

    def test_docker_host_override_refuses_before_context_or_creation(self):
        with self.assertRaises(run.Refused):
            self.simulated_startup(env_override="tcp://unrelated.example:2375")


if __name__ == "__main__":
    unittest.main()
