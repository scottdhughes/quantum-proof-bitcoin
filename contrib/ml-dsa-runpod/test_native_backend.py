#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Pure-Python ownership/transition tests; no native compilation or node launch."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import signal
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("tested_runpod_backend", HERE / "native_backend.py")
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
native = backend.native


def descriptor(version="c"):
    head, tree = backend.VERSIONS[version]
    digest = ("a" if version == "a3" else "b") * 64
    return {"schema": backend.SCHEMA, "version": version, "source_head": head, "source_tree": tree,
            "manifest_sha256": "c" * 64, "files": {name: digest for name in backend.REQUIRED}}


class DescriptorTests(unittest.TestCase):
    def test_frozen_versions_and_distinct_node_identities(self):
        old, new = descriptor("a3"), descriptor()
        self.assertEqual(backend.validate_descriptor(new), new)
        self.assertNotEqual(backend.payload_identity(old)["node_sha256"], backend.payload_identity(new)["node_sha256"])
        self.assertEqual(backend.payload_identity(new)["payload_sha256"], hashlib.sha256(backend.canonical(new)).hexdigest())

    def test_retarged_source_is_refused(self):
        value = descriptor()
        value["source_head"] = "0" * 40
        with self.assertRaises(Exception):
            backend.validate_descriptor(value)

    def test_missing_file_is_refused(self):
        value = descriptor()
        value["files"].pop("seed/demo-signer-bin/pilot-signer")
        with self.assertRaises(Exception):
            backend.validate_descriptor(value)

    def test_paths_and_unknown_fields_are_refused(self):
        for path in ("/etc/passwd", "seed/../outside", "seed//empty", "seed/./dot", "seed/back\\slash"):
            with self.subTest(path=path):
                value = descriptor()
                value["files"][path] = "0" * 64
                with self.assertRaises(Exception):
                    backend.validate_descriptor(value)
        value = descriptor()
        value["pretend_docker_id"] = "x"
        with self.assertRaises(Exception):
            backend.validate_descriptor(value)

    def test_identity_is_compact_and_separates_payload_from_provider(self):
        value = backend.payload_identity(descriptor())
        self.assertNotIn("files", value)
        self.assertNotIn("image", value)
        self.assertEqual(set(value), {"version", "source_head", "source_tree", "manifest_sha256", "payload_sha256", "node_sha256", "signer_sha256"})


class MetadataTests(unittest.TestCase):
    def test_atomic_private_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metadata.json"
            native.write_json(path, {"value": 1})
            native.write_json(path, {"value": 2})
            self.assertEqual(native.read_json(path), {"value": 2})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_symlink_and_duplicate_member_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text('{"x":1,"x":2}')
            target.chmod(0o600)
            with self.assertRaises(ValueError):
                native.read_json(target)
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaises(OSError):
                native.read_json(alias)
            with self.assertRaises(OSError):
                native.write_json(alias, {"safe": True})
            self.assertEqual(target.read_text(), '{"x":1,"x":2}')

    def test_registry_namespace_cannot_be_rebound(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            context = {"pid_namespace": "pid:[42]", "boot_id": "11111111-1111-1111-1111-111111111111"}
            with mock.patch.object(native, "execution_context", return_value=context):
                native.with_registry(path, "pqbtc-runpod-first", lambda value: None)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    native.with_registry(path, "pqbtc-runpod-other", lambda value: None)
            self.assertEqual(path.read_bytes(), before)


class ExecutionContextTests(unittest.TestCase):
    def test_changed_context_with_retained_processes_never_inspects_new_pids(self):
        first = {"pid_namespace": "pid:[42]", "boot_id": "11111111-1111-1111-1111-111111111111"}
        later = dict(first, pid_namespace="pid:[43]")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            with mock.patch.object(native, "execution_context", return_value=first):
                def add(value):
                    value["groups"].append({"role": "worker", "pid": 42, "start": "1234", "uid": 1001,
                                            "session": 42, "pgid": 42, "executables": ["/owned/node"],
                                            "wrapper": "/owned/native_exec.py", "pre_exec": None})
                native.with_registry(path, "pqbtc-runpod-context", add)
            before = path.read_bytes()
            with mock.patch.object(native, "execution_context", return_value=later), \
                 mock.patch.object(native, "proc_identity", side_effect=AssertionError("foreign PID inspected")):
                with self.assertRaisesRegex(ValueError, "context changed"):
                    native.registry(path, "pqbtc-runpod-context")
            self.assertEqual(path.read_bytes(), before)

    def test_clean_empty_registry_can_move_to_new_namespace_and_boot(self):
        first = {"pid_namespace": "pid:[42]", "boot_id": "11111111-1111-1111-1111-111111111111"}
        later = {"pid_namespace": "pid:[43]", "boot_id": "22222222-2222-2222-2222-222222222222"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            with mock.patch.object(native, "execution_context", return_value=first):
                native.with_registry(path, "pqbtc-runpod-context", lambda value: None)
            with mock.patch.object(native, "execution_context", return_value=later):
                native.with_registry(path, "pqbtc-runpod-context", lambda value: None)
            value = native.read_json(path)
            self.assertEqual(value["context"], later)
            self.assertEqual(value["previous_empty_contexts"], [first])
            self.assertEqual(value["groups"], [])


class ProcessProofTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executable = str(Path(os.sys.executable).resolve())

    def tearDown(self):
        self.temporary.cleanup()

    def process(self, pid, *, uid=1001, session=42, pgid=42, start="1234", executable=None, zombie=False):
        path = self.root / str(pid)
        path.mkdir()
        fields = ["Z" if zombie else "S", "1", str(pgid), str(session)] + ["0"] * 15 + [start, "0", "0"]
        (path / "stat").write_text(str(pid) + " (test worker) " + " ".join(fields))
        (path / "status").write_text("Uid:\t" + "\t".join([str(uid)] * 4) + "\nNoNewPrivs:\t1\n" +
                                     "\n".join(name + ":\t0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")) + "\n")
        if not zombie:
            (path / "exe").symlink_to(executable or self.executable)
        (path / "cmdline").write_bytes(b"python3\0owned.py\0")
        return path

    def record(self):
        return {"role": "worker", "pid": 42, "start": "1234", "uid": 1001, "session": 42,
                "pgid": 42, "executables": [self.executable], "wrapper": "/owned/native_exec.py", "pre_exec": None}

    def test_owned_parent_and_child_session_are_observed(self):
        self.process(42)
        self.process(43)
        self.process(44, session=44, pgid=44)
        members = native.verified_members(self.record(), proc=self.root)
        self.assertEqual([item["pid"] for item in members], [42, 43])
        self.assertTrue(all(item["uid"] == 1001 and item["no_new_privileges"] == 1 for item in members))

    def test_recycled_leader_is_refused(self):
        self.process(42, start="9999")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            native.verified_members(self.record(), proc=self.root)

    def test_unrelated_denied_executable_is_not_inspected(self):
        self.process(42)
        self.process(44, uid=102, session=44, pgid=44)
        original = native.proc_identity
        def inspect(pid, **kwargs):
            if pid == 44:
                raise PermissionError("unrelated provider executable")
            return original(pid, **kwargs)
        with mock.patch.object(native, "proc_identity", side_effect=inspect) as observed:
            self.assertEqual([v["pid"] for v in native.verified_members(self.record(), proc=self.root)], [42])
        self.assertNotIn(44, [call.args[0] for call in observed.call_args_list])

    def test_orphaned_child_retains_session_ownership(self):
        self.process(43)
        self.assertEqual([item["pid"] for item in native.verified_members(self.record(), proc=self.root)], [43])

    def test_unknown_uid_and_executable_are_refused(self):
        self.process(42)
        child = self.process(43, uid=1000)
        with self.assertRaisesRegex(ValueError, "unverified"):
            native.verified_members(self.record(), proc=self.root)
        (child / "status").write_text((self.root / "42/status").read_text())
        (child / "exe").unlink()
        (child / "exe").symlink_to("/bin/sh")
        with self.assertRaisesRegex(ValueError, "unverified"):
            native.verified_members(self.record(), proc=self.root)

    def test_privilege_regain_is_refused(self):
        path = self.process(42)
        (path / "status").write_text((path / "status").read_text().replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))
        with self.assertRaisesRegex(ValueError, "unverified"):
            native.verified_members(self.record(), proc=self.root)

    def test_zombie_leader_does_not_hide_live_child(self):
        self.process(42, zombie=True)
        self.process(43)
        self.assertEqual([item["pid"] for item in native.verified_members(self.record(), proc=self.root)], [43])

    def test_role_uid_pair_is_enforced(self):
        value = self.record()
        value["role"] = "signer"
        with self.assertRaises(ValueError):
            native.validate_record(value)


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.manager = backend.NativeManager(root / "control", versions_root=root / "versions",
                                             runtime_root=root / "runtime", data_root=root / "data")
        self.old, self.new = descriptor("a3"), descriptor()
        self.prior = {"schema": "PQBTC-RUNPOD-NATIVE-RUNTIME-1", "namespace": self.manager.namespace,
                      "volume_id": "1" * 32, "data_root": str(self.manager.data_root), "descriptor": self.old, "history": []}
        self.manager.verify_payload = backend.validate_descriptor
        self.selected = "a3"
        self.manager._selected = lambda: self.selected
        self.manager._select = lambda value: setattr(self, "selected", value["version"])

    def tearDown(self):
        self.temporary.cleanup()

    def pending(self):
        self.manager._write_json("native-replacement.json", {"schema": "PQBTC-RUNPOD-NATIVE-REPLACEMENT-1",
                                 "volume_id": self.prior["volume_id"], "previous": self.old, "candidate": self.new})

    def test_transition_preserves_data_and_records_genuine_binary_change(self):
        self.manager.ensure = lambda: copy.deepcopy(self.prior)
        self.manager.emergency_stop = mock.Mock(return_value={"stopped_native_processes": 0})
        self.manager.data_root.mkdir()
        sentinel = self.manager.data_root / "custody-not-a-real-key"
        sentinel.write_bytes(b"UNCHANGED TEST DATA")
        result = self.manager.upgrade(self.new)
        self.assertEqual(sentinel.read_bytes(), b"UNCHANGED TEST DATA")
        self.assertEqual(self.selected, "c")
        self.assertFalse(result["data_rollback"])
        self.assertFalse(result["outer_provider_image_changed"])
        self.assertNotEqual(result["previous_payload"]["node_sha256"], result["native_payload"]["node_sha256"])
        self.assertEqual(self.manager._read_json("native-runtime.json")["volume_id"], self.prior["volume_id"])

    def test_rollback_without_history_and_same_binary_are_refused(self):
        self.manager.ensure = lambda: copy.deepcopy(self.prior)
        with self.assertRaises(Exception):
            self.manager.upgrade(self.new, rollback=True)
        with self.assertRaises(Exception):
            self.manager.upgrade(self.old)

    def test_interrupted_candidate_selection_is_committed_without_data_restore(self):
        self.pending()
        self.selected = "c"
        value = self.manager._reconcile_transition(copy.deepcopy(self.prior))
        self.assertEqual(value["descriptor"], self.new)
        self.assertEqual(value["history"], [self.old])
        self.assertFalse((self.manager.state_dir / "native-replacement.json").exists())

    def test_interrupted_old_selection_retains_old_binary(self):
        self.pending()
        value = self.manager._reconcile_transition(copy.deepcopy(self.prior))
        self.assertEqual(value["descriptor"], self.old)
        self.assertEqual(value["history"], [])

    def test_unknown_selection_and_wrong_volume_are_preserved(self):
        self.pending()
        before = (self.manager.state_dir / "native-replacement.json").read_bytes()
        self.selected = "unowned"
        with self.assertRaises(Exception):
            self.manager._reconcile_transition(copy.deepcopy(self.prior))
        self.assertEqual((self.manager.state_dir / "native-replacement.json").read_bytes(), before)
        self.selected = "a3"
        prior = copy.deepcopy(self.prior)
        prior["volume_id"] = "2" * 32
        with self.assertRaises(Exception):
            self.manager._reconcile_transition(prior)


class CommandBindingTests(unittest.TestCase):
    def test_signer_default_uses_bound_data_path_but_preserves_explicit_recovery_path(self):
        class Base:
            def _start_signer(self, *args, **kwargs):
                self.received_path = kwargs["path"]
                return {"checkpoint": "DATA_ONLY"}
        bound = SimpleNamespace(DATA="/var/lib/pqbtc/attempt/data", SERVER="/owned/server")
        cls = type("BoundSignerTest", (backend._NativeControllerMethods, Base), {"_public_module": bound})
        value = object.__new__(cls)
        value._signer = SimpleNamespace(pid=42)
        kind = "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD"
        value._signer_info = {"pid": 42, "start": "1234", "proof_kind": kind, "pre_exec_sha256": "a" * 64}
        proof = {"pid": 42, "start": "1234", "uid": 1000, "proof_kind": kind, "sha256": "a" * 64}
        value.manager = SimpleNamespace(signer_execution_proof=lambda: proof)
        value._start_signer("FD_ONLY_TEST_PASSWORD")
        self.assertEqual(value.received_path, bound.DATA + "/signer/current")
        value._start_signer("FD_ONLY_TEST_PASSWORD", path="/owned/staged-recovery")
        self.assertEqual(value.received_path, "/owned/staged-recovery")

    def test_roles_register_worker_signer_and_bridge_without_docker(self):
        value = object.__new__(backend._NativeControllerMethods)
        value.manager = SimpleNamespace(registry_path=Path("/private/registry"), namespace="pqbtc-runpod-test",
                                        descriptor=descriptor())
        value._public_module = backend.public
        commands = [
            value._command("1001:1000", "python3", backend.public.SOURCE + "/contrib/ml-dsa-console/public_runtime.py"),
            value._command("1000:1000", "python3", "-c", "FD-ONLY-LAUNCHER", backend.public.SERVER),
            value._command("1001:1000", "python3", backend.public.SOURCE + "/contrib/ml-dsa-qualification/public_transport.py"),
        ]
        for command, role in zip(commands, ("worker", "signer", "bridge")):
            self.assertNotIn("docker", command)
            self.assertEqual(command[command.index("--role") + 1], role)
            self.assertIn("--registry", command)
        signer = commands[1]
        self.assertIn("--signer-fd-exec", signer)
        self.assertEqual(signer[signer.index("--expected-sha256") + 1], "b" * 64)
        self.assertEqual(signer[signer.index("--") + 1], backend.public.SERVER)
        self.assertNotIn("FD-ONLY-LAUNCHER", signer)
        with self.assertRaises(Exception):
            value._command("0:0", "python3")


class ImmutableSignerTests(unittest.TestCase):
    def record(self):
        return {"role": "signer", "pid": 42, "start": "1234", "uid": 1000, "session": 42, "pgid": 42,
                "executables": ["/owned/signer"], "wrapper": "/owned/native_exec.py",
                "pre_exec": {"sha256": "a" * 64, "path": "/owned/signer", "device": 1, "inode": 2, "size": 100}}

    def value(self):
        return {"pid": 42, "start": "1234", "uid": 1000, "session": 42, "pgid": 42,
                "zombie": False, "no_new_privileges": 1,
                "capabilities": {key: "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")}}

    def test_exact_verified_fd_survives_path_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "signer-ELF-DATA-only"
            raw = b"\x7fELF synthetic file DATA; never executed"
            path.write_bytes(raw)
            path.chmod(0o555)
            expected = hashlib.sha256(raw).hexdigest()
            fd, proof = native.immutable_exec_fd(path, expected, owner=os.geteuid())
            try:
                self.assertGreaterEqual(fd, 5)
                path.rename(path.with_suffix(".retained"))
                path.write_bytes(b"\x7fELF different DATA")
                with os.fdopen(os.dup(fd), "rb") as handle:
                    self.assertEqual(hashlib.file_digest(handle, "sha256").hexdigest(), expected)
                self.assertEqual(proof["sha256"], expected)
                self.assertEqual(proof["inode"], path.with_suffix(".retained").stat().st_ino)
            finally:
                os.close(fd)

    def test_wrong_digest_writable_file_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "signer-ELF-DATA-only"
            raw = b"\x7fELF DATA only"
            path.write_bytes(raw)
            path.chmod(0o555)
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                native.immutable_exec_fd(path, "0" * 64, owner=os.geteuid())
            path.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "file refused"):
                native.immutable_exec_fd(path, hashlib.sha256(raw).hexdigest(), owner=os.geteuid())
            alias = path.with_suffix(".link")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                native.immutable_exec_fd(alias, hashlib.sha256(raw).hexdigest(), owner=os.geteuid())

    def test_non_dumpable_proof_is_bound_to_immutable_launch_and_live_pidfd(self):
        fields = ["S", "1", "42", "42"] + ["0"] * 15 + ["1234", "0", "0"]
        with mock.patch.object(Path, "read_text", return_value="42 (signer) " + " ".join(fields)), \
             mock.patch.object(os, "pidfd_open", return_value=99, create=True) as opened, \
             mock.patch.object(signal, "pidfd_send_signal", create=True) as sent, \
             mock.patch.object(os, "close") as closed:
            value = native.signer_metadata_identity(self.value(), self.record())
        opened.assert_called_once_with(42)
        sent.assert_called_once_with(99, 0)
        closed.assert_called_once_with(99)
        self.assertEqual(value["pre_exec_sha256"], "a" * 64)
        self.assertTrue(value["pidfd_live"])
        self.assertFalse(value["post_exec_executable_observable"])
        self.assertNotIn("executable_sha256", value)
        self.assertNotIn("executable", value)

    def test_wrong_pid_start_uid_or_session_never_gets_hardened_fallback(self):
        for key, changed in (("pid", 43), ("start", "9999"), ("uid", 1001), ("session", 99)):
            value = self.value()
            value[key] = changed
            with self.subTest(key=key), mock.patch.object(os, "pidfd_open", create=True) as opened:
                with self.assertRaisesRegex(ValueError, "ownership proof mismatch"):
                    native.signer_metadata_identity(value, self.record())
                opened.assert_not_called()

    def test_signer_without_preexec_fd_record_is_refused(self):
        value = self.record()
        value["pre_exec"] = None
        with self.assertRaisesRegex(ValueError, "FD launch proof"):
            native.validate_record(value)


if __name__ == "__main__":
    unittest.main()
