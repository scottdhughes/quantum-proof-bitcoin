"""Pure filesystem/guard/admission tests; never invokes Docker or a native node."""
import hashlib
import ast
import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receiver_forensic", HERE / "research_receiver_clone.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def make_source(root):
    for name in ["blocks", "blocks/index", "chainstate"]:
        (root / name).mkdir(mode=0o700)
    for name, value in {"blocks/blk00000.dat": b"public block fixture", "blocks/rev00000.dat": b"public undo fixture",
                        "blocks/xor.dat": b"12345678", "blocks/index/CURRENT": b"MANIFEST-000001\n",
                        "blocks/index/MANIFEST-000001": b"public manifest", "blocks/index/000003.log": b"public DB WAL",
                        "chainstate/000004.ldb": b"public UTXO fixture", "chainstate/000005.log": b"public UTXO WAL",
                        "chainstate/LOCK": b"", "mempool.dat": b"public signed mempool"}.items():
        path = root / name
        path.write_bytes(value)
        path.chmod(0o600)
    for name in ["blocks/index/LOG", "blocks/index/LOG.old", "chainstate/LOG", ".cookie", "pqbtc.conf", "debug.log", "wallet.dat"]:
        p = root / name
        p.write_bytes(b"excluded fixture content")
        p.chmod(0o600)


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        make_source(self.source)
        self.dest = self.root / "clone"
        self.identity = {"uid": os.getuid(), "gid": os.getgid()}

    def tearDown(self):
        self.temporary.cleanup()

    def scan(self):
        return receiver.scan_public_tree(self.source, **self.identity)

    def test_public_blocks_utxo_mempool_and_internal_WAL_only(self):
        manifest = self.scan()
        names = [r["path"] for r in manifest["files"]]
        self.assertIn("blocks/index/000003.log", names)
        self.assertIn("chainstate/000005.log", names)
        self.assertIn("blocks/xor.dat", names)
        for path in ["blocks/index/LOG", "blocks/index/LOG.old", "chainstate/LOG", ".cookie", "debug.log", "wallet.dat", "pqbtc.conf"]:
            self.assertNotIn(path, names)
        copied = receiver.copy_public_tree(self.source, self.dest, **self.identity)
        self.assertEqual(copied["file_count"], 10)
        for entry in copied["files"]:
            self.assertEqual((self.source / entry["path"]).read_bytes(), (self.dest / entry["path"]).read_bytes())
            self.assertEqual(hashlib.sha256((self.dest / entry["path"]).read_bytes()).hexdigest(), entry["sha256"])
        self.assertFalse((self.dest / ".cookie").exists())
        self.assertFalse((self.dest / "chainstate/LOG").exists())

    def test_existing_clone_is_never_adopted_or_overwritten(self):
        self.dest.mkdir(mode=0o700)
        marker = self.dest / "retained"
        marker.write_bytes(b"retained")
        with self.assertRaisesRegex(receiver.Refusal, "NEW_DESTINATION"):
            receiver.copy_public_tree(self.source, self.dest, **self.identity)
        self.assertEqual(marker.read_bytes(), b"retained")

    def test_symlink_hardlink_special_file_and_unknown_path(self):
        p = self.source / "blocks/blk00000.dat"
        original = p.read_bytes()
        p.unlink()
        p.symlink_to(self.source / ".cookie")
        with self.assertRaises(receiver.Refusal):
            self.scan()
        p.unlink()
        os.link(self.source / "wallet.dat", p)
        with self.assertRaises(receiver.Refusal):
            self.scan()
        p.unlink()
        os.mkfifo(p, 0o600)
        with self.assertRaises(receiver.Refusal):
            self.scan()
        p.unlink()
        p.write_bytes(original)
        p.chmod(0o600)
        unknown = self.source / "blocks/unexpected.bin"
        unknown.write_bytes(b"unrecognized")
        unknown.chmod(0o600)
        with self.assertRaisesRegex(receiver.Refusal, "PUBLIC_PATH"):
            self.scan()

    def test_source_uid_mode_and_link_guards(self):
        with self.assertRaisesRegex(receiver.Refusal, "SOURCE_OWNER"):
            receiver.scan_public_tree(self.source, uid=os.getuid() + 1, gid=os.getgid())
        (self.source / "mempool.dat").chmod(0o644)
        with self.assertRaisesRegex(receiver.Refusal, "SOURCE_MODE"):
            self.scan()

    def test_file_count_and_total_bytes_bounds_precede_content_open(self):
        with mock.patch.object(receiver, "MAX_FILES", 1):
            with self.assertRaisesRegex(receiver.Refusal, "FILE_COUNT"):
                self.scan()

    def test_direct_relative_opener_rejects_escape_or_diagnostic_log(self):
        root_fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for parts in [("..", "wallet.dat"), ("blocks", "index", "LOG"), (".cookie",)]:
                with self.assertRaises(receiver.Refusal):
                    receiver.open_relative(root_fd, parts)
        finally:
            os.close(root_fd)
        with mock.patch.object(receiver, "MAX_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(receiver.Refusal, "TOTAL_BYTES"):
                self.scan()

    def test_single_file_size_bound_without_allocating_contents(self):
        with (self.source / "blocks/blk00000.dat").open("r+b") as f:
            f.truncate(receiver.MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(receiver.Refusal, "FILE_BYTES"):
            self.scan()

    def test_modified_source_after_copy_is_detected(self):
        original = receiver.copy_one
        changed = False

        def mutate(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                p = self.source / "mempool.dat"
                p.write_bytes(b"changed public fixture")
                changed = True
            return result
        with mock.patch.object(receiver, "copy_one", side_effect=mutate):
            with self.assertRaisesRegex(receiver.Refusal, "SOURCE_CHANGED"):
                receiver.copy_public_tree(self.source, self.dest, **self.identity)

    def test_private_log_is_not_opened_during_copy(self):
        original = os.open

        def guarded(path, flags, *args, **kwargs):
            if str(path).split("/")[-1] in ["LOG", "LOG.old", ".cookie", "pqbtc.conf", "wallet.dat", "debug.log"]:
                raise AssertionError("excluded fixture content must not be opened")
            return original(path, flags, *args, **kwargs)
        with mock.patch.object(receiver.os, "open", side_effect=guarded):
            receiver.copy_public_tree(self.source, self.dest, **self.identity)

    def test_empty_exact_process_lock_omitted_without_open_or_copy(self):
        lock = self.source / "blocks/.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        original = os.open

        def guarded(path, flags, *args, **kwargs):
            if str(path).split("/")[-1] == ".lock":
                raise AssertionError("process lock must never be opened or copied")
            return original(path, flags, *args, **kwargs)
        with mock.patch.object(receiver.os, "open", side_effect=guarded):
            copied = receiver.copy_public_tree(self.source, self.dest, **self.identity)
        self.assertFalse((self.dest / "blocks/.lock").exists())
        self.assertEqual(copied["file_count"], 10)
        omitted = copied["omitted_process_locks"]
        self.assertEqual(len(omitted), 1)
        self.assertEqual(omitted[0]["path"], "blocks/.lock")
        self.assertEqual(omitted[0]["bytes"], 0)
        self.assertIn("fresh lock", omitted[0]["reason"])
        self.assertNotIn("blocks/.lock", copied["omitted_diagnostic_logs"])

    def test_process_lock_nonempty_directory_symlink_hardlink_and_mode_refused(self):
        lock = self.source / "blocks/.lock"
        lock.write_bytes(b"nonempty")
        lock.chmod(0o600)
        with self.assertRaises(receiver.Refusal):
            self.scan()
        lock.unlink()
        lock.mkdir(mode=0o700)
        with self.assertRaises(receiver.Refusal):
            self.scan()
        lock.rmdir()
        lock.symlink_to(self.source / ".cookie")
        with self.assertRaises(receiver.Refusal):
            self.scan()
        lock.unlink()
        other = self.root / "empty fixture"
        other.write_bytes(b"")
        other.chmod(0o600)
        os.link(other, lock)
        with self.assertRaises(receiver.Refusal):
            self.scan()
        lock.unlink()
        lock.write_bytes(b"")
        lock.chmod(0o644)
        with self.assertRaisesRegex(receiver.Refusal, "SOURCE_MODE"):
            self.scan()

    def test_process_lock_wrong_uid_or_gid_refused(self):
        lock = self.source / "blocks/.lock"
        lock.write_bytes(b"")
        lock.chmod(0o600)
        original = os.stat
        for changed in ["st_uid", "st_gid"]:
            def wrong_owner(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == ".lock":
                    fields = {n: getattr(info, n) for n in ["st_mode", "st_uid", "st_gid"]}
                    fields[changed] += 1
                    return SimpleNamespace(**fields)
                return info
            with self.subTest(changed=changed), mock.patch.object(receiver.os, "stat", side_effect=wrong_owner):
                with self.assertRaisesRegex(receiver.Refusal, "SOURCE_OWNER"):
                    self.scan()

    def test_process_lock_omission_does_not_allow_nearby_names_or_other_directories(self):
        for rel in ["blocks/.lock.old", "chainstate/.lock", "blocks/index/.lock"]:
            lock = self.source / rel
            lock.write_bytes(b"")
            lock.chmod(0o600)
            with self.subTest(path=rel), self.assertRaisesRegex(receiver.Refusal, "PUBLIC_PATH_FILE"):
                self.scan()
            lock.unlink()


def good_context():
    return {"height": 408, "tip": receiver.EXPECTED_TIP, "utxo_hash": receiver.EXPECTED_UTXO,
            "utxo_count": 547, "network_active": False, "peer_count": 0, "mempool_size": 0}


class ResponseLostDocker:
    """Daemon create side effect succeeds; CLI never returns its response."""
    def __init__(self, mutate=None, absent=False):
        self.container_id = "c" * 64
        self.container = None
        self.calls = []
        self.mutate = mutate
        self.absent = absent

    def call(self, args, **_kwargs):
        self.calls.append(args)
        if args[0] == "create":
            self.container = receiver.expected_clone_identity(self.container_id)
            self.container["State"] = {"Running": True, "Pid": 7654}
            if self.mutate:
                self.mutate(self.container)
            raise subprocess.TimeoutExpired(["docker", "create"], 1)
        if args[:2] == ["container", "inspect"]:
            if self.absent or self.container is None:
                name = args[-1]
                return SimpleNamespace(returncode=1, stdout=b"\n",
                                       stderr=("error: no such object: " + name + "\n").encode())
            return SimpleNamespace(returncode=0, stdout=('"' + self.container_id + '"\n').encode(), stderr=b"")
        if args[0] == "stop":
            if args[-1] != self.container_id or args[-1] == receiver.SOURCE_ID:
                raise AssertionError("must stop only fully bound new ID")
            self.container["State"] = {"Running": False, "Pid": 0}
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError("unexpected fake Docker command")

    def value(self, args, **_kwargs):
        self.calls.append(args)
        if args[:2] != ["container", "inspect"]:
            raise AssertionError("selected readback only")
        if args[-1] != self.container_id:
            raise AssertionError("after lookup only the exact full ID may be inspected")
        return self.container


class NativeGuards(unittest.TestCase):
    def test_initializer_mode_then_owner_succeeds_with_CHOWN_without_FOWNER(self):
        tree = ast.parse((HERE / "research_receiver_clone.py").read_bytes())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "host_run")
        expression = next(n.value for n in fn.body if isinstance(n, ast.Assign) and
                          any(isinstance(t, ast.Name) and t.id == "init" for t in n.targets))

        def source(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return source(node.left) + source(node.right)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "repr" and \
                    len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == "BASE":
                return repr(receiver.BASE)
            raise AssertionError("Initializer must remain an explicit fixed program")
        program = ast.parse(source(expression))
        owner, mode, operations = 0, 0o755, []
        # Pure permission model: root has CHOWN only, without FOWNER/DAC.
        # The program is parsed, never executed; no filesystem owner is changed.
        for statement in program.body:
            if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)):
                continue
            call = statement.value
            if not (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and
                    call.func.value.id == "os" and call.func.attr in ["chmod", "chown"]):
                continue
            operations.append(call.func.attr)
            self.assertIsInstance(call.args[0], ast.Name)
            self.assertEqual(call.args[0].id, "p")
            if call.func.attr == "chmod":
                if owner != 0:
                    raise PermissionError("CHOWN-only root no longer owns the destination and lacks FOWNER")
                mode = ast.literal_eval(call.args[1])
            else:
                owner = ast.literal_eval(call.args[1])
                self.assertEqual(ast.literal_eval(call.args[2]), 1000)
        self.assertEqual(operations, ["chmod", "chown"])
        self.assertEqual((owner, mode), (1001, 0o700))

    def test_create_side_effect_then_timeout_is_discovered_and_stopped(self):
        docker = ResponseLostDocker()
        returned_id = None
        try:
            returned_id = docker.call(["create", "opaque-reviewed-layout"]).stdout.decode().strip()
        except subprocess.TimeoutExpired:
            pass
        result = receiver.cleanup_native(docker, returned_id)
        self.assertEqual(result.get("container_id"), docker.container_id)
        self.assertTrue(result["backend_stopped"])
        self.assertEqual(result["pid"], 0)
        stops = [args for args in docker.calls if args[0] == "stop"]
        self.assertEqual(stops, [["stop", "--time", "5", docker.container_id]])

    def test_create_response_loss_wrong_layout_never_stops_unrelated_container(self):
        mutations = [lambda c: c["Config"]["Labels"].update({"unexpected": "ownership"}),
                     lambda c: c["HostConfig"].update({"NetworkMode": "bridge"}),
                     lambda c: c["HostConfig"].update({"PidMode": "host"}),
                     lambda c: c["HostConfig"].update({"CgroupnsMode": "private"}),
                     lambda c: c["Mounts"][0].update({"Name": receiver.SOURCE_VOLUME}),
                     lambda c: c.update({"Name": "/" + receiver.SOURCE_CONTAINER})]
        for mutate in mutations:
            docker = ResponseLostDocker(mutate=mutate)
            try:
                docker.call(["create", "opaque-reviewed-layout"])
            except subprocess.TimeoutExpired:
                pass
            with self.assertRaises(receiver.Refusal):
                receiver.cleanup_native(docker, None)
            self.assertFalse(any(args[0] == "stop" for args in docker.calls))

    def test_unknown_id_absence_requires_actual_selected_missing_proof(self):
        docker = ResponseLostDocker(absent=True)
        result = receiver.cleanup_native(docker, None)
        self.assertTrue(result.get("absence_proved"))
        self.assertEqual(docker.calls[0], ["container", "inspect", "--format", "{{json .Id}}", receiver.CLONE_CONTAINER])

    def test_exact_chain_and_offline_context_required(self):
        receiver.validate_context(good_context())
        for key, value in [("height", 409), ("tip", "0" * 64), ("utxo_hash", "0" * 64),
                           ("utxo_count", 546), ("network_active", True), ("peer_count", 1)]:
            changed = good_context() | {key: value}
            with self.assertRaises(receiver.Refusal):
                receiver.validate_context(changed)

    def test_native_verdict_is_selected_and_cannot_emit_raw_payload(self):
        value = {"txid": receiver.TARGET_TXID, "allowed": False, "reject-reason": "missing-inputs",
                 "unknown-payload": "must not appear"}
        self.assertEqual(receiver.select_verdict(value), {"txid": receiver.TARGET_TXID,
                                                        "allowed": False, "reject-reason": "missing-inputs"})
        for changed in [value | {"txid": "0" * 64}, value | {"allowed": "yes"},
                        value | {"reject-reason": "ab" * 300}]:
            with self.assertRaises(receiver.Refusal):
                receiver.select_verdict(changed)

    def test_stop_finally_runs_after_native_admission_error(self):
        node = mock.Mock()
        with mock.patch.object(receiver, "collect_context", return_value=good_context()):
            node.rpc.return_value.testmempoolaccept.side_effect = RuntimeError("opaque")
            result = receiver.admit_with_node(node, b"fixture")
        node.start.assert_called_once_with(network_active=False)
        node.stop.assert_called_once()
        self.assertEqual(result["result"], "FAIL")
        self.assertNotIn("opaque", str(result))

    def test_successful_rejection_is_diagnostic_success_not_transaction_acceptance(self):
        node = mock.Mock()
        node.rpc.return_value.testmempoolaccept.return_value = [{"txid": receiver.TARGET_TXID,
                                                                "allowed": False, "reject-reason": "missing-inputs"}]
        with mock.patch.object(receiver, "collect_context", return_value=good_context()):
            result = receiver.admit_with_node(node, b"fixture")
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(result["native_verdict"]["allowed"])
        node.stop.assert_called_once()

    def test_stop_failure_marks_diagnostic_failure(self):
        node = mock.Mock()
        node.rpc.return_value.testmempoolaccept.return_value = [{"txid": receiver.TARGET_TXID, "allowed": True}]
        node.stop.side_effect = RuntimeError("must not disclose")
        with mock.patch.object(receiver, "collect_context", return_value=good_context()):
            result = receiver.admit_with_node(node, b"fixture")
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(result["node_stop_clean"])
        self.assertNotIn("must not disclose", str(result))

    def test_exact_raw_hash_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "public.raw"
            p.write_bytes(b"public signed bytes")
            p.chmod(0o600)
            with self.assertRaisesRegex(receiver.Refusal, "RAW_BINDING"):
                receiver.read_raw_transaction(p, uid=os.getuid(), gid=os.getgid())

    def test_actual_extracted_public_artifact_passes_exact_binding(self):
        p = HERE / "sender-extraction-20261117-02/pending-signed-transaction.raw"
        self.assertTrue(p.is_file(), "Root-extracted public signed artifact is required for this fixture test")
        data = receiver.read_raw_transaction(p, uid=os.getuid(), gid=os.getgid())
        self.assertEqual(len(data), 3878)
        self.assertEqual(hashlib.sha256(data).hexdigest(), receiver.TARGET_RAW_SHA)

    def test_exact_missing_proof_with_projected_empty_stdout(self):
        for kind, error in [("container", b"error: no such object: fresh-name\n"),
                            ("volume", b"Error response from daemon: get fresh-name: no such volume\n")]:
            receiver.require_missing(SimpleNamespace(returncode=1, stdout=b"\n", stderr=error), kind, "fresh-name")
        for value in [SimpleNamespace(returncode=0, stdout=b'"existing"', stderr=b""),
                      SimpleNamespace(returncode=1, stdout=b"", stderr=b"permission denied"),
                      SimpleNamespace(returncode=1, stdout=b"", stderr=b"error: no such object: other-name\n")]:
            with self.assertRaises(receiver.Refusal):
                receiver.require_missing(value, "container", "fresh-name")

    def test_empty_cap_add_serializations_are_equivalent(self):
        value = receiver.expected_clone_identity("b" * 64)
        value["HostConfig"]["CapAdd"] = []
        self.assertEqual(receiver.validate_clone_for_stop(value), "b" * 64)

    def test_host_cpu_gate_without_sleeping_or_reading_actual_host(self):
        quiet = ["cpu 100 0 100 10000 0 0 0 0\n", "cpu 100 0 100 11000 0 0 0 0\n"]
        with mock.patch.object(receiver.Path, "read_text", side_effect=quiet), \
                mock.patch.object(receiver.time, "sleep") as sleep, \
                mock.patch.object(receiver.time, "monotonic", side_effect=[0, 15]):
            self.assertEqual(receiver.cpu_readiness()["host_busy_percent"], 0)
            sleep.assert_called_once_with(15)
        busy = ["cpu 100 0 100 10000 0 0 0 0\n", "cpu 1100 0 100 10000 0 0 0 0\n"]
        with mock.patch.object(receiver.Path, "read_text", side_effect=busy), \
                mock.patch.object(receiver.time, "sleep"), \
                mock.patch.object(receiver.time, "monotonic", side_effect=[0, 15]):
            with self.assertRaisesRegex(receiver.Refusal, "RESEARCH_NOT_IDLE"):
                receiver.cpu_readiness()

    def test_nonzero_helper_can_preserve_only_projected_failure_receipt(self):
        docker = receiver.Docker()
        value = SimpleNamespace(returncode=1, stdout=b'{"result":"FAIL","guard":"SOURCE_CHANGED"}')
        with mock.patch.object(docker, "call", return_value=value):
            self.assertEqual(docker.value(["unused"]), {"result": "FAIL", "guard": "SOURCE_CHANGED"})
        value.stdout = b'{"result":"FAIL","guard":"not a fixed guard payload"}'
        with mock.patch.object(docker, "call", return_value=value):
            with self.assertRaises(receiver.Refusal):
                docker.value(["unused"])

    def test_cleanup_never_targets_original_source_id(self):
        docker = mock.Mock()
        docker.call.return_value = SimpleNamespace(returncode=0, stdout=('"' + receiver.SOURCE_ID + '"').encode())
        source = receiver.expected_clone_identity(receiver.SOURCE_ID)
        with mock.patch.object(receiver, "selected_inspect", return_value=source):
            with self.assertRaises(receiver.Refusal):
                receiver.stop_temporary(docker, "copy")
        self.assertFalse(any(call.args[0][0] == "stop" for call in docker.call.call_args_list))

    def test_ownership_guard_refuses_source_container_or_wrong_mount(self):
        self.assertNotEqual(receiver.CLONE_CONTAINER, receiver.SOURCE_CONTAINER)
        value = receiver.expected_clone_identity("a" * 64)
        self.assertEqual(receiver.validate_clone_for_stop(value), "a" * 64)
        for bad in [value | {"Id": receiver.SOURCE_ID}, value | {"Name": "/" + receiver.SOURCE_CONTAINER},
                    value | {"Image": "sha256:" + "0" * 64}]:
            with self.assertRaises(receiver.Refusal):
                receiver.validate_clone_for_stop(bad)


if __name__ == "__main__":
    unittest.main()
