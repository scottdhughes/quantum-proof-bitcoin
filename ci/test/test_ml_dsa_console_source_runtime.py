"""Source runtime storage, descriptor and container boundaries; no native host code."""
import copy
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "contrib/ml-dsa-console" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class SourceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = module("source_runtime")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.state.mkdir(mode=0o700)
        self.manifest = {"schema": "PQBTC-MLDSA44-SOURCE-BUILD-1", "source_head": "12" * 20,
                         "source_tree": "34" * 20, "compiler": "gcc", "architecture": "aarch64",
                         "sha256": {p: "56" * 32 for p in self.runtime.REQUIRED_HASHES},
                         "toolchain": {"cc": "fixture"}, "checks": {"native": "PASS"}}
        self.raw = json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.descriptor = {"schema": "PQBTC-MLDSA44-SOURCE-RUNTIME-1", "image": "sha256:" + "78" * 32,
                           "manifest": self.manifest, "manifest_sha256": hashlib.sha256(self.raw).hexdigest()}
        self.manager = self.runtime.SourceManager("source-fixture")
        self.labels = self.runtime.labels(self.descriptor)
        self.volume = {"Name": self.manager.volume, "Driver": "local", "Options": None, "Labels": self.labels}
        self.marker = {"schema": self.runtime.VOLUME_SCHEMA, "volume_id": "ab" * 16,
                       "source_head": self.manifest["source_head"], "manifest_sha256": self.descriptor["manifest_sha256"]}
        self.config = {"Id": "new-container", "Image": self.descriptor["image"], "State": {"Running": False},
                       "Config": {"Labels": self.labels}, "Mounts": [{"Type": "volume", "Name": self.manager.volume,
                       "Destination": "/tmp", "RW": True}], "HostConfig": {"ReadonlyRootfs": True, "NetworkMode": "none",
                       "Memory": 4294967296, "NanoCpus": 4000000000, "CapDrop": ["ALL"], "CapAdd": None,
                       "SecurityOpt": ["no-new-privileges"], "Privileged": False, "Tmpfs": self.runtime.IPC_TMPFS,
                       "RestartPolicy": {"Name": "no"}}}
        self.calls = []
        self.custody_present = False

    def docker(self, command, **kwargs):
        self.calls.append(command)
        result = b""
        code = 0
        if command[1:3] == ["volume", "inspect"]:
            code, result = (0, json.dumps([self.volume]).encode()) if self.volume else (1, b"")
        elif command[1:3] == ["volume", "create"]:
            self.volume = self.saved_volume
        elif command[1] == "inspect":
            code, result = (0, json.dumps(self.config).encode()) if self.config else (1, b"")
        elif command[1] == "run":
            if "--detach" in command:
                result = b"helper-id\n"
            elif "custody_state" in " ".join(command):
                result = json.dumps({"custody_state": self.custody_present}).encode()
            elif self.runtime.MANIFEST in " ".join(command):
                result = self.raw
            else:
                result = json.dumps(self.marker).encode()
        elif command[1] == "create":
            self.config = self.saved_config
        elif command[1] == "start":
            self.config["State"]["Running"] = True
        return subprocess.CompletedProcess(command, code, result, b"fixture refusal" if code else b"")

    def ensure(self, descriptor=None):
        with patch.object(subprocess, "run", side_effect=self.docker):
            return self.manager.ensure(self.state, repo=ROOT, descriptor=descriptor or self.descriptor, progress=lambda _: None)

    def test_descriptor_rejects_changed_manifest_or_missing_native_hash(self):
        self.runtime.validate_descriptor(self.descriptor)
        for change in ("checksum", "path", "image"):
            value = copy.deepcopy(self.descriptor)
            if change == "checksum":
                value["manifest"]["source_head"] = "00" * 20
            elif change == "path":
                del value["manifest"]["sha256"][self.runtime.REQUIRED_HASHES[0]]
            else:
                value["image"] = "debian:latest"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.runtime.validate_descriptor(value)

    def test_source_runtime_uses_descriptor_image_and_retains_volume_uuid(self):
        result = self.ensure()
        self.assertEqual(result["volume_id"], self.marker["volume_id"])
        self.assertEqual(result["runtime_descriptor"], self.descriptor)
        self.assertEqual(self.runtime.load_descriptor(self.state / "runtime.json", private=True), self.descriptor)
        self.assertTrue(any(c[1] == "start" for c in self.calls))
        self.assertFalse(any("pqbtc-mldsa-demo-20261109" in c for c in self.calls))

    def test_container_accepts_its_declared_inherited_image_build_label(self):
        self.config["Config"]["Labels"] = {**self.labels, "org.pqbtc.console.build": "source-1"}
        self.assertEqual(self.ensure()["volume_id"], self.marker["volume_id"])
        self.assertEqual(self.runtime.labels(self.descriptor)["org.pqbtc.console.build"], "source-1")

    def test_recreated_container_preserves_volume_and_has_no_host_binds(self):
        self.saved_config, self.config = self.config, None
        self.ensure()
        command = next(c for c in self.calls if c[1] == "create")
        self.assertIn(self.descriptor["image"], command)
        self.assertNotIn("type=bind", " ".join(command))
        self.assertIn("--read-only", command)

    def test_foreign_volume_and_changed_marker_are_refused_before_start(self):
        self.volume["Labels"] = {"other": "yes"}
        with self.assertRaises(ValueError):
            self.ensure()
        self.assertFalse(any(c[1] in ("start", "create") for c in self.calls))
        self.volume["Labels"] = self.labels
        self.marker["manifest_sha256"] = "00" * 32
        with self.assertRaises(ValueError):
            self.ensure()

    def test_different_saved_descriptor_refuses_replacement(self):
        self.ensure()
        value = copy.deepcopy(self.descriptor)
        value["image"] = "sha256:" + "99" * 32
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, "changed|match"):
            self.ensure(value)
        self.assertFalse(self.calls)

    def test_missing_volume_with_existing_wallet_does_not_bootstrap_another_wallet(self):
        self.volume = None
        session = self.state / "session.json"
        session.write_text(json.dumps({"checkpoint": {"wallet_id": "11" * 16}}))
        session.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "wallet|recovery"):
            self.ensure()
        self.assertFalse(any(c[1:3] == ["volume", "create"] for c in self.calls))

    def test_new_volume_copies_seed_only_from_built_image(self):
        self.saved_volume, self.volume = self.volume, None
        self.saved_config, self.config = self.config, None
        self.ensure()
        helper = next(c for c in self.calls if c[1] == "run" and "--detach" in c)
        self.assertIn(self.descriptor["image"], helper)
        self.assertNotIn("type=bind", " ".join(helper))
        self.assertTrue(any(c[1] == "exec" and "/opt/pqbtc-runtime/seed/." in c for c in self.calls))
        self.assertFalse(any("tar" in c for c in self.calls))

    def test_volume_mounts_never_copy_up_image_tmp_into_new_storage(self):
        self.saved_volume, self.volume = self.volume, None
        self.saved_config, self.config = self.config, None
        self.ensure()
        mounts = [value for command in self.calls for value in command if value.startswith("type=volume,")]
        self.assertGreaterEqual(len(mounts), 3)  # bootstrap, marker reader, runtime
        for mount in mounts:
            with self.subTest(mount=mount):
                self.assertIn(",volume-nocopy", mount)

    def test_descriptor_symlinks_and_writable_files_are_rejected(self):
        target = self.state / "target.json"
        target.write_text(json.dumps(self.descriptor))
        target.chmod(0o600)
        link = self.state / "link.json"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            self.runtime.load_descriptor(link)
        target.chmod(0o666)
        with self.assertRaises(ValueError):
            self.runtime.load_descriptor(target)

    def test_controller_verifies_new_source_tree_native_hashes_and_manifest(self):
        controller = module("controller")
        config = {"id": "fresh", "running": True, "image": self.descriptor["image"], "ro": True, "network": "none",
                  "memory": 4294967296, "cpus": 4000000000, "drop": ["ALL"], "security": ["no-new-privileges"],
                  "privileged": False, "capadd": None, "restart": "no", "tmpfs": self.runtime.IPC_TMPFS,
                  "labels": self.labels, "mounts": self.config["Mounts"]}
        identity = {"source_head": self.manifest["source_head"], "source_tree": self.manifest["source_tree"],
                    "worktree": "clean", "sha256": self.manifest["sha256"]}
        volume = {"name": self.manager.volume, "driver": "local", "options": None, "labels": self.labels}
        def docker(command, **_kwargs):
            if command[1] == "inspect":
                value = json.dumps(config).encode()
            elif command[1:3] == ["volume", "inspect"]:
                value = json.dumps(volume).encode()
            elif self.runtime.MANIFEST in command:
                value = self.raw
            elif self.runtime.MARKER in command:
                value = json.dumps(self.marker).encode()
            else:
                value = json.dumps(identity).encode()
            return subprocess.CompletedProcess(command, 0, value, b"")
        c = controller.Controller(self.manager.container, "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                  ROOT / "contrib/ml-dsa-console", runtime_descriptor=self.descriptor)
        with patch.object(subprocess, "run", side_effect=docker):
            self.assertEqual(c._prepare(), ("fresh", identity))
            self.assertEqual(c._prepared_storage["volume_id"], self.marker["volume_id"])
            identity["source_tree"] = "00" * 20
            with self.assertRaisesRegex(controller.ConsoleError, "source|tree"):
                c._prepare()

    def test_source_app_selection_preserves_existing_legacy_sessions(self):
        app = module("app")
        self.assertEqual(app.runtime_kind(self.state, None), "source")
        (self.state / "session.json").write_text("{}")
        self.assertEqual(app.runtime_kind(self.state, None), "legacy")
        self.assertEqual(app.runtime_kind(self.state, Path("new-descriptor.json")), "source")

    def test_source_worker_comes_from_image_source_not_current_host_files(self):
        controller = module("controller")
        c = controller.Controller(self.manager.container, "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                  self.state / "nonexistent-host-source", runtime_descriptor=self.descriptor)
        c._prepared_storage = {"kind": "named-volume", "volume": self.manager.volume, "volume_id": "ab" * 16}
        c._metadata.update(signer_dir="/tmp/mldsa-console-signer-fixture", node_dir="/tmp/mldsa-console-node-fixture",
                           code_dir="/tmp/mldsa-console-code-fixture")
        written = []
        def invoke(user, *args, data=None, **_kwargs):
            if "tempfile.mkdtemp" in " ".join(map(str, args)):
                return b"/run/pqbtc-ipc/mldsa-console-ipc-fixture\n"
            if args[-1] == "/tmp/mldsa-demo-source/contrib/ml-dsa-console/runtime.py":
                return b"# exact image source worker\n"
            if data is not None:
                written.append(data)
            return b""
        with patch.object(c, "_invoke", side_effect=invoke):
            c._setup_paths()
        self.assertEqual(written, [b"# exact image source worker\n"])

    def test_no_cache_is_forwarded_only_for_a_fresh_source_build(self):
        with patch.object(subprocess, "run", side_effect=self.docker), patch.object(self.manager, "_build_image", return_value=self.descriptor) as build:
            self.manager.ensure(self.state, repo=ROOT, compiler="clang", no_cache=True, progress=lambda _: None)
        self.assertEqual(build.call_args.kwargs["compiler"], "clang")
        self.assertTrue(build.call_args.kwargs["no_cache"])
        with patch.object(subprocess, "run", side_effect=self.docker), patch.object(self.manager, "_build_image", side_effect=AssertionError("Must resume existing image")):
            self.manager.ensure(self.state, repo=ROOT, no_cache=True, progress=lambda _: None)

    def test_another_installation_cannot_race_volume_initialization(self):
        path = self.state / ".runtime-setup.lock"
        with path.open("w") as handle:
            path.chmod(0o600)
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(subprocess, "run", side_effect=AssertionError("No Docker call during competing install")):
                with self.assertRaisesRegex(ValueError, "installation"):
                    self.manager.ensure(self.state, descriptor=self.descriptor)

    def test_missing_host_session_cannot_create_a_new_wallet_over_existing_custody(self):
        self.custody_present = True
        with self.assertRaisesRegex(ValueError, "session|metadata"):
            self.ensure()
        self.assertFalse((self.state / "runtime.json").exists())
        self.assertFalse(any(c[1] in ("start", "create") for c in self.calls))

    def test_initialized_seed_only_volume_can_finish_an_interrupted_first_install(self):
        self.custody_present = False
        self.assertEqual(self.ensure()["volume_id"], self.marker["volume_id"])


if __name__ == "__main__":
    unittest.main()
