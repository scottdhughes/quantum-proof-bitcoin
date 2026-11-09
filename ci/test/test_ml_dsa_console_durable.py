#!/usr/bin/env python3
"""Durable Docker lifecycle boundaries; no native prototype code runs here."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("console_durable", ROOT / "contrib/ml-dsa-console/durable.py")


class DurableTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.state.chmod(0o700)
        self.manager = self.module.RuntimeManager()
        self.labels = dict(self.module.LABELS)
        self.volume = {"Name": self.manager.volume, "Driver": "local", "Options": None, "Labels": self.labels}
        self.marker = {"schema": self.module.SCHEMA, "source_head": self.module.HEAD, "volume_id": "ab" * 16}
        self.config = {"Id": "new-container", "Image": self.module.IMAGE, "State": {"Running": False},
                       "Config": {"Labels": self.labels}, "Mounts": [{"Type": "volume", "Name": self.manager.volume,
                       "Destination": "/tmp", "RW": True}], "HostConfig": {"ReadonlyRootfs": True, "NetworkMode": "none",
                       "Memory": 4294967296, "NanoCpus": 4000000000, "CapDrop": ["ALL"], "CapAdd": None,
                       "SecurityOpt": ["no-new-privileges"], "Privileged": False, "Tmpfs": self.module.IPC_TMPFS,
                       "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}}}
        self.calls = []
        self.daemon_up = True

    def docker(self, command, **_kwargs):
        self.calls.append(command)
        code, value = 0, b""
        if command[1] == "info":
            code = 0 if self.daemon_up else 1
        elif command[1:3] == ["desktop", "start"]:
            self.daemon_up = True
        elif command[1:3] == ["volume", "inspect"]:
            code, value = (0, json.dumps([self.volume]).encode()) if self.volume else (1, b"")
        elif command[1] == "inspect":
            code, value = (0, json.dumps([self.config]).encode()) if self.config else (1, b"")
        elif command[1] == "run":
            value = json.dumps(self.marker).encode()
        elif command[1] == "create":
            self.config = copy.deepcopy(self.original_config)
        elif command[1] == "start":
            self.config["State"]["Running"] = True
        return subprocess.CompletedProcess(command, code, value, b"fixture failure" if code else b"")

    def ensure(self):
        with patch.object(subprocess, "run", side_effect=self.docker):
            return self.manager.ensure(self.state, progress=lambda _message: None)

    def test_stopped_managed_container_starts_with_same_volume_identity(self):
        result = self.ensure()
        self.assertEqual(result, {"container": self.manager.container, "volume": self.manager.volume,
                                  "volume_id": self.marker["volume_id"]})
        self.assertTrue(any(command[1] == "start" for command in self.calls))
        self.assertFalse(any(command[1] == "create" for command in self.calls))

    def test_missing_managed_container_is_recreated_without_host_binds(self):
        self.original_config, self.config = self.config, None
        self.ensure()
        command = next(command for command in self.calls if command[1] == "create")
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("type=volume,source=" + self.manager.volume + ",target=/tmp", command)
        self.assertNotIn("type=bind", " ".join(command))
        self.assertIn(self.module.IMAGE, command)

    def test_daemon_down_starts_docker_desktop_before_reading_volume(self):
        self.daemon_up = False
        self.ensure()
        commands = [command[1:3] for command in self.calls]
        self.assertIn(["desktop", "start"], commands)
        self.assertLess(commands.index(["desktop", "start"]), commands.index(["volume", "inspect"]))

    def test_foreign_volume_is_never_started_or_overwritten(self):
        self.volume["Labels"] = {"foreign": "yes"}
        with self.assertRaises(self.module.RuntimeError):
            self.ensure()
        self.assertFalse(any(command[1] in ("run", "start", "create") for command in self.calls))

    def test_volume_driver_options_are_refused(self):
        self.volume["Options"] = {"device": "/host/path"}
        with self.assertRaises(self.module.RuntimeError):
            self.ensure()

    def test_partial_or_corrupt_volume_is_not_reinitialized(self):
        for marker in ({}, {**self.marker, "source_head": "00" * 20}, {**self.marker, "volume_id": "../wrong"}):
            with self.subTest(marker=marker):
                self.marker = marker
                self.calls = []
                with self.assertRaises(self.module.RuntimeError):
                    self.ensure()
                self.assertFalse(any(command[1] in ("start", "create") for command in self.calls))

    def test_foreign_container_config_does_not_start(self):
        self.config["HostConfig"]["NetworkMode"] = "bridge"
        with self.assertRaises(self.module.RuntimeError):
            self.ensure()
        self.assertFalse(any(command[1] == "start" for command in self.calls))

    def test_missing_volume_and_seed_refuses_silent_replacement(self):
        self.volume, self.config = None, None
        with self.assertRaisesRegex(self.module.RuntimeError, "seed|prepared"):
            self.ensure()
        self.assertFalse(any(command[1:3] == ["volume", "create"] for command in self.calls))

    def test_symlinked_host_metadata_is_refused_before_migration(self):
        target = self.state / "other.json"
        target.write_text("{}")
        (self.state / "session.json").symlink_to(target)
        with self.assertRaises(self.module.RuntimeError):
            self.manager._migration_state(self.state)

    def test_fresh_state_directory_is_created_private_without_inventing_wallet(self):
        fresh = self.state / "new-state"
        self.assertEqual(self.manager._migration_state(fresh), {})
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o700)
        self.assertFalse((fresh / "session.json").exists())

    def test_existing_wallet_requires_all_selected_owned_directories(self):
        path = self.state / "session.json"
        path.write_text(json.dumps({"checkpoint": {"wallet_id": "11" * 16}, "signer_dir": "/tmp/mldsa-console-signer-one"}))
        path.chmod(0o600)
        with self.assertRaises(self.module.RuntimeError):
            self.manager._migration_state(self.state)

    def migration_fixture(self):
        selected = {"checkpoint": {"wallet_id": "11" * 16}, "container_id": "old-seed", "signer_clean": True,
                    "signer_dir": "/tmp/mldsa-console-signer-selected", "node_dir": "/tmp/mldsa-console-node-selected",
                    "code_dir": "/tmp/mldsa-console-code-selected"}
        path = self.state / "session.json"
        path.write_text(json.dumps(selected))
        path.chmod(0o600)
        seed = {"Id": "old-seed", "Image": self.module.IMAGE, "State": {"Running": True},
                "HostConfig": {"ReadonlyRootfs": True, "NetworkMode": "none", "CapDrop": ["ALL"],
                               "SecurityOpt": ["no-new-privileges"]},
                "Mounts": [{"Type": "bind", "RW": False, "Destination": "/source-git", "Source": "/public/project/.git"}]}
        return selected, seed

    def test_migration_copies_only_selected_state_under_correct_linux_uid(self):
        selected, seed = self.migration_fixture()
        with patch.object(subprocess, "run", side_effect=self.docker), patch.object(self.manager, "_copy_stream") as copying:
            self.manager._bootstrap(self.state, seed, lambda _message: None)
        self.assertEqual(len(copying.call_args_list), 2)
        self.assertEqual(copying.call_args_list[0].args[1:],
                         (1000, ["demo-signer-bin/pilot-signer", "mldsa-console-signer-selected"]))
        self.assertEqual(copying.call_args_list[1].args[1:],
                         (1001, ["mldsa-demo-source", "mldsa-demo-build/bin", "mldsa-console-node-selected", "mldsa-console-code-selected"]))
        helpers = [command for command in self.calls if command[1] == "run"]
        self.assertEqual(len(helpers), 1)
        self.assertIn("CHOWN", helpers[0])
        self.assertIn("type=bind,source=/public/project/.git,target=/source-git,readonly", helpers[0])
        script_command = next(command for command in self.calls if "wallet_sha256" in " ".join(command))
        script = script_command[script_command.index("-c") + 1]
        compile(script, "migration-guest-validation", "exec")
        migration = json.loads(script_command[-4])
        self.assertEqual(migration["wallet_id"], selected["checkpoint"]["wallet_id"])
        self.assertEqual(migration["old_container_id"], seed["Id"])
        self.assertTrue(any(command[1:3] == ["rm", "--force"] for command in self.calls))

    def test_unclean_or_wrong_seed_wallet_is_refused_without_creating_volume(self):
        _, seed = self.migration_fixture()
        seed["Id"] = "different-container"
        with patch.object(subprocess, "run", side_effect=self.docker), self.assertRaises(self.module.RuntimeError):
            self.manager._bootstrap(self.state, seed, lambda _message: None)
        self.assertFalse(self.calls)

    def test_archive_pipe_stays_between_uid_scoped_contained_processes(self):
        calls = []
        class Process:
            returncode = 0
            def __init__(self, command, **kwargs):
                calls.append((command, kwargs))
                self.stdout = io.BytesIO()
            def communicate(self, timeout=None):
                return b"", b""
        with patch.object(subprocess, "Popen", side_effect=Process):
            self.manager._copy_stream("owned-helper", 1000, ["mldsa-console-signer-selected"])
        self.assertEqual(calls[0][0][:5], ["docker", "exec", "--user", "1000:1000", self.manager.seed_container])
        self.assertEqual(calls[1][0][:6], ["docker", "exec", "-i", "--user", "0:0", "owned-helper"])
        self.assertIn("--same-owner", calls[1][0])
        self.assertIn("--same-permissions", calls[1][0])


if __name__ == "__main__":
    unittest.main()
