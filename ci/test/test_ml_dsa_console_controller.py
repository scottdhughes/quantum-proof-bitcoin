#!/usr/bin/env python3
"""Controller storage and subprocess-boundary regression tests (no native host code)."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("console_controller", ROOT / "contrib/ml-dsa-console/controller.py")
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.c = controller.Controller("pqbtc-mldsa-local", "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                       ROOT / "contrib/ml-dsa-console")
        self.identity = {"source_head": "9f4b20a938e67ef985df0780fb41b6035abef15e", "worktree": "clean",
                         "sha256": {"spec": "ab" * 32, "daemon": "cd" * 32,
                                    "/tmp/mldsa-demo-build/bin/pqbtcd": "bb55d172508ed47727334f37be374dd34c67ecb42b2cceabae4a7b1d1a575159",
                                    "/tmp/mldsa-demo-build/bin/pqbtc-mldsa-client": "727e654e4ba692c21c6e259eea0f11838f88ff866a08843907f272395f741317",
                                    "/tmp/demo-signer-bin/pilot-signer": "e0b0aea159a0e39704314df63298b9d21d85bfeed21e86e98cab7a41ea70846c"}}
        self.manifest = {"schema": "PQBTC-MLDSA44-PUBLIC-DEMO-WALLET-1",
                         "spec_sha256": "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126",
                         "network_binding": "96bd879ee215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36",
                         "wallet_id": "11" * 16, "next_receive": 2, "next_change": 1, "entries": []}
        self.checkpoint = {"wallet_id": "11" * 16, "generation": 8, "next_receive": 2, "next_change": 1}
        self.payload = {"schema": "PQBTC-MLDSA44-CONSOLE-BACKUP-1", "created_at": "2026-11-09T16:00:00Z",
                        "identity": self.identity, "checkpoint": self.checkpoint, "manifest": self.manifest,
                        "chain": {"genesis": "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2", "tip": "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2", "blocks": []},
                        "ciphertext": "42" * 167}

    def bundle(self, payload=None):
        value = copy.deepcopy(payload or self.payload)
        value["sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return value

    def test_bundle_detects_tampering_and_wrong_identity_before_restore(self):
        good = self.bundle()
        self.assertEqual(controller.validate_bundle(good, self.identity)["ciphertext"], "42" * 167)
        bad = copy.deepcopy(good)
        bad["ciphertext"] = "41" * 167
        with self.assertRaises(controller.ConsoleError):
            controller.validate_bundle(bad, self.identity)
        identity = copy.deepcopy(self.identity)
        identity["sha256"]["daemon"] = "00" * 32
        with self.assertRaises(controller.ConsoleError):
            controller.validate_bundle(good, identity)

    def test_even_rechecksummed_bundle_rejects_bad_counter_and_record_bounds(self):
        for field, value in (("ciphertext", "42" * 168), ("ciphertext", "42" * 166),
                             ("checkpoint", {**self.checkpoint, "next_receive": True}),
                             ("checkpoint", {**self.checkpoint, "next_receive": 1})):
            with self.subTest(field=field), self.assertRaises(controller.ConsoleError):
                controller.validate_bundle(self.bundle({**self.payload, field: value}), self.identity)

    def test_old_backup_merges_retained_floors_and_entries(self):
        newer = copy.deepcopy(self.manifest)
        newer.update(next_receive=9, next_change=4)
        merged = controller.merge_manifests(self.manifest, newer)
        self.assertEqual((merged["next_receive"], merged["next_change"]), (9, 4))
        self.assertEqual(self.manifest["next_receive"], 2)
        other = copy.deepcopy(newer)
        other["wallet_id"] = "22" * 16
        with self.assertRaises(controller.ConsoleError):
            controller.merge_manifests(self.manifest, other)

    def test_atomic_metadata_is_private_and_retained_across_relaunch(self):
        self.c._metadata["retained"] = {self.manifest["wallet_id"]: {"manifest": self.manifest, "checkpoint": self.checkpoint}}
        self.c._save()
        self.assertEqual((self.state / "session.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        reopened = controller.Controller("pqbtc-mldsa-local", "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                         ROOT / "contrib/ml-dsa-console")
        self.assertEqual(reopened._metadata["retained"]["11" * 16]["manifest"]["next_receive"], 2)
        self.assertEqual(reopened.status()["phase"], "stopped")

    def test_atomic_write_rejects_symlink_without_overwriting_target(self):
        victim = Path(self.temp.name) / "victim"
        victim.write_text("preserve")
        (self.state / "unsafe.json").symlink_to(victim)
        with self.assertRaises(controller.ConsoleError):
            self.c._write_json("unsafe.json", {"new": True})
        self.assertEqual(victim.read_text(), "preserve")

    def test_invalid_browser_actions_are_rejected_before_docker(self):
        cases = [([], {}), ("shell", {}), ("receive", {"path": "/tmp/file"}), ("send", {"address": "x", "amount_sats": True}),
                 ("mine", {"blocks": 102}), ("recover", {"backup_id": "../../wallet"}), ("unlock", {"password": "real"})]
        with patch.object(subprocess, "run", side_effect=AssertionError("Docker must not execute")):
            for action, params in cases:
                with self.subTest(action=action), self.assertRaises(controller.ConsoleError):
                    self.c.action(action, params)

    def test_unclean_signer_exit_cannot_produce_backup_checkpoint(self):
        class Exited:
            returncode = 1
            def poll(self): return 1
            def communicate(self, timeout=None): return (b"MLDSA_WALLET_STATUS_V1 " + b"11" * 16 + b" 8 2 1\n", b"failed\n")
        self.c._signer = Exited()
        with self.assertRaisesRegex(controller.ConsoleError, "clean"):
            self.c._stop_signer()
        self.assertNotIn("checkpoint", self.c._metadata)

    def test_backup_rejects_raw_chain_identity_and_header_link_mismatch(self):
        bad = copy.deepcopy(self.payload)
        bad["chain"]["tip"] = "00" * 32
        with self.assertRaises(controller.ConsoleError):
            controller.validate_bundle(self.bundle(bad), self.identity)
        bad["chain"]["blocks"] = ["00" * 80]
        with self.assertRaises(controller.ConsoleError):
            controller.validate_bundle(self.bundle(bad), self.identity)

    def worker_process(self, responses):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, responses)
        os.close(write_fd)
        class Process:
            returncode = None
            stdin = io.BytesIO()
            stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return self.returncode
            def communicate(self, timeout=None):
                self.returncode = 0
                return b"", b""
        process = Process()
        self.addCleanup(process.stdout.close)
        self.c._worker = process
        return process

    def test_malformed_transport_taints_worker_and_late_response_cannot_be_reused(self):
        process = self.worker_process(b'not-json\n{"ok":true,"result":{"txid":"late"},"manifest":null}\n')
        with self.assertRaises(controller.ConsoleError):
            self.c._request("send", {"address": "example", "amount_sats": 1})
        sent = process.stdin.getvalue()
        with self.assertRaisesRegex(controller.ConsoleError, "unusable"):
            self.c._request("status")
        self.assertEqual(process.stdin.getvalue(), sent)
        self.c._stop_worker()
        self.assertIsNone(self.c._worker)

    def test_valid_worker_error_keeps_next_response_aligned(self):
        self.worker_process(b'{"ok":false,"error":"insufficient funds"}\n{"ok":true,"result":{"height":104},"manifest":null}\n')
        with self.assertRaisesRegex(controller.ConsoleError, "insufficient funds"):
            self.c._request("send")
        self.assertEqual(self.c._request("status"), {"height": 104})

    def test_startup_failure_reaps_owned_worker_and_signer(self):
        config = {"id": "fixture", "running": True, "image": controller.IMAGE, "ro": True, "network": "none",
                  "memory": 4294967296, "cpus": 4000000000, "drop": ["ALL"], "security": ["no-new-privileges"],
                  "privileged": False, "tmpfs": {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"},
                  "mounts": [{"Destination": "/source-git", "Type": "bind", "RW": False}]}
        processes = []
        class Process:
            def __init__(self, signer):
                self.signer = signer
                self.returncode = None if signer else 0
                self.stdin = io.BytesIO()
                read_fd, self.write_fd = os.pipe()
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
                os.write(self.write_fd, b'{"pid":123,"start":"456"}\n')
                if signer:
                    os.write(self.write_fd, b'MLDSA_WALLET_STATUS_V1 ' + b'11' * 16 + b' 8 2 1\n')
                else:
                    os.close(self.write_fd)
            def poll(self): return self.returncode
            def finish(self):
                os.write(self.write_fd, b'MLDSA_WALLET_STATUS_V1 ' + b'11' * 16 + b' 8 2 1\n')
                os.close(self.write_fd)
                self.returncode = 0
            def communicate(self, timeout=None): return self.stdout.read(), b""
        def popen(command, **kwargs):
            process = Process(controller.SERVER in command)
            processes.append(process)
            self.addCleanup(process.stdout.close)
            return process
        def docker(command, **kwargs):
            if command[1] == "inspect":
                return subprocess.CompletedProcess(command, 0, json.dumps(config).encode(), b"")
            script = command[command.index("-c") + 1] if "-c" in command else ""
            output = b""
            if "rev-parse" in script:
                output = json.dumps(self.identity).encode()
            elif "tempfile.mkdtemp" in script:
                role = next(role for role in ("signer", "node", "code") if "mldsa-console-" + role in script)
                output = ("/tmp/mldsa-console-" + role + "-fixture\n").encode()
            elif "is_socket" in script:
                output = b"1\n"
            elif "os.kill" in script:
                processes[0].finish()
            return subprocess.CompletedProcess(command, 0, output, b"")
        with patch.object(subprocess, "run", side_effect=docker), patch.object(subprocess, "Popen", side_effect=popen):
            with self.assertRaises(controller.ConsoleError):
                self.c.action("start")
        self.assertIsNone(self.c._worker)
        self.assertIsNone(self.c._signer)
        self.assertEqual(processes[0].returncode, 0)
        self.assertTrue((self.state / "session.json").exists())

    def test_first_start_refuses_native_hashes_outside_qualified_fixture(self):
        config = {"id": "fixture", "running": True, "image": controller.IMAGE, "ro": True, "network": "none",
                  "memory": 4294967296, "cpus": 4000000000, "drop": ["ALL"], "security": ["no-new-privileges"],
                  "privileged": False, "tmpfs": {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"},
                  "mounts": [{"Destination": "/source-git", "Type": "bind", "RW": False}]}
        identity = copy.deepcopy(self.identity)
        identity["sha256"]["/tmp/mldsa-demo-build/bin/pqbtcd"] = "00" * 32
        def docker(command, **kwargs):
            value = config if command[1] == "inspect" else identity
            return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")
        with patch.object(subprocess, "run", side_effect=docker):
            with self.assertRaisesRegex(controller.ConsoleError, "qualification"):
                self.c.action("start")
        self.assertIsNone(self.c._signer)
        self.assertIsNone(self.c._worker)

    def test_missing_native_build_reports_retained_backups_and_preparation_need(self):
        config = {"id": "fixture", "running": True, "image": controller.IMAGE, "ro": True, "network": "none",
                  "memory": 4294967296, "cpus": 4000000000, "drop": ["ALL"], "security": ["no-new-privileges"],
                  "privileged": False, "tmpfs": {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"},
                  "mounts": [{"Destination": "/source-git", "Type": "bind", "RW": False}]}
        def docker(command, **kwargs):
            if command[1] == "inspect":
                return subprocess.CompletedProcess(command, 0, json.dumps(config).encode(), b"")
            return subprocess.CompletedProcess(command, 1, b"", b"FileNotFoundError: native daemon missing")
        with patch.object(subprocess, "run", side_effect=docker), self.assertRaisesRegex(controller.ConsoleError, "native source/build"):
            self.c.action("start")
        self.assertTrue((self.state / "backups").is_dir())

    def durable_fixture(self, config=None, marker=None, volume=None, migration=None):
        labels = {"org.pqbtc.console.schema": "durable-1", "org.pqbtc.console.source": controller.HEAD}
        config = config or {"id": "recreated-container", "running": True, "image": controller.IMAGE, "ro": True,
            "network": "none", "memory": 4294967296, "cpus": 4000000000, "drop": ["ALL"],
            "security": ["no-new-privileges"], "privileged": False, "labels": labels,
            "tmpfs": {"/run/pqbtc-ipc": "rw,noexec,nosuid,nodev,size=1048576,mode=1777"},
            "mounts": [{"Destination": "/tmp", "Type": "volume", "RW": True, "Name": "pqbtc-mldsa-local-data-v1"}]}
        marker = marker or {"schema": "PQBTC-MLDSA44-DURABLE-RUNTIME-1", "source_head": controller.HEAD, "volume_id": "55" * 16}
        volume = volume or {"name": "pqbtc-mldsa-local-data-v1", "driver": "local", "options": None, "labels": labels}
        def docker(command, **kwargs):
            self.assertEqual(command[0], "docker", "Controller executed a host helper")
            if command[1] == "inspect":
                result = config
            elif command[1:3] == ["volume", "inspect"]:
                result = volume
            elif "/tmp/.pqbtc-runtime-v1.json" in command:
                result = marker
            elif "/tmp/.pqbtc-migration-v1.json" in command:
                result = migration or {}
            else:
                script = command[command.index("-c") + 1]
                if "rev-parse" in script:
                    result = self.identity
                elif "tempfile.mkdtemp" in script:
                    if 'dir="/run/pqbtc-ipc"' in script:
                        path = "/run/pqbtc-ipc/mldsa-console-ipc-fixture"
                    else:
                        role = next(role for role in ("signer", "node", "code") if "mldsa-console-" + role in script)
                        path = "/tmp/mldsa-console-" + role + "-replacement"
                    return subprocess.CompletedProcess(command, 0, (path + "\n").encode(), b"")
                elif "wallet.dat" in script:
                    result = {"wallet_sha256": "66" * 32}
                elif "public-wallet.json" in script:
                    result = self.manifest
                else:
                    return subprocess.CompletedProcess(command, 0, b"", b"")
            return subprocess.CompletedProcess(command, 0, json.dumps(result).encode(), b"")
        return docker, config, marker, volume

    def test_managed_volume_is_validated_and_bound_by_marker_identity(self):
        docker, _, _, _ = self.durable_fixture()
        with patch.object(subprocess, "run", side_effect=docker):
            container_id, identity = self.c._prepare()
        self.assertEqual(container_id, "recreated-container")
        self.assertEqual(identity, self.identity)
        self.assertEqual(self.c._prepared_storage, {"kind": "named-volume", "volume": "pqbtc-mldsa-local-data-v1", "volume_id": "55" * 16})

    def test_named_container_requires_its_own_managed_volume(self):
        self.c.container = "pqbtc-other-local"
        docker, config, _, volume = self.durable_fixture()
        config["mounts"][0]["Name"] = "pqbtc-other-local-data-v1"
        volume["name"] = "pqbtc-other-local-data-v1"
        with patch.object(subprocess, "run", side_effect=docker):
            self.c._prepare()
        self.assertEqual(self.c._prepared_storage["volume"], "pqbtc-other-local-data-v1")

    def test_unmanaged_mounts_volume_options_labels_and_bad_marker_are_refused(self):
        for change in ("host-bind", "other-volume", "volume-options", "container-label", "marker-id", "added-capability", "automatic-restart"):
            docker, config, marker, volume = self.durable_fixture()
            if change == "host-bind":
                config["mounts"][0]["Type"] = "bind"
            if change == "other-volume":
                config["mounts"][0]["Name"] = "unrelated"
            if change == "volume-options":
                volume["options"] = {"type": "none", "device": "/host"}
            if change == "container-label":
                config["labels"] = {}
            if change == "marker-id":
                marker["volume_id"] = "bad"
            if change == "added-capability":
                config["capadd"] = ["DAC_OVERRIDE"]
            if change == "automatic-restart":
                config["restart"] = "always"
            with self.subTest(change=change), patch.object(subprocess, "run", side_effect=docker):
                with self.assertRaises(controller.ConsoleError):
                    self.c._prepare()

    def existing_durable_session(self):
        self.c._metadata.update(checkpoint=self.checkpoint, manifest=self.manifest, identity=self.identity,
            container_id="prior-container", storage={"kind": "named-volume", "volume": "pqbtc-mldsa-local-data-v1", "volume_id": "55" * 16},
            signer_dir="/tmp/mldsa-console-signer-fixture", node_dir="/tmp/mldsa-console-node-fixture", code_dir="/tmp/mldsa-console-code-fixture")

    def test_same_durable_volume_survives_container_recreation_and_restores_public_floors(self):
        self.existing_durable_session()
        self.manifest["next_receive"] = 9
        docker, _, _, _ = self.durable_fixture()
        with patch.object(subprocess, "run", side_effect=docker):
            container_id, identity = self.c._prepare()
            self.c._verify_session_storage(container_id, identity)
        self.assertEqual(self.c._metadata["container_id"], "recreated-container")
        self.assertEqual(self.c._floors(self.checkpoint)["next_receive"], 9)
        self.assertEqual(self.c._metadata["checkpoint"], self.checkpoint)

    def test_changed_durable_volume_identity_is_refused(self):
        self.existing_durable_session()
        docker, _, marker, _ = self.durable_fixture()
        marker["volume_id"] = "77" * 16
        with patch.object(subprocess, "run", side_effect=docker):
            container_id, identity = self.c._prepare()
            with self.assertRaises(controller.ConsoleError):
                self.c._verify_session_storage(container_id, identity)
        self.assertEqual(self.c._metadata["container_id"], "prior-container")

    def test_intact_backup_reaches_new_restore_when_current_wallet_or_public_metadata_is_damaged(self):
        backup_id = "aa" * 16
        self.c._write_json("backups/" + backup_id + ".json", self.bundle())
        for damaged in ("wallet-missing", "public-missing", "public-corrupt"):
            self.existing_durable_session()
            docker, _, _, _ = self.durable_fixture()
            restored_records = []
            def boundary(command, **kwargs):
                script = command[command.index("-c") + 1] if "-c" in command else ""
                if "wallet/wallet.dat" in script and "/tmp/mldsa-console-signer-fixture" in command and damaged == "wallet-missing":
                    return subprocess.CompletedProcess(command, 1, b"", b"FileNotFoundError: current wallet.dat missing")
                if "public/public-wallet.json" in script and damaged == "public-missing":
                    return subprocess.CompletedProcess(command, 1, b"", b"current public metadata unavailable")
                if "public/public-wallet.json" in script and damaged == "public-corrupt":
                    return subprocess.CompletedProcess(command, 0, b'{"invalid":"public record"}', b"")
                if command[-1:] == ["/tmp/mldsa-console-signer-replacement/wallet/wallet.dat"]:
                    restored_records.append(kwargs.get("input"))
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                return docker(command, **kwargs)
            with self.subTest(damaged=damaged), patch.object(subprocess, "run", side_effect=boundary):
                with patch.object(subprocess, "Popen", side_effect=controller.ConsoleError("new signer restore reached")):
                    with self.assertRaisesRegex(controller.ConsoleError, "new signer restore reached"):
                        self.c.action("recover", {"backup_id": backup_id})
            self.assertEqual(restored_records, [b"B" * 167])
            self.assertEqual(self.c._metadata["signer_dir"], "/tmp/mldsa-console-signer-replacement")

    def test_backup_recovery_rejects_foreign_volume_before_stopping_current_worker(self):
        self.existing_durable_session()
        backup_id = "aa" * 16
        self.c._write_json("backups/" + backup_id + ".json", self.bundle())
        docker, _, marker, _ = self.durable_fixture()
        marker["volume_id"] = "77" * 16
        class Active:
            def poll(self): return None
        active = Active()
        self.c._worker = active
        with patch.object(subprocess, "run", side_effect=docker):
            with self.assertRaisesRegex(controller.ConsoleError, "volume identity changed"):
                self.c.action("recover", {"backup_id": backup_id})
        self.assertIs(self.c._worker, active)
        self.assertEqual(self.c._metadata["signer_dir"], "/tmp/mldsa-console-signer-fixture")

    def test_legacy_migration_requires_exact_selected_state_marker_before_metadata_changes(self):
        self.existing_durable_session()
        self.c._metadata.pop("storage")
        marker = {"schema": "PQBTC-MLDSA44-DURABLE-MIGRATION-1", "old_container_id": "wrong-prior-container",
                  "wallet_id": self.checkpoint["wallet_id"], "wallet_sha256": "66" * 32,
                  **{role + "_dir": self.c._metadata[role + "_dir"] for role in ("signer", "node", "code")}}
        docker, _, _, _ = self.durable_fixture(migration=marker)
        with patch.object(subprocess, "run", side_effect=docker):
            container_id, identity = self.c._prepare()
            with self.assertRaisesRegex(controller.ConsoleError, "migration"):
                self.c._verify_session_storage(container_id, identity)
        self.assertNotIn("storage", self.c._metadata)
        self.assertEqual(self.c._metadata["retained"], {})
        marker["old_container_id"] = "prior-container"
        with patch.object(subprocess, "run", side_effect=docker):
            self.c._verify_session_storage(container_id, identity)
        self.assertEqual(self.c._metadata["storage"]["volume_id"], "55" * 16)

    def test_one_dead_handle_stops_only_verified_owned_signer_and_reports_unclean_state(self):
        self.c._metadata["checkpoint"] = copy.deepcopy(self.checkpoint)
        class DeadWorker:
            def poll(self): return 137
            def communicate(self, timeout=None): return b"", b"engine stopped"
        class Signer:
            returncode = None
            def poll(self): return self.returncode
            def communicate(self, timeout=None): return b'MLDSA_WALLET_STATUS_V1 ' + b'11' * 16 + b' 8 2 1\n', b""
        signer = Signer()
        self.c._worker, self.c._signer = DeadWorker(), signer
        self.c._signer_info = {"pid": 123, "start": "456", "uid": 1000, "executable": controller.SERVER}
        def docker(command, **kwargs):
            self.assertEqual(command[0:2], ["docker", "exec"])
            self.assertIn("1000:1000", command)
            self.assertEqual(command[-4:], ["123", "456", "1000", controller.SERVER])
            signer.returncode = 0
            return subprocess.CompletedProcess(command, 0, b"", b"")
        with patch.object(subprocess, "run", side_effect=docker):
            with self.assertRaisesRegex(controller.ConsoleError, "owned companion"):
                self.c.status()
        self.assertEqual(self.c.status()["phase"], "stopped")
        self.assertIs(self.c._metadata["signer_clean"], False)
        self.assertIsNone(self.c._signer)

    def test_durable_ipc_is_ephemeral_and_wallet_path_is_preserved(self):
        self.existing_durable_session()
        docker, _, _, _ = self.durable_fixture()
        with patch.object(subprocess, "run", side_effect=docker):
            self.c._prepare()
            self.c._setup_paths()
        self.assertEqual(self.c._socket(), "/run/pqbtc-ipc/mldsa-console-ipc-fixture/signer.sock")
        self.assertEqual(self.c._metadata["signer_dir"], "/tmp/mldsa-console-signer-fixture")

    def test_dead_engine_handles_reconcile_to_stopped_without_clean_checkpoint(self):
        self.c._metadata["checkpoint"] = copy.deepcopy(self.checkpoint)
        self.c._metadata["signer_clean"] = True
        class Dead:
            def poll(self): return 137
            def communicate(self, timeout=None): return b"", b"engine stopped"
        self.c._worker = Dead()
        self.c._signer = Dead()
        status = self.c.status()
        self.assertEqual(status["phase"], "stopped")
        self.assertIsNone(self.c._worker)
        self.assertIsNone(self.c._signer)
        self.assertIs(self.c._metadata["signer_clean"], False)
        self.assertEqual(self.c._metadata["checkpoint"], self.checkpoint)

    def test_retained_floor_does_not_fabricate_signer_checkpoint_generation(self):
        self.c._retain(point=self.checkpoint)
        restored = {**self.checkpoint, "generation": 3}
        self.c._retain(point=restored)
        self.assertEqual(self.c._metadata["checkpoint"], restored)
        self.assertEqual(self.c._metadata["retained"]["11" * 16]["checkpoint"], restored)

    def test_corrupt_retained_counter_refused_on_relaunch(self):
        self.c._metadata["retained"] = {"11" * 16: {"manifest": {**self.manifest, "next_receive": True}, "checkpoint": self.checkpoint}}
        self.c._save()
        with self.assertRaises(controller.ConsoleError):
            controller.Controller("pqbtc-mldsa-local", "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                  ROOT / "contrib/ml-dsa-console")

    def test_symlinked_metadata_is_refused_as_console_error(self):
        other = Path(self.temp.name) / "other.json"
        other.write_text("{}")
        (self.state / "session.json").symlink_to(other)
        with self.assertRaises(controller.ConsoleError):
            controller.Controller("pqbtc-mldsa-local", "/tmp/mldsa-demo-source", "/tmp/mldsa-demo-build", self.state,
                                  ROOT / "contrib/ml-dsa-console")

    def test_failed_atomic_replace_preserves_previous_metadata_and_uncertain_temp(self):
        self.c._save()
        before = (self.state / "session.json").read_bytes()
        with patch.object(os, "replace", side_effect=OSError("simulated disk failure")), self.assertRaises(OSError):
            self.c._write_json("session.json", {"changed": True})
        self.assertEqual((self.state / "session.json").read_bytes(), before)
        self.assertEqual(len(list(self.state.glob("session.json.tmp-*"))), 1)

    def test_no_backup_after_unclean_signer_exit(self):
        self.c._metadata["signer_clean"] = False
        class ExitedWorker:
            def poll(self): return 1
        self.c._worker = ExitedWorker()
        with self.assertRaisesRegex(controller.ConsoleError, "clean"):
            self.c._backup()
        self.assertEqual(list((self.state / "backups").iterdir()), [])

    def test_truncated_checkpoint_and_counter_overflow_are_refused(self):
        for line in (b"MLDSA_WALLET_STATUS_V1 11 2 3 4\n", b"MLDSA_WALLET_STATUS_V1 " + b"11" * 16 + b" 1 2147483649 0\n"):
            with self.assertRaises(controller.ConsoleError):
                controller.parse_checkpoint(line)


if __name__ == "__main__":
    unittest.main()
