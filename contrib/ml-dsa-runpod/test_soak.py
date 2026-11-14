# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""DATA-only protocol/identity tests; no native product binary is built or run."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


driver = load("runpod_soak_test_driver", "run_public_soak.py")
agent = load("runpod_soak_test_agent", "runpod_agent.py")


def transport():
    return {"kind": "ssh", "argv": ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                     "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                                     "-o", "UserKnownHostsFile=/tmp/test-public-known-hosts", "-o", "GlobalKnownHostsFile=/dev/null",
                                     "-p", "2222", "root@203.0.113.2"]}


def qualified():
    hashes = {driver.base.NODE: "a" * 64, driver.base.SIGNER: "b" * 64,
              driver.base.SOURCE_PREFIX + "docs/ML_DSA_44_PUBLIC_TEST_PROFILE.md": driver.base.PROFILE,
              driver.base.SOURCE_PREFIX + "docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md": "d" * 64}
    return {"source_head": "1" * 40, "source_tree": "2" * 40, "node_sha256": "a" * 64,
            "signer_sha256": "b" * 64, "descriptor": {"manifest_sha256": "e" * 64, "manifest": {"sha256": hashes}}}


def payload():
    value = qualified()
    return {"schema": "PQBTC-RUNPOD-PAYLOAD-1", "version": "a3", "source_head": value["source_head"],
            "source_tree": value["source_tree"], "manifest_sha256": "e" * 64,
            "files": {"seed/" + name.removeprefix("/tmp/"): digest for name, digest in value["descriptor"]["manifest"]["sha256"].items()}}


def restart():
    return {"schema": "PQBTC-RUNPOD-RESTART-1", "result": "PASS", "pod_id": "test-pod-123", "provider_restart": True,
            "before_generation": "2026-11-14T12:00:00Z", "after_generation": "2026-11-14T12:05:00Z", "transport": transport()}


class IdentityTests(unittest.TestCase):
    def test_public_native_paths_cannot_escape_the_exported_provider_mount(self):
        settings = {"runtime_root": "/opt/pqbtc-runtime", "versions_root": "/opt/pqbtc-runpod/versions",
                    "data_root": "/var/lib/pqbtc/attempt/data"}
        driver.validate_native_paths(settings, "/var/lib/pqbtc/attempt/control")
        for field, value in (("runtime_root", "/tmp/runtime"), ("versions_root", "/tmp/versions"),
                             ("data_root", "/tmp/data"), ("data_root", "/var/lib/pqbtc"),
                             ("data_root", "/var/lib/pqbtc/other-attempt/data")):
            changed = {**settings, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                driver.validate_native_paths(changed, "/var/lib/pqbtc/attempt/control")
        for state in ("/tmp/control", "/var/lib/pqbtc", "/var/lib/pqbtc/attempt/../control"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                driver.validate_native_paths(settings, state)

    def prelaunch_fixture(self, root):
        hashes = {}
        for name in driver.CONTROL_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# DATA fixture only\n")
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        imported = root / "contrib/ml-dsa-console/runtime.py"
        imported.write_bytes(b"# tracked helper outside partial control hash list\n")
        return {"repo": str(root), "backend": "docker", "control_identity":
                {"source_head": "1" * 40, "source_tree": "2" * 40, "sha256": hashes},
                "docker": [sys.executable, "-c", 'print(\'{"architecture":"DATA","daemon_id":"DATA-ONLY"}\')']}

    def prelaunch(self, value):
        return subprocess.run([sys.executable, "-I", "-c", driver.PRELAUNCH_SCRIPT, json.dumps(value)],
                              capture_output=True, timeout=20)

    def test_gitless_reflected_source_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.prelaunch_fixture(Path(directory))
            self.assertNotEqual(self.prelaunch(value).returncode, 0)

    def test_complete_git_tree_and_git_worktree_file_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            value = self.prelaunch_fixture(root)
            environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], env=environment, stderr=subprocess.DEVNULL).decode().strip()
            git("init", "--quiet")
            git("add", ".")
            git("-c", "user.name=DATA Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "DATA fixture")
            value["control_identity"].update(source_head=git("rev-parse", "HEAD"), source_tree=git("rev-parse", "HEAD^{tree}"))
            self.assertEqual(self.prelaunch(value).returncode, 0)
            (root / "contrib/ml-dsa-console/runtime.py").write_bytes(b"# changed unpinned imported helper\n")
            self.assertNotEqual(self.prelaunch(value).returncode, 0)
            git("checkout", "--", "contrib/ml-dsa-console/runtime.py")
            worktree = parent / "worktree"
            git("worktree", "add", "--detach", str(worktree), "HEAD")
            self.assertTrue((worktree / ".git").is_file())
            value["repo"] = str(worktree)
            observed = self.prelaunch(value)
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            self.assertTrue(json.loads(observed.stdout)["source_git_observed"])

    def test_payload_preserves_qualified_binary_and_contract(self):
        self.assertEqual(driver.validate_payload(payload(), qualified(), "a"), payload())
        for changed in ("source_head", "source_tree", "manifest_sha256"):
            wrong = payload()
            wrong[changed] = "f" * len(wrong[changed])
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                driver.validate_payload(wrong, qualified(), "a")
        wrong = payload()
        wrong["files"]["seed/mldsa-demo-build/bin/pqbtcd"] = "f" * 64
        with self.assertRaises(ValueError):
            driver.validate_payload(wrong, qualified(), "a")

    def test_payload_refuses_escape_and_another_transition_version(self):
        for name in ("/etc/passwd", "seed/../escape", "seed\n/injected"):
            wrong = payload()
            wrong["files"][name] = "f" * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                driver.validate_payload(wrong, qualified(), "a")
        with self.assertRaises(ValueError):
            driver.validate_payload(payload(), qualified(), "b")

    def test_actual_process_hash_and_uid_are_required(self):
        version = {**qualified(), "payload": payload()}
        summary = {key: payload()[key] for key in ("version", "source_head", "source_tree", "manifest_sha256")}
        summary.update(node_sha256="a" * 64, signer_sha256="b" * 64,
                       payload_sha256=hashlib.sha256(driver.canonical(payload()) + b"\n").hexdigest())
        value = {"schema": "PQBTC-RUNPOD-NATIVE-IDENTITY-1", "backend": "native", "pod_id": "test-pod-123",
                 "namespace": "pqbtc-runpod-test", "payload": summary,
                 "payload_root": "/opt/pqbtc-runpod/versions/a3", "active_seed": "/opt/pqbtc-runtime/seed",
                 "running_node": {"uid": 1001, "pid": 12, "sha256": "a" * 64}, "running_signer": None, "signer_running": False}
        host = {"native": {"pod_id": "test-pod-123", "namespace": "pqbtc-runpod-test",
                           "versions_root": "/opt/pqbtc-runpod/versions", "runtime_root": "/opt/pqbtc-runtime"}}
        driver.validate_native_identity(host, value, version)
        for field, wrong in (("uid", 0), ("sha256", "f" * 64), ("pid", 1)):
            changed = copy.deepcopy(value)
            changed["running_node"][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                driver.validate_native_identity(host, changed, version)
        value["signer_running"] = True
        with self.assertRaises(ValueError):
            driver.validate_native_identity(host, value, version)
        signer = {"proof_kind": "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD", "pid": 23, "start": "99", "uid": 1000,
                  "session": 23, "pgid": 23, "sha256": "b" * 64, "live": True, "pidfd_bound": True,
                  "post_exec_executable_observable": False, "no_new_privileges": 1,
                  "capabilities": dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapAmb"), "0000000000000000"),
                  "pre_exec_file": {"path": "/opt/pqbtc-runpod/versions/a3/seed/demo-signer-bin/pilot-signer",
                                    "device": 1, "inode": 7, "size": 100}}
        value["running_signer"] = signer
        driver.validate_native_identity(host, value, version)
        for field, wrong in (("sha256", "f" * 64), ("pidfd_bound", False), ("proof_kind", "ASSUMED"),
                             ("post_exec_executable_observable", True), ("uid", 0), ("no_new_privileges", 0)):
            changed = copy.deepcopy(value)
            changed["running_signer"][field] = wrong
            with self.subTest(signer_field=field), self.assertRaises(ValueError):
                driver.validate_native_identity(host, changed, version)

    def test_process_crash_is_not_a_provider_restart(self):
        with self.assertRaises(ValueError):
            driver.validate_restart_receipt({"crashed": True, "restarted": True,
                                             "crash_kind": "OWNED_NATIVE_APPLICATION_PROCESS_GROUPS"}, "test-pod-123")
        value = restart()
        driver.validate_restart_receipt(value, "test-pod-123")
        value["after_generation"] = value["before_generation"]
        with self.assertRaises(ValueError):
            driver.validate_restart_receipt(value, "test-pod-123")


class TransportTests(unittest.TestCase):
    def test_strict_transport_with_provider_public_key_metadata(self):
        value = transport()
        value.update(pod_id="test-pod-123", generation="gen2", hostkey_source="AUTHENTICATED_PROVIDER_EXEC_PUBLIC_KEY_ONLY",
                     known_hosts_sha256="f" * 64)
        self.assertEqual(driver.validate_ssh(value), transport())

    def test_transport_rejects_hooks_keys_forwarding_and_commands(self):
        for injection in (["-i", "/private-key"], ["-F/tmp/config"], ["-L1:host:2"], ["-J", "jump"],
                          ["-oProxyCommand=malicious"], ["-o", "IdentityFile=/private-key"], ["some-command"]):
            value = transport()
            value["argv"][-1:-1] = injection
            with self.subTest(injection=injection), self.assertRaises(ValueError):
                driver.validate_ssh(value)

    def test_transport_cannot_disable_pinning_or_override_a_prior_option(self):
        for option in ("StrictHostKeyChecking=no", "GlobalKnownHostsFile=/another/file", "ForwardAgent=yes"):
            value = transport()
            value["argv"][-1:-1] = ["-o", option]
            with self.subTest(option=option), self.assertRaises(ValueError):
                driver.validate_ssh(value)


class ControllerBoundaryTests(unittest.TestCase):
    def test_all_remote_python_control_entrypoints_disable_bytecode(self):
        docker = {"backend": "docker", "repo": "/control", "state_dir": "/task/control", "control_identity": {},
                  "role": "bootstrap", "container": "pqbtc-mldsa-public-soak-data", "p2p_port": 23833,
                  "sudo_docker": False, "transport": {"kind": "local"},
                  "versions": {"a": {"remote_descriptor": "/task/descriptor.json"}}}
        native = {**docker, "backend": "native", "role": "follower", "transport": transport(), "_attempt_claim": {},
                  "native": {"namespace": "pqbtc-runpod-data", "pod_id": "test-pod-123", "data_root": "/var/lib/pqbtc/data/data",
                             "versions_root": "/opt/pqbtc-runpod/versions", "runtime_root": "/opt/pqbtc-runtime"}}
        self.assertEqual(driver.agent_command(docker, "future")[:2], ["python3", "-B"])
        self.assertEqual(shlex.split(driver.agent_command(native, "future")[-1])[:2], ["python3", "-B"])
        def blocked(_host, arguments, **kwargs):
            self.assertEqual(arguments[:2], ["python3", "-B"])
            raise RuntimeError("DATA-only vector inspection; no remote execution")
        with patch.object(driver.base, "host_json", side_effect=blocked):
            for operation, arguments in ((driver.prelaunch_host, (native,)), (driver.namespace_probe, (native,)),
                                         (driver.namespace_claim, (native, "0" * 32)), (driver.emergency_stop_owned, (native,))):
                with self.subTest(operation=operation.__name__), self.assertRaises(RuntimeError):
                    operation(*arguments)
        with patch.object(driver, "_host_json", return_value={}) as boundary:
            driver.host_json({}, ["python3", "-I", "-c", "print(0)"])
            self.assertEqual(boundary.call_args.args[1][:3], ["python3", "-B", "-I"])

    def test_hardened_signer_identity_uses_fd_proof_without_proc_executable_read(self):
        proof = {"proof_kind": "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD", "pid": 23, "start": "99"}
        control = types.SimpleNamespace(manager=types.SimpleNamespace(identity=lambda: {"signer_execution_proof": proof}),
                                        _signer=types.SimpleNamespace(pid=23, poll=lambda: None), _signer_info={"start": "99"})
        holder = types.SimpleNamespace(controller=control, pod_id="test-pod-123", deadline=time.time() + 5,
                                       monotonic_deadline=time.monotonic() + 5)
        def observed(name, uid, **kwargs):
            self.assertEqual((name, uid), ("pqbtcd", 1001))
            return {"sha256": "a" * 64, "uid": 1001}
        with patch.object(agent, "native_process", side_effect=observed):
            value = agent.NativeAgent.act(holder, "identity", {})
        self.assertTrue(value["signer_running"])
        self.assertEqual(value["running_signer"], proof)

    def test_effective_cpu_set_is_finite_and_bounded(self):
        self.assertEqual(agent.cpuset_count("0-3,8,9"), 6)
        for value in ("", "-1", "1-0", "0-999999999", "0,malformed"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                agent.cpuset_count(value)

    def test_missing_record_control_really_targets_both_selected_files(self):
        calls = []
        controller = types.SimpleNamespace(journal={"checkpoint": {"wallet_id": "1" * 32, "next_receive": 5, "next_change": 4}},
                                           manager=types.SimpleNamespace(data_root=Path("/test-owned-data")),
                                           action=lambda *args: calls.append(("action", args)),
                                           _stop_worker=lambda: calls.append(("stop_worker",)),
                                           _invoke=lambda *args: calls.append(("invoke", args)))
        result = agent.quarantine_records(controller)
        invokes = [item[1] for item in calls if item[0] == "invoke"]
        self.assertEqual([item[0] for item in invokes], ["1000:1000", "1001:1000"])
        self.assertEqual(invokes[0][-2], "wallet.dat")
        self.assertEqual(invokes[1][-2], "public-wallet.json")
        self.assertTrue(result["selected_record_missing"] and result["public_record_missing"])
        self.assertEqual(calls[1], ("stop_worker",))

    def test_full_elapsed_time_cannot_be_replaced_by_preflight(self):
        self.assertEqual(driver.base.duration_for("soak"), 86400)
        self.assertEqual(driver.base.duration_for("preflight"), 900)
        for mono, wall in ((900, 900), (86399, 86400), (86400, 86399)):
            with self.subTest(mono=mono, wall=wall), self.assertRaises(ValueError):
                driver.base.require_elapsed("soak", mono, wall)

    def test_public_helper_is_pinned_bounded_and_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "helper.py"
            path.write_text("print('{\"result\":\"PASS\"}')\n")
            helper = {"argv": [sys.executable, str(path)], "script_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertEqual(driver.public_command(helper), {"result": "PASS"})
            path.write_text("print('changed')\n")
            with self.assertRaises(ValueError):
                driver.public_command(helper)
            path.write_text("import time\ntime.sleep(5)\n")
            helper["script_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                driver.public_command(helper, timeout=0.05)

    def test_provider_helper_stops_heirs_after_leader_exit(self):
        for closed_pipes in (False, True):
            with self.subTest(closed_pipes=closed_pipes), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, child_pid = root / "helper.py", root / "child.pid"
                output = ", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL" if closed_pipes else ""
                path.write_text("import pathlib,subprocess,sys\n"
                                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(3)']" + output + ")\n"
                                "pathlib.Path(" + repr(str(child_pid)) + ").write_text(str(child.pid))\n"
                                "print('{\"result\":\"PASS\"}',flush=True)\n")
                helper = {"argv": [sys.executable, str(path)], "script_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                if closed_pipes:
                    self.assertEqual(driver.public_command(helper, timeout=0.3), {"result": "PASS"})
                else:
                    with self.assertRaises(ValueError):
                        driver.public_command(helper, timeout=0.3)
                pid = int(child_pid.read_text())
                deadline, running = time.monotonic() + 1, True
                while running and time.monotonic() < deadline:
                    observed = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
                    state = observed.stdout.strip()
                    running = observed.returncode == 0 and bool(state) and not state.startswith("Z")
                    if running:
                        time.sleep(0.02)
                self.assertFalse(running, "Exited helper left its same-session child running")

    def test_provider_restart_preserves_wallet_before_confirmed_spend(self):
        def exercise(lower_floor):
            before = {"wallet": {"wallet_id": "1" * 32, "next_receive": 5, "next_change": 4},
                      "nodes": [{"height": 102, "tip": "a" * 64, "utxo_hash": "b" * 64, "utxo_count": 102}]}
            after = copy.deepcopy(before)
            if lower_floor:
                after["wallet"]["next_receive"] -= 1
            host = {"name": "runpod", "role": "follower", "backend": "native", "native": {"pod_id": "test-pod-123"},
                    "_live_identity": {"volume_id": "2" * 32}}
            events = []
            run = types.SimpleNamespace(config={"provider_restart": {"argv": []}}, follower="runpod", bootstrap="mac",
                                        hosts={"runpod": host}, statuses={"runpod": before}, operator_values={"runpod": "disposable"},
                                        until="future", agents={"runpod": types.SimpleNamespace(close=lambda: {"exit_code": 0})},
                                        prelaunch={}, guard=types.SimpleNamespace(snapshot=lambda _: dict(before["wallet"])),
                                        statuses_now=lambda: None, log=types.SimpleNamespace(append=lambda *args: events.append(args)),
                                        action=lambda _, kind, *args, **kwargs: {"volume_id": "2" * 32} if kind == "identity" else after if kind == "status" else {},
                                        identity=lambda *args: None, bridge=lambda: None, sample=lambda: None,
                                        payment=lambda *args: {"confirmed": True})
            with patch.object(driver, "public_command", return_value=restart()), patch.object(driver, "prelaunch_host", return_value={}), \
                    patch.object(driver.base, "AgentClient", return_value=object()):
                result = driver.Soak.provider_restart_rehearsal(run)
            self.assertTrue(result["floors_preserved"])
            self.assertEqual(events[-1][0], "actual_provider_restart_verified")
        exercise(False)
        with self.assertRaises(ValueError):
            exercise(True)


if __name__ == "__main__":
    unittest.main()
