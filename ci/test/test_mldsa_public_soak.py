"""Soak evidence/time/slot/floor gates; unit fixtures never become a soak."""
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
import unittest
import hashlib
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "contrib/ml-dsa-qualification/run_public_soak.py"


class PublicSoakTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = None
        if DRIVER.exists():
            spec = importlib.util.spec_from_file_location("public_soak_driver_tests", DRIVER)
            cls.driver = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.driver)

    def runner(self):
        self.assertIsNotNone(self.driver, "Reusable two-host public soak runner is missing")
        return self.driver

    def test_short_or_preflight_time_never_becomes_a_24_hour_pass(self):
        runner = self.runner()
        self.assertEqual(runner.duration_for("soak"), 86400)
        self.assertEqual(runner.duration_for("preflight"), 900)
        with self.assertRaises(ValueError):
            runner.require_elapsed("soak", 86399.999, 86400)
        with self.assertRaises(ValueError):
            runner.require_elapsed("soak", 86400, 86399.999)
        self.assertEqual(runner.require_elapsed("preflight", 900, 900), "PREFLIGHT_PASS")
        self.assertEqual(runner.require_elapsed("soak", 86400, 86400), "PASS")

    def test_ssh_arguments_are_quoted_as_data_without_a_committed_host_route(self):
        runner = self.runner()
        host = {"transport": {"kind": "ssh", "argv": ["ssh", "-T", "unit@example.invalid"]},
                "repo": "/tmp/owned $(literal) project", "state_dir": "/tmp/private ' state",
                "container": "pqbtc-mldsa-public-soak-unit", "p2p_port": 23833, "sudo_docker": True,
                "role": "bootstrap", "versions": {"a": {"remote_descriptor": "/tmp/descriptor ' a.json"}}}
        command = runner.agent_command(host, "2026-11-12T00:00:00+00:00")
        self.assertEqual(command[:3], host["transport"]["argv"])
        remote = shlex.split(command[-1])
        self.assertIn(host["repo"] + "/contrib/ml-dsa-qualification/public_soak_agent.py", remote)
        self.assertEqual(remote[remote.index("--state-dir") + 1], host["state_dir"])

    def test_floor_or_identity_rollback_and_reissued_address_are_terminal(self):
        runner = self.runner()
        guard = runner.FloorGuard()
        def status(receive, change=0, identity="ab" * 16):
            return {"wallet": {"wallet_id": identity, "next_receive": receive, "next_change": change}}
        guard.observe("one", status(5))
        before = guard.snapshot("one")
        guard.observe("one", status(6))
        entry = {"branch": 0, "index": 5, "address": "tq1public-unit-address"}
        guard.issued("one", entry, before)
        for value in (status(4), status(6, identity="cd" * 16)):
            with self.assertRaises(ValueError):
                guard.observe("one", value)
        with self.assertRaises(ValueError):
            guard.issued("one", entry, before)

    def test_only_declared_fault_time_can_explain_a_missed_slot(self):
        runner = self.runner()
        ledger = runner.SlotLedger("soak")
        with self.assertRaises(ValueError):
            ledger.missed(0, [])
        ledger.missed(0, [{"name": "crash", "started_elapsed": 0, "finished_elapsed": 59}])
        self.assertEqual(ledger.rows[0]["fault"], "crash")
        with self.assertRaises(ValueError):
            ledger.success(2, 0.1)
        ledger.success(1, 0.1, started_elapsed=60)
        with self.assertRaises(ValueError):
            ledger.success(2, 60.001)

    def test_event_chain_detects_tampering_and_never_writes_secret_fields(self):
        runner = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = runner.EventLog(path, secrets=("unit-operator-material",))
            log.append("one", {"txid": "ab" * 32})
            log.append("two", {"tip": "cd" * 32})
            for value in ({"password": "public-test-marker"}, {"value": "unit-operator-material"}):
                with self.assertRaises(ValueError):
                    log.append("secret_refused", value)
            log.close()
            self.assertEqual(runner.verify_events(path)["count"], 2)
            lines = path.read_text(encoding="utf8").splitlines()
            changed = json.loads(lines[0])
            changed["data"]["txid"] = "ef" * 32
            lines[0] = json.dumps(changed)
            path.write_text("\n".join(lines) + "\n", encoding="utf8")
            with self.assertRaises(ValueError):
                runner.verify_events(path)

    def test_controller_wrappers_and_flat_probe_results_keep_their_distinct_shapes(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "one", "role": "bootstrap"}, {"name": "two", "role": "follower"}]}
        soak = runner.Soak(config, "preflight", Log(), {}, "future")
        status = {"wallet": {"wallet_id": "ab" * 16, "next_receive": 1, "next_change": 0}}
        class Agent:
            def call(self, action, *_args, **_kwargs):
                if action == "transaction":
                    return {"result": {"txid": "cd" * 32, "confirmed": True}, "status": status}
                return {"result": "PASS", "scope": "BOUNDED_PUBLIC_P2P_OVERSIZED_HEADER_CONTROL"}
        soak.agents["one"] = Agent()
        with self.subTest(shape="controller"):
            self.assertEqual(soak.action("one", "transaction").get("txid"), "cd" * 32)
        with self.subTest(shape="flat"):
            self.assertIsInstance(soak.action("one", "hostile"), dict)

    def qualified(self):
        runner = self.runner()
        source = runner.load_module(ROOT / "contrib/ml-dsa-console/source_runtime.py", "soak_descriptor_fixture")
        manifest = {"schema": "PQBTC-MLDSA44-SOURCE-BUILD-1", "source_head": "a" * 40,
                    "source_tree": "b" * 40, "compiler": "gcc", "architecture": "x86_64",
                    "sha256": {path: "cd" * 32 for path in source.REQUIRED_HASHES}}
        descriptor = {"schema": source.DESCRIPTOR_SCHEMA, "image": "sha256:" + "ab" * 32, "manifest": manifest,
                      "manifest_sha256": hashlib.sha256(source.canonical(manifest)).hexdigest()}
        identity = {"head": manifest["source_head"], "tree": manifest["source_tree"], "sha256": manifest["sha256"]}
        receipt = {"schema": "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1", "result": "PASS", "public_soak": False,
                   "emulated": False, "image": descriptor["image"], "manifest_sha256": descriptor["manifest_sha256"],
                   "source": {"head": manifest["source_head"], "tree": manifest["source_tree"]},
                   "architecture": "x86_64", "compiler": "gcc", "checks": {name: "PASS" for name in runner.REQUIRED_CHECKS},
                   "identity_before": identity, "identity_after": identity, "cleanup": "REMOVED"}
        return descriptor, receipt

    def test_prior_partial_emulated_or_wrong_binary_qualification_is_refused(self):
        runner = self.runner()
        descriptor, baseline = self.qualified()
        runner.validate_qualified_version(descriptor, baseline)
        values = [{**baseline, "result": "DEVELOPMENT_ONLY"}, {**baseline, "emulated": True},
                  {**baseline, "image": "sha256:" + "ef" * 32}, {**baseline, "checks": {}}]
        wrong = copy.deepcopy(baseline)
        wrong["identity_after"]["sha256"][runner.NODE] = "ef" * 32
        values.append(wrong)
        for index, value in enumerate(values):
            with self.subTest(index=index), self.assertRaises(ValueError):
                runner.validate_qualified_version(descriptor, value)

    def test_upgrade_requires_distinct_source_image_and_native_node_bytes(self):
        runner = self.runner()
        descriptor, receipt = self.qualified()
        first = runner.validate_qualified_version(descriptor, receipt)
        second = {**first, "source_head": "c" * 40, "source_tree": "d" * 40,
                  "image": "sha256:" + "ef" * 32, "node_sha256": "12" * 32}
        runner.validate_version_pair(first, second)
        for field in ("source_head", "source_tree", "image", "node_sha256"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.validate_version_pair(first, {**second, field: first[field]})

    def full_outcome(self):
        runner = self.runner()
        phases = [{"name": name, "started_elapsed": offset, "finished_elapsed": offset + 300, "result": "PASS"}
                  for name, offset in runner.FAULTS]
        for index, phase in enumerate(phases):
            phase["recovery_payment"] = {"sender": "one", "receiver": "two", "txid": f"{index + 1:064x}",
                                         "block_hash": f"{index + 101:064x}", "settle_seconds": 0.5,
                                         "recipient_in_mempool": True, "started_elapsed": phase["started_elapsed"] + 298,
                                         "completed_elapsed": phase["started_elapsed"] + 298.5}
        misses = {index for _name, offset in runner.FAULTS[:6] for index in range(offset // 60, offset // 60 + 5)}
        ledger = runner.SlotLedger("soak")
        for index in range(1440):
            if index in misses:
                ledger.missed(index, phases)
            else:
                ledger.success(index, 0.5, started_elapsed=index * 60)
        probe = {"result": "PASS", "scope": "ANONYMOUS_PUBLIC_TLS_NATIVE_P2P_HANDSHAKE_ONLY"}
        return ledger, phases, {"final_recovered_spend": True, "cleanup_ok": True, "public_start": probe, "public_end": probe}

    def test_final_pass_requires_every_fault_and_no_unexplained_payment_gap(self):
        runner = self.runner()
        ledger, phases, options = self.full_outcome()
        result = runner.validate_outcome("soak", 86400, 86400, ledger, phases, **options)
        self.assertEqual((result["result"], result["successful_normal_slots"], result["missed_slots"]), ("PASS", 1410, 30))
        for key in ("final_recovered_spend", "cleanup_ok"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_outcome("soak", 86400, 86400, ledger, phases, **{**options, key: False})
        with self.assertRaises(ValueError):
            runner.validate_outcome("soak", 86400, 86400, ledger, phases[:-1], **options)
        invalid = copy.deepcopy(ledger)
        invalid.rows[0] = {"slot": 0, "success": False, "fault": "crash"}
        with self.assertRaises(ValueError):
            runner.validate_outcome("soak", 86400, 86400, invalid, phases, **options)

    def test_bad_agent_readiness_stops_the_just_started_owned_process(self):
        runner = self.runner()
        children = []
        original = subprocess.Popen
        script = 'import sys;print("{}",flush=True);sys.stdin.read()'
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        try:
            with patch.object(runner, "agent_command", return_value=[sys.executable, "-c", script]), \
                    patch.object(runner.subprocess, "Popen", side_effect=spawn), \
                    patch.object(runner, "emergency_stop_owned", create=True, return_value={"backend_stopped": True}):
                with self.assertRaises(ValueError):
                    runner.AgentClient({}, "future", ())
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), "Failed constructor left its agent alive")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                for pipe in (child.stdin, child.stdout, child.stderr):
                    if pipe and not pipe.closed:
                        pipe.close()

    def test_event_clock_span_cannot_be_replaced_with_a_claimed_elapsed_summary(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "require_event_duration", None)), "Independent event-clock duration gate is missing")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = runner.EventLog(path)
            log.append("public_clock_started", {"duration_seconds": 86400})
            log.append("public_clock_completed", {"monotonic_seconds": 86400, "wall_seconds": 86400})
            log.close()
            with self.assertRaises(ValueError):
                runner.require_event_duration(runner.verify_events(path), "soak")

    def test_non_json_container_cannot_bypass_public_field_inspection(self):
        runner = self.runner()
        with self.assertRaises(ValueError):
            runner.public_value(({"password": "public-unit-refusal-marker"},))

    def test_complete_two_host_configuration_joins_local_receipts_before_launch(self):
        runner = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            descriptor, receipt = self.qualified()
            versions = {}
            for label in ("a", "b"):
                desc, proof = copy.deepcopy(descriptor), copy.deepcopy(receipt)
                if label == "b":
                    desc["image"] = "sha256:" + "ef" * 32
                    desc["manifest"].update(source_head="c" * 40, source_tree="d" * 40)
                    desc["manifest"]["sha256"][runner.NODE] = "12" * 32
                    source = runner.load_module(ROOT / "contrib/ml-dsa-console/source_runtime.py", "soak_config_descriptor_fixture")
                    desc["manifest_sha256"] = hashlib.sha256(source.canonical(desc["manifest"])).hexdigest()
                    proof.update(image=desc["image"], manifest_sha256=desc["manifest_sha256"],
                                 source={"head": "c" * 40, "tree": "d" * 40})
                    for key in ("identity_before", "identity_after"):
                        proof[key].update(head="c" * 40, tree="d" * 40, sha256=desc["manifest"]["sha256"])
                desc_path, receipt_path = folder / (label + "-descriptor.json"), folder / (label + "-receipt.json")
                desc_path.write_text(json.dumps(desc), encoding="utf8")
                receipt_path.write_text(json.dumps(proof), encoding="utf8")
                versions[label] = {"descriptor": str(desc_path), "native_receipt": str(receipt_path), "remote_descriptor": str(desc_path)}
            def host(name, role, transport):
                return {"name": name, "role": role, "transport": transport, "repo": "/tmp/public-source",
                        "state_dir": "/tmp/new-public-state", "container": "pqbtc-mldsa-public-soak-unit",
                        "p2p_port": 23833, "sudo_docker": role == "bootstrap", "versions": copy.deepcopy(versions)}
            config = {"schema": runner.CONFIG_SCHEMA, "hosts": [host("one", "bootstrap", {"kind": "ssh", "argv": ["ssh", "-T", "unit@example.invalid"]}),
                                                                 host("two", "follower", {"kind": "local"})],
                      "public_endpoint": {"hostname": "owned.example", "port": 443, "public_ips": ["8.8.8.8"]},
                      "cleanup_public_route": False}
            value = runner.prepare_config(config)
            self.assertIn("qualified", value["hosts"][0]["versions"]["a"])
            self.assertNotIn("qualified", config["hosts"][0]["versions"]["a"])
            swapped = copy.deepcopy(config)
            swapped["hosts"][0]["transport"] = {"kind": "local"}
            swapped["hosts"][0]["sudo_docker"] = False
            swapped["hosts"][1]["transport"] = {"kind": "ssh", "argv": ["ssh", "-T", "unit@example.invalid"]}
            swapped["hosts"][1]["sudo_docker"] = True
            try:
                actual = runner.prepare_config(swapped)
            except ValueError as error:
                self.fail("Local bootstrap plus SSH follower must be accepted: " + str(error))
            self.assertEqual(actual["hosts"][0]["role"], "bootstrap")
            self.assertEqual(actual["hosts"][0]["transport"]["kind"], "local")
            self.assertEqual(actual["hosts"][1]["role"], "follower")
            self.assertEqual(actual["hosts"][1]["transport"]["kind"], "ssh")
            for invalid in ([{**host, "transport": {"kind": "local"}} for host in swapped["hosts"]],
                            [{**host, "transport": {"kind": "ssh", "argv": ["ssh", "unit@example.invalid"]}} for host in swapped["hosts"]]):
                with self.assertRaises(ValueError):
                    runner.prepare_config({**swapped, "hosts": invalid})
            with self.assertRaises(ValueError):
                runner.prepare_config({**config, "hosts": config["hosts"][:1]})

    def test_maintenance_crossing_a_slot_deadline_cannot_catch_up_a_missing_payment(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "one", "role": "bootstrap"}, {"name": "two", "role": "follower"}]}
        run = runner.Soak(config, "soak", Log(), {}, "future")
        run.started_mono = run.started_wall = 0
        for index in range(10):
            run.ledger.rows.append({"slot": index, "success": True, "settle_seconds": 0.1})
        clock = [600.0]
        run.sample = lambda: None
        run.action = lambda *_args, **_kwargs: {"baseline_accepted": True, "invalid_signature_allowed": False,
                                               "wrong_network_refused": True, "broadcast": False,
                                               "reject_reason": "mandatory-script-verify-flag-failed"}
        def probe():
            clock[0] += 70
        run.probe = probe
        def payment(*_args):
            raise ValueError("late_payment_attempt")
        run.payment = payment
        with patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(runner.time, "time", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, "Unexplained missed"):
                run.workload()

    def test_adverse_control_requires_signature_verification_as_the_rejection_reason(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "validate_adverse", None)), "Actual signature-rejection reason gate is missing")
        value = {"baseline_accepted": True, "invalid_signature_allowed": False, "wrong_network_refused": True,
                 "broadcast": False, "reject_reason": "mandatory-script-verify-flag-failed"}
        runner.validate_adverse(value)
        for reason in ("missing-inputs", "mempool min fee not met", "", None):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                runner.validate_adverse({**value, "reject_reason": reason})

    def test_payment_waits_for_receiver_mempool_before_mining(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "one", "role": "bootstrap"}, {"name": "two", "role": "follower"}]}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        run.receive = lambda _host: "tq1public-unit-address"
        run.agree = lambda **_kwargs: None
        seen, state = [], {"relayed": False, "polls": 0}
        def action(host, action, params=None, **_kwargs):
            seen.append((host, action, params))
            if action == "send":
                return {"broadcast": True, "txid": "ab" * 32}
            if action == "transaction" and "block_hash" not in params:
                state["polls"] += 1
                state["relayed"] = state["polls"] >= 2
                return {"txid": "ab" * 32, "in_mempool": state["relayed"]}
            if action == "mine":
                self.assertTrue(state["relayed"], "Mined before the receiver observed unconfirmed transaction relay")
                return {"blocks": ["cd" * 32]}
            return {"txid": "ab" * 32, "confirmed": True, "confirmations": 1, "block_hash": "cd" * 32}
        run.action = action
        with patch.object(runner.time, "sleep", return_value=None):
            value = run.payment("one", "two")
        self.assertTrue(value["recipient_in_mempool"])
        self.assertEqual(state["polls"], 2)
        self.assertEqual(value["txid"], "ab" * 32)

    def test_workload_clock_origin_follows_the_fsynced_start_event(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "begin_workload", None)), "Fsynced workload clock origin helper missing")
        clock = [100.0]
        class Log:
            def append(self, *_args): clock[0] += 0.75
        class Run:
            started_mono = started_wall = None
        run, report = Run(), {}
        with patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(runner.time, "time", side_effect=lambda: clock[0]):
            runner.begin_workload(run, Log(), report, "soak", {})
        self.assertEqual(run.started_mono, 100.75)
        self.assertEqual(run.started_wall, 100.75)

    def test_fault_cannot_pass_without_a_new_payment_inside_its_remaining_budget(self):
        runner = self.runner()
        ledger, phases, options = self.full_outcome()
        invalid = copy.deepcopy(phases)
        invalid[0].pop("recovery_payment")
        with self.assertRaises(ValueError):
            runner.validate_outcome("soak", 86400, 86400, ledger, invalid, **options)
        invalid = copy.deepcopy(phases)
        invalid[0]["recovery_payment"]["completed_elapsed"] = invalid[0]["finished_elapsed"] + 1
        with self.assertRaises(ValueError):
            runner.validate_outcome("soak", 86400, 86400, ledger, invalid, **options)

    def test_funnel_snapshot_requires_the_actual_owned_loopback_handler(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "funnel_snapshot", None)), "Funnel ownership snapshot helper missing")
        host = {"p2p_port": 23833}
        endpoint = {"hostname": "owned.example", "port": 443}
        config = {"TCP": {"443": {"TCPForward": "127.0.0.1:23833", "TerminateTLS": "owned.example"},
                          "8443": {"TCPForward": "127.0.0.1:9999", "TerminateTLS": "other.example"}},
                  "AllowFunnel": {"owned.example:443": True, "other.example:8443": True}}
        point = runner.funnel_snapshot(config, host, endpoint)
        self.assertEqual(point["handler"], config["TCP"]["443"])
        wrong = copy.deepcopy(config)
        wrong["TCP"]["443"]["TCPForward"] = "127.0.0.1:9999"
        with self.assertRaises(ValueError):
            runner.funnel_snapshot(wrong, host, endpoint)
        self.assertFalse(runner.same_funnel_handler(wrong, point))
        other_changed = copy.deepcopy(config)
        other_changed["TCP"]["8443"]["TCPForward"] = "127.0.0.1:9998"
        self.assertTrue(runner.same_funnel_handler(other_changed, point))

    def test_prelaunch_rejects_emulation_dirty_control_code_and_same_docker_daemon(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "validate_prelaunch", None)), "Prelaunch host identity gate missing")
        descriptor, receipt = self.qualified()
        qualified = runner.validate_qualified_version(descriptor, receipt)
        qualified["descriptor"]["manifest"]["sha256"].update({runner.SOURCE_PREFIX + path: "ab" * 32 for path in runner.CONTROL_FILES})
        host = {"versions": {"a": {"qualified": qualified}, "b": {"qualified": qualified}}}
        value = {"source_head": qualified["source_head"], "source_tree": qualified["source_tree"], "clean": True,
                 "control_sha256": {path: "ab" * 32 for path in runner.CONTROL_FILES},
                 "docker_architecture": "x86_64", "docker_daemon_id": "public-unit-daemon-one"}
        runner.validate_prelaunch(host, value)
        for invalid in ({**value, "clean": False}, {**value, "docker_architecture": "aarch64"},
                        {**value, "control_sha256": {}}):
            with self.assertRaises(ValueError):
                runner.validate_prelaunch(host, invalid)
        with self.assertRaises(ValueError):
            runner.require_distinct_daemons({"one": value, "two": value})

    def test_volume_anchor_rejects_first_upgrade_that_silently_replaces_data(self):
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "require_original_volume", None)), "Initial volume identity anchor missing")
        runner.require_original_volume({"one": "ab" * 16}, "one", "ab" * 16)
        with self.assertRaises(ValueError):
            runner.require_original_volume({"one": "ab" * 16}, "one", "cd" * 16)

    def test_stuck_agent_stops_backend_before_and_after_terminating_its_watchdog(self):
        import io
        runner = self.runner()
        self.assertTrue(callable(getattr(runner, "emergency_stop_owned", None)), "Independent Docker-stop fallback missing")
        events = []
        class Process:
            stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
            returncode = None
            def poll(self): return self.returncode
            def terminate(self):
                events.append("terminate")
                self.returncode = -15
            def wait(self, **_kwargs): return self.returncode
        agent = runner.AgentClient.__new__(runner.AgentClient)
        agent.host, agent.process, agent.stderr_closed = {}, Process(), True
        agent.stderr_bytes, agent.stderr_hash = 0, hashlib.sha256()
        agent._stderr = lambda: None
        def stop(_host):
            events.append("independent_stop")
            return {"backend_stopped": True}
        ticks = iter([0, 100])
        with patch.object(runner.time, "monotonic", side_effect=lambda: next(ticks, 100)), \
                patch.object(runner, "emergency_stop_owned", side_effect=stop):
            with self.assertRaises(ValueError):
                agent.close()
        self.assertEqual(events, ["independent_stop", "terminate", "independent_stop"])

    def test_changed_funnel_handler_is_preserved_without_any_off_command(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        endpoint = {"hostname": "owned.example", "port": 443, "public_ips": ["8.8.8.8"]}
        host = {"name": "one", "role": "bootstrap", "p2p_port": 23833, "transport": {"kind": "local"}}
        config = {"hosts": [host, {"name": "two", "role": "follower"}], "public_endpoint": endpoint, "cleanup_public_route": True}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        initial = {"TCP": {"443": {"TCPForward": "127.0.0.1:23833", "TerminateTLS": "owned.example"}},
                   "AllowFunnel": {"owned.example:443": True}}
        run.funnel = runner.funnel_snapshot(initial, host, endpoint)
        changed = copy.deepcopy(initial)
        changed["TCP"]["443"]["TCPForward"] = "127.0.0.1:9999"
        with patch.object(runner, "read_funnel", return_value=changed), patch.object(runner.subprocess, "run") as command:
            with self.assertRaises(ValueError):
                run.cleanup()
        command.assert_not_called()

    def test_independent_stop_helper_uses_immutable_ids_and_preserves_unrelated_containers(self):
        runner = self.runner()
        record = {"Name": "/pqbtc-mldsa-public-soak-unit", "Id": "ab" * 32, "Image": "sha256:" + "cd" * 32,
                  "Config": {"Labels": {"org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": runner.PROFILE,
                                        "org.pqbtc.console.build": "source-1", "org.pqbtc.console.manifest": "ef" * 32}},
                  "HostConfig": {"PortBindings": {"23833/tcp": [{"HostIp": "127.0.0.1", "HostPort": "23833"}]}},
                  "Mounts": [{"Type": "volume", "Name": "pqbtc-mldsa-public-soak-unit-data-v1", "Destination": "/var/lib/pqbtc", "RW": True}],
                  "State": {"Running": True}}
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fake = folder / "docker.py"
            fake.write_text('''import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); state=json.loads(p.read_text(encoding='utf8')); args=sys.argv[2:]
if args[0]=='inspect':
 selector=args[-1]
 value=state['record'] if selector in (state['record']['Id'],state['record']['Name'][1:]) else None
 if value is None: print('No such object:',file=sys.stderr);raise SystemExit(1)
 print(json.dumps(value))
elif args[0]=='volume': print(json.dumps(state['volume']))
elif args[0]=='run': print(json.dumps(state['marker']))
elif args[0]=='stop':
 state['stops'].append(args[-1]); assert args[-1]==state['record']['Id']
 state['record']['State']['Running']=False;p.write_text(json.dumps(state),encoding='utf8');print(args[-1])
else: raise SystemExit(2)
''', encoding="utf8")
            for label in ("owned", "foreign", "wrong_port", "wrong_manifest", "wrong_marker", "wrong_attempt", "missing_journal"):
                state = copy.deepcopy(record)
                if label == "foreign":
                    state["Config"]["Labels"]["org.pqbtc.console.schema"] = "unrelated"
                if label == "wrong_port":
                    state["HostConfig"]["PortBindings"]["23833/tcp"][0]["HostPort"] = "8844"
                if label == "wrong_manifest":
                    state["Config"]["Labels"]["org.pqbtc.console.manifest"] = "12" * 32
                state_path = folder / (label + ".json")
                volume = {"Name": "pqbtc-mldsa-public-soak-unit-data-v1", "Driver": "local", "Options": None,
                          "Labels": {"org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": runner.PROFILE}}
                marker = {"volume_id": "11" * 16, "profile_sha256": runner.PROFILE}
                if label == "wrong_marker":
                    marker["volume_id"] = "22" * 16
                state_path.write_text(json.dumps({"record": state, "volume": volume, "marker": marker, "stops": []}), encoding="utf8")
                owned = folder / (label + "-state")
                owned.mkdir(mode=0o700)
                claim = {"schema": runner.CLAIM_SCHEMA, "attempt_id": "aa" * 16, "container": record["Name"][1:],
                         "volume": volume["Name"], "port": 23833, "profile_sha256": runner.PROFILE}
                disk_claim = copy.deepcopy(claim)
                if label == "wrong_attempt":
                    disk_claim["attempt_id"] = "bb" * 16
                claim_path = owned / runner.CLAIM_FILE
                claim_path.write_text(json.dumps(disk_claim), encoding="utf8")
                claim_path.chmod(0o600)
                if label != "missing_journal":
                    journal = owned / "public-runtime.json"
                    journal.write_text(json.dumps({"schema": "PQBTC-MLDSA44-PUBLIC-RUNTIME-1", "container": record["Name"][1:],
                                                  "volume": volume["Name"], "volume_id": "11" * 16, "port": 23833,
                                                  "compatibility": {"profile_sha256": runner.PROFILE},
                                                  "descriptor": {"image": record["Image"], "manifest_sha256": "ef" * 32}}), encoding="utf8")
                    journal.chmod(0o600)
                payload = {"container": record["Name"][1:], "p2p_port": 23833, "profile": runner.PROFILE,
                           "images": {record["Image"]: "ef" * 32}, "docker": [sys.executable, str(fake), str(state_path)],
                           "state_dir": str(owned), "attempt_claim": claim, "expected_volume_id": "11" * 16}
                result = subprocess.run([sys.executable, "-c", runner.EMERGENCY_STOP_SCRIPT, json.dumps(payload)], capture_output=True, timeout=10)
                after = json.loads(state_path.read_text(encoding="utf8"))
                with self.subTest(label=label):
                    if label == "owned":
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        self.assertTrue(json.loads(result.stdout)["backend_stopped"])
                        self.assertEqual(after["stops"], [record["Id"]])
                        self.assertFalse(after["record"]["State"]["Running"])
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(after["stops"], [])

    def test_prelaunch_helper_hashes_control_files_without_importing_them(self):
        runner = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            folder, repo = Path(temporary), Path(temporary) / "repo"
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            git("config", "user.name", "Public fixture")
            git("config", "user.email", "fixture@example.invalid")
            for name in runner.CONTROL_FILES:
                target = repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("raise RuntimeError('prelaunch must never execute this file')\n", encoding="utf8")
            git("add", ".")
            git("commit", "-qm", "Public prelaunch fixture")
            fake = folder / "docker.py"
            fake.write_text('print(\'{"architecture":"aarch64","daemon_id":"public-unit-distinct-daemon"}\')\n', encoding="utf8")
            payload = {"repo": str(repo), "control_files": list(runner.CONTROL_FILES), "docker": [sys.executable, str(fake)],
                       "approved_revisions": [[git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")]]}
            result = subprocess.run([sys.executable, "-c", runner.PRELAUNCH_SCRIPT, json.dumps(payload)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            value = json.loads(result.stdout)
            self.assertTrue(value["clean"])
            self.assertEqual(value["source_head"], git("rev-parse", "HEAD"))
            self.assertEqual(value["docker_architecture"], "aarch64")
            self.assertEqual(set(value["control_sha256"]), set(runner.CONTROL_FILES))

    def test_failed_independent_stop_preserves_the_still_live_agent_watchdog(self):
        import io
        runner = self.runner()
        class Process:
            stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
            returncode = None
            def poll(self): return None
            def terminate(self): raise AssertionError("Killed the only live guard before proving backend shutdown")
        agent = runner.AgentClient.__new__(runner.AgentClient)
        agent.host, agent.process, agent.stderr_closed = {}, Process(), True
        agent.stderr_bytes, agent.stderr_hash = 0, hashlib.sha256()
        agent._stderr = lambda: None
        ticks = iter([0, 100])
        try:
            with patch.object(runner.time, "monotonic", side_effect=lambda: next(ticks, 100)), \
                    patch.object(runner, "emergency_stop_owned", side_effect=ValueError("unreachable host")):
                with self.assertRaisesRegex(ValueError, "watchdog was preserved"):
                    agent.close()
        finally:
            for pipe in (agent.process.stdin, agent.process.stdout, agent.process.stderr):
                pipe.close()

    def test_actual_fault_path_calls_payment_before_passing_with_shared_deadline(self):
        runner = self.runner()
        events = []
        class Log:
            def append(self, kind, _data): events.append(kind)
        config = {"hosts": [{"name": "one", "role": "bootstrap"}, {"name": "two", "role": "follower"}]}
        run = runner.Soak(config, "preflight", Log(), {"one": "unit", "two": "unit"}, "future")
        run.started_mono = runner.time.monotonic() - 75
        run.action = lambda *_args, **_kwargs: {"crashed": True, "restarted": True}
        run.bridge = lambda: None
        run.identity = lambda *_args: None
        run.agree = lambda: None
        run.sample = lambda: None
        def payment(sender, receiver):
            remaining = run.action_deadline - runner.time.monotonic()
            self.assertTrue(0 < remaining <= 300)
            events.append("recovery_payment")
            now = runner.time.monotonic() - run.started_mono
            return {"sender": sender, "receiver": receiver, "txid": "ab" * 32, "block_hash": "cd" * 32,
                    "settle_seconds": 0, "recipient_in_mempool": True, "started_elapsed": now, "completed_elapsed": now}
        run.payment = payment
        run.fault("crash")
        self.assertEqual(events[-2:], ["recovery_payment", "fault_completed"])
        self.assertEqual(run.phases[0]["recovery_payment"]["txid"], "ab" * 32)
        self.assertIsNone(run.action_deadline)

    def test_same_daemon_rejection_occurs_before_any_agent_is_started(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "one", "role": "bootstrap"}, {"name": "two", "role": "follower"}]}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        with patch.object(runner, "prelaunch_host", return_value={"docker_daemon_id": "same-public-unit-daemon"}), \
                patch.object(runner, "AgentClient") as launch:
            with self.assertRaisesRegex(ValueError, "same Docker daemon"):
                run.setup()
        launch.assert_not_called()

    def test_post_termination_backend_check_runs_even_if_agent_exits_during_signal(self):
        import io
        runner = self.runner()
        events = []
        class Process:
            stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
            returncode = None
            def poll(self): return self.returncode
            def terminate(self):
                events.append("terminate")
                self.returncode = 0
                raise ProcessLookupError("public-unit-race")
        agent = runner.AgentClient.__new__(runner.AgentClient)
        agent.host, agent.process, agent.stderr_closed = {}, Process(), True
        agent.stderr_bytes, agent.stderr_hash = 0, hashlib.sha256()
        agent._stderr = lambda: None
        def stop(_host):
            events.append("independent_stop")
            return {"backend_stopped": True}
        ticks = iter([0, 100])
        with patch.object(runner.time, "monotonic", side_effect=lambda: next(ticks, 100)), \
                patch.object(runner, "emergency_stop_owned", side_effect=stop):
            with self.assertRaises(ProcessLookupError):
                agent.close()
        self.assertEqual(events, ["independent_stop", "terminate", "independent_stop"])

    def test_old_matching_wallet_with_new_state_directory_is_never_a_cleanup_target(self):
        runner = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            state = folder / "docker-state.json"
            record = {"Name": "/pqbtc-mldsa-public-soak-old", "Id": "ab" * 32, "Image": "sha256:" + "cd" * 32,
                      "Config": {"Labels": {"org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": runner.PROFILE,
                                            "org.pqbtc.console.build": "source-1", "org.pqbtc.console.manifest": "ef" * 32}},
                      "HostConfig": {"PortBindings": {"23833/tcp": [{"HostIp": "127.0.0.1", "HostPort": "23833"}]}},
                      "State": {"Running": True}}
            state.write_text(json.dumps({"record": record, "stops": []}), encoding="utf8")
            fake = folder / "docker.py"
            fake.write_text('''import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); state=json.loads(p.read_text(encoding='utf8')); args=sys.argv[2:]
if args[0] in ('inspect','container'): print(json.dumps(state['record']))
elif args[0]=='volume': print(json.dumps({'Name':'pqbtc-mldsa-public-soak-old-data-v1'}))
elif args[0]=='stop':
 state['stops'].append(args[-1]);state['record']['State']['Running']=False;p.write_text(json.dumps(state),encoding='utf8')
else: raise SystemExit(2)
''', encoding="utf8")
            payload = {"container": record["Name"][1:], "p2p_port": 23833, "profile": runner.PROFILE,
                       "images": {record["Image"]: "ef" * 32}, "docker": [sys.executable, str(fake), str(state)],
                       "state_dir": str(folder / "new-state-dir"), "attempt_claim": None}
            namespace = {"container": payload["container"], "volume": payload["container"] + "-data-v1",
                         "state_dir": payload["state_dir"], "docker": payload["docker"], "operation": "probe"}
            probe = subprocess.run([sys.executable, "-c", runner.NAMESPACE_SCRIPT, json.dumps(namespace)], capture_output=True, timeout=10)
            self.assertEqual(probe.returncode, 0, probe.stderr.decode())
            self.assertEqual(json.loads(probe.stdout), {"container_absent": False, "volume_absent": False, "state_dir_absent": True})
            subprocess.run([sys.executable, "-c", runner.EMERGENCY_STOP_SCRIPT, json.dumps(payload)], capture_output=True, timeout=10)
            after = json.loads(state.read_text(encoding="utf8"))
            self.assertEqual(after["stops"], [], "Cleanup stopped an older matching deployment without an attempt claim")
            self.assertTrue(after["record"]["State"]["Running"])

    def test_second_host_namespace_collision_prevents_every_agent_launch(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "one", "role": "bootstrap", "p2p_port": 23833}, {"name": "two", "role": "follower"}],
                  "public_endpoint": {"hostname": "owned.example", "port": 443}, "cleanup_public_route": False}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        audits = [{"docker_daemon_id": "daemon-one"}, {"docker_daemon_id": "daemon-two"}]
        probes = [{"container_absent": True, "volume_absent": True, "state_dir_absent": True},
                  {"container_absent": False, "volume_absent": False, "state_dir_absent": True}]
        with patch.object(runner, "prelaunch_host", side_effect=audits), \
                patch.object(runner, "namespace_probe", create=True, side_effect=probes), \
                patch.object(runner, "AgentClient", side_effect=AssertionError("launched before both namespaces were checked")) as launch, \
                patch.object(runner, "read_funnel", return_value={"TCP": {"443": {"TCPForward": "127.0.0.1:23833", "TerminateTLS": "owned.example"}},
                                                               "AllowFunnel": {"owned.example:443": True}}), \
                patch.object(runner, "emergency_stop_owned") as stop:
            try:
                run.setup()
            except (ValueError, AssertionError):
                pass
            run.cleanup()
        launch.assert_not_called()
        stop.assert_not_called()
        self.assertFalse(run.agents)

    def test_namespace_claim_is_atomic_and_never_reuses_even_an_empty_state_directory(self):
        runner = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fake = folder / "docker.py"
            fake.write_text("import sys;print('No such '+sys.argv[1],file=sys.stderr);raise SystemExit(1)\n", encoding="utf8")
            claim = {"schema": runner.CLAIM_SCHEMA, "attempt_id": "ab" * 16, "container": "pqbtc-mldsa-public-soak-new",
                     "volume": "pqbtc-mldsa-public-soak-new-data-v1", "port": 23833, "profile_sha256": runner.PROFILE}
            payload = {"container": claim["container"], "volume": claim["volume"], "state_dir": str(folder / "new-state"),
                       "operation": "claim", "claim": claim, "docker": [sys.executable, str(fake)]}
            first = subprocess.run([sys.executable, "-c", runner.NAMESPACE_SCRIPT, json.dumps(payload)], capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            saved = Path(payload["state_dir"]) / runner.CLAIM_FILE
            self.assertEqual(json.loads(saved.read_text(encoding="utf8")), claim)
            second = subprocess.run([sys.executable, "-c", runner.NAMESPACE_SCRIPT, json.dumps(payload)], capture_output=True, timeout=10)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(json.loads(saved.read_text(encoding="utf8")), claim)

    def test_ssh_research_cpu_limit_is_enforced_when_it_is_the_follower(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        config = {"hosts": [{"name": "mac", "role": "bootstrap", "transport": {"kind": "local"}},
                            {"name": "research", "role": "follower", "transport": {"kind": "ssh"}}]}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        values = {name: {"rss_bytes": 1_000_000, "peak_rss_bytes": 2_000_000,
                         "maxmempool_bytes": 32_000_000, "mempool_usage_bytes": 1000,
                         "whole_host_cpu_percent": 1} for name in ("mac", "research")}
        values["research"].update(whole_host_cpu_percent=91, bridge_alive=True)
        run.action = lambda name, _action: values[name]
        with self.assertRaisesRegex(ValueError, "Research host CPU"):
            run.sample()
        values["research"]["whole_host_cpu_percent"] = 50
        values["mac"].pop("whole_host_cpu_percent")
        run.sample()
        values["research"]["bridge_alive"] = False
        with self.assertRaisesRegex(ValueError, "public bridge"):
            run.sample()

    def test_mac_bootstrap_funnel_cleanup_uses_the_working_normal_user_cli(self):
        runner = self.runner()
        class Log:
            def append(self, *_args): pass
        endpoint = {"hostname": "owned.example", "port": 443, "public_ips": ["8.8.8.8"]}
        host = {"name": "mac", "role": "bootstrap", "p2p_port": 23833, "transport": {"kind": "local"}, "sudo_docker": False}
        config = {"hosts": [host, {"name": "research", "role": "follower"}], "public_endpoint": endpoint, "cleanup_public_route": True}
        run = runner.Soak(config, "preflight", Log(), {}, "future")
        before = {"TCP": {"443": {"TCPForward": "127.0.0.1:23833", "TerminateTLS": "owned.example"}}, "AllowFunnel": {"owned.example:443": True}}
        run.funnel = runner.funnel_snapshot(before, host, endpoint)
        with patch.object(runner, "read_funnel", side_effect=[before, {}]), \
                patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as command:
            run.cleanup()
        self.assertEqual(command.call_args.args[0], ["tailscale", "funnel", "--tls-terminated-tcp=443", "off"])


if __name__ == "__main__":
    unittest.main()
