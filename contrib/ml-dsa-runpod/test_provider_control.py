#!/usr/bin/env python3
"""Pure DATA/control tests. No live provider, authentication, or native work."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
import time
import unittest

import provider_control as p


PIN = "runpod/base@sha256:" + "5" * 64
KEY = "TEST_PROVIDER_AUTH_" + "x" * 24


def pod(plan, volume_id="volume1", pod_id="pod1"):
    return {"id": pod_id, "name": plan["task"], "status": "RUNNING", "actions": ["restart", "terminate"],
            "image": plan["image"], "cpu": {"id": "cpu3c", "vcpuCount": 4, "memory": 8}, "cloud": "SECURE", "disk": 40,
            "ports": ["22/tcp"], "registry": None, "mounts": {"network": [{"volumeId": volume_id, "path": "/var/lib/pqbtc"}], "global": []},
            "globalNetworking": {"enabled": False}, "dataCenterId": plan["data_center"], "cost": 0.12,
            "createdAt": "2026-11-14T17:00:00Z", "startedAt": "2026-11-14T17:01:00Z",
            "ssh": {"direct": {"host": "8.8.8.8", "port": 20333, "username": "root"}}, "runtime": {"uptime": 600}}


class FakeAPI:
    def __init__(self):
        self.plan = None
        self.pods, self.volumes, self.calls = {}, {}, []
        self.fail_pod_post = False
        self.pending_delete = False
        self.hostkey_unavailable_once = False

    def collection(self, kind):
        self.calls.append(("LIST", kind, None))
        return list(copy.deepcopy(self.pods if kind == "pods" else self.volumes).values())

    def call(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path.startswith("/v2/catalog/cpus/"):
            return 200, {"id": "cpu3c", "ramGbPerVcpu": 2, "vcpu": {"min": 2, "max": 32},
                         "price": {"securePerVcpu": 0.03}, "availability": "HIGH",
                         "dataCenters": [{"id": "US-MD-1", "availability": "HIGH"}, {"id": "EU-RO-1", "availability": "HIGH"}]}
        if path.startswith("/v2/catalog/datacenters"):
            return 200, {"dataCenters": [{"id": "EU-RO-1", "networkVolumeTypes": ["STANDARD"]},
                                        {"id": "US-MD-1", "networkVolumeTypes": ["STANDARD"]}]}
        if method == "POST" and path == "/v2/network-volumes":
            value = {"id": "volume1", **body}
            self.volumes[value["id"]] = copy.deepcopy(value)
            return 201, value
        if method == "POST" and path == "/v2/pods":
            value = pod(self.plan)
            self.pods["pod1"] = copy.deepcopy(value)
            if self.fail_pod_post:
                raise p.Refused("provider_transport")
            return 201, value
        if method == "POST" and path.endswith("/action"):
            value = self.pods["pod1"]
            value["startedAt"] = "2026-11-14T17:03:00Z"
            value["runtime"]["uptime"] = 1
            return 200, copy.deepcopy(value)
        if method == "POST" and path.endswith("/exec"):
            assert body == p.HOSTKEY_COMMAND
            if self.hostkey_unavailable_once:
                self.hostkey_unavailable_once = False
                return 503, {"title": "Unavailable"}
            wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))
            return 200, {"exitCode": 0, "stderr": "", "stdout": "ssh-ed25519 " + base64.b64encode(wire).decode() + "\n",
                         "timedOut": False, "truncated": False}
        parts = path.split("/")
        source = self.pods if parts[2] == "pods" else self.volumes
        value = source.get(parts[3])
        if value is None:
            return 404, {"title": "Not Found", "status": 404, "detail": "resource not found"}
        if method == "DELETE":
            if not self.pending_delete:
                del source[parts[3]]
            return 204, None
        return 200, copy.deepcopy(value)


class Response(io.BytesIO):
    def __init__(self, value, status=200):
        super().__init__(value)
        self.status = status


class Opener:
    def __init__(self, responses):
        self.responses, self.requests = list(responses), []

    def open(self, request, timeout):
        self.requests.append(request)
        return self.responses.pop(0)


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name) / "state"
        self.api = FakeAPI()
        self.plan = p.make_plan(self.directory, self.api, PIN)
        self.api.plan = self.plan
        self.binding = p.load(self.directory)[1]
        self.binding["deadline_epoch"] = int(time.time()) + p.MAX_SECONDS
        self.binding["guard"] = {"script_sha256": "0" * 64,
                                 "label": "org.pqbtc.runpod." + self.plan["task"].rsplit("-", 1)[1],
                                 "armed_at_epoch": self.binding["deadline_epoch"] - p.MAX_SECONDS}
        p.save_binding(self.directory, self.binding)
        p.put(self.directory / "guard-heartbeat.json", {"task": self.plan["task"], "plan_sha256": self.binding["plan_sha256"],
              "pid": os.getpid(), "epoch": int(time.time()), "deadline_epoch": self.binding["deadline_epoch"]})

    def tearDown(self):
        self.tmp.cleanup()

    def create(self):
        return p.create(self.directory, self.api)

    def export(self):
        archive = self.directory / "export.tar"
        with tarfile.open(archive, "w") as stream:
            member = tarfile.TarInfo("public-state/result.json")
            content = b'{"scope":"VALUELESS_TEST_ONLY"}\n'
            member.size = len(content)
            stream.addfile(member, io.BytesIO(content))
        os.chmod(archive, 0o600)
        raw = archive.read_bytes()
        receipt = self.directory / "export.json"
        p.put(receipt, {"schema": "PQBTC-RUNPOD-STATE-EXPORT-1", "result": "PASS", "path": str(archive),
              "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "task_generated_auth_cookies_excluded": True,
              "binding": {"task": self.plan["task"], "pod_id": "pod1", "volume_id": "volume1",
                          "generation": "2026-11-14T17:01:00Z"}})
        return receipt

    def test_plan_is_readonly_fresh_scoped_and_budgeted(self):
        self.assertTrue(p.TASK.fullmatch(self.plan["task"]))
        self.assertEqual(self.plan["data_center"], "US-MD-1")
        self.assertEqual(self.plan["duration_seconds"], 28 * 3600)
        self.assertLessEqual(float(self.plan["quote"]["all_in_planned_upper_usd"]), 10)
        self.assertFalse(any(v[0] in ("POST", "DELETE") for v in self.api.calls))
        with self.assertRaisesRegex(p.Refused, "fresh_state_required"):
            p.make_plan(self.directory, self.api, PIN)

    def test_plan_requires_immutable_image(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(p.Refused, "image_digest_required"):
                p.make_plan(Path(t) / "other", self.api, "runpod/base:latest")

    def test_budget_refuses_excessive_rate_and_short_soak(self):
        for hourly, seconds in ((0.21, p.MAX_SECONDS), (0.12, 86400), (0.12, p.MAX_SECONDS + 1)):
            with self.assertRaises(p.Refused):
                p.quote_bound(hourly, seconds=seconds)

    def test_expired_quote_creates_nothing(self):
        plan = copy.deepcopy(self.plan)
        plan["catalog"]["observed_at_epoch"] -= 901
        p.put(self.directory / "plan.json", plan)
        binding = self.binding.copy()
        binding["plan_sha256"] = p.digest(p.read(self.directory / "plan.json"))
        p.save_binding(self.directory, binding)
        beat = p.decode(p.read(self.directory / "guard-heartbeat.json"))
        beat["plan_sha256"] = binding["plan_sha256"]
        p.put(self.directory / "guard-heartbeat.json", beat)
        with self.assertRaisesRegex(p.Refused, "fresh_create_required"):
            self.create()
        self.assertFalse(self.api.volumes or self.api.pods)

    def test_guard_required_and_staleness_refused(self):
        beat = p.decode(p.read(self.directory / "guard-heartbeat.json"))
        beat["epoch"] -= 11
        p.put(self.directory / "guard-heartbeat.json", beat)
        with self.assertRaisesRegex(p.Refused, "guard_not_live"):
            self.create()
        self.assertFalse(self.api.volumes or self.api.pods)

    def test_deadline_extension_beyond_authorized_window_refused(self):
        binding = copy.deepcopy(self.binding)
        binding["deadline_epoch"] += 1
        p.save_binding(self.directory, binding)
        with self.assertRaisesRegex(p.Refused, "guard_bound"):
            self.create()
        self.assertFalse(self.api.volumes or self.api.pods)

    def test_preexisting_same_name_never_adopted(self):
        self.api.pods["other"] = {"id": "other", "name": self.plan["task"]}
        with self.assertRaisesRegex(p.Refused, "name_already_exists"):
            self.create()
        self.assertEqual(set(self.api.pods), {"other"})
        self.assertFalse(self.api.volumes)

    def test_create_binds_exact_volume_and_pod_once(self):
        result = self.create()
        self.assertEqual(result["id"], "pod1")
        self.assertEqual(p.load(self.directory)[1]["phase"], "ACTIVE")
        with self.assertRaisesRegex(p.Refused, "fresh_create_required"):
            self.create()
        self.assertEqual(sum(v[0] == "POST" and v[1] == "/v2/pods" for v in self.api.calls), 1)

    def test_unknown_post_outcome_reconciles_without_post_retry(self):
        self.api.fail_pod_post = True
        with self.assertRaisesRegex(p.Refused, "provider_transport"):
            self.create()
        result = p.terminate(self.directory, self.api, emergency=True)
        self.assertEqual(result["phase"], "CLOSED")
        self.assertEqual(sum(v[0] == "POST" and v[1] == "/v2/pods" for v in self.api.calls), 1)
        self.assertFalse(self.api.pods or self.api.volumes)

    def test_unknown_bad_geometry_is_cleaned_without_adoption(self):
        self.api.fail_pod_post = True
        with self.assertRaises(p.Refused):
            self.create()
        self.api.pods["pod1"]["cost"] = 99
        self.assertEqual(p.terminate(self.directory, self.api, emergency=True)["phase"], "CLOSED")
        self.assertFalse(self.api.pods or self.api.volumes)

    def test_rejected_creation_requires_complete_exact_name_absence(self):
        binding = p.load(self.directory)[1]
        binding.update(phase="CREATING", intents={"volume": 1}, rejections={"volume": 422})
        p.save_binding(self.directory, binding)
        self.assertEqual(p.terminate(self.directory, self.api, emergency=True)["phase"], "CLOSED")
        self.assertTrue(p.load(self.directory)[1]["not_created"]["volume"]["complete_exact_name_list_absent"])

    def test_normal_close_requires_export_then_confirms_both_absent(self):
        self.create()
        with self.assertRaisesRegex(p.Refused, "export_required"):
            p.terminate(self.directory, self.api)
        receipt = self.export()
        result = p.terminate(self.directory, self.api, export_receipt=receipt)
        self.assertEqual(result["phase"], "CLOSED")
        self.assertEqual(set(result["deleted"]), {"pod", "volume"})
        self.assertFalse(self.api.pods or self.api.volumes)

    def test_arbitrary_export_file_cannot_authorize_data_deletion(self):
        self.create()
        receipt = self.directory / "export.json"
        p.put(receipt, {"wrong_pod": "unrelated"})
        with self.assertRaisesRegex(p.Refused, "export_receipt"):
            p.terminate(self.directory, self.api, export_receipt=receipt)
        self.assertFalse(any(v[0] == "DELETE" for v in self.api.calls))

    def test_export_other_pod_or_generation_cannot_delete(self):
        self.create()
        receipt = self.export()
        original = p.decode(p.read(receipt))
        for field, value in (("pod_id", "other"), ("volume_id", "other"), ("generation", "2026-11-14T17:00:00Z")):
            changed = copy.deepcopy(original)
            changed["binding"][field] = value
            p.put(receipt, changed)
            with self.subTest(field=field), self.assertRaises(p.Refused):
                p.terminate(self.directory, self.api, export_receipt=receipt)
        self.assertFalse(any(v[0] == "DELETE" for v in self.api.calls))

    def test_corrupted_archive_cannot_delete(self):
        self.create()
        receipt = self.export()
        value = p.decode(p.read(receipt))
        archive = Path(value["path"])
        raw = bytearray(archive.read_bytes())
        raw[0] ^= 1
        archive.write_bytes(raw)
        with self.assertRaisesRegex(p.Refused, "export_archive_hash"):
            p.terminate(self.directory, self.api, export_receipt=receipt)
        self.assertFalse(any(v[0] == "DELETE" for v in self.api.calls))

    def test_unknown_late_post_is_reconciled_next_watch_tick(self):
        binding = p.load(self.directory)[1]
        binding.update(phase="ABORT_REQUESTED", intents={"volume": 1})
        p.save_binding(self.directory, binding)
        p.watch_tick(self.directory, self.api)
        self.assertEqual(p.load(self.directory)[1]["phase"], "TERMINATING")
        self.api.volumes["latevolume"] = {"id": "latevolume", "name": self.plan["task"] + "-data", "size": 20,
                                          "dataCenter": self.plan["data_center"], "type": "STANDARD"}
        p.watch_tick(self.directory, self.api)
        self.assertFalse(self.api.volumes)
        self.assertEqual(p.load(self.directory)[1]["phase"], "CLOSED")

    def test_wrong_cleanup_identity_preserved(self):
        self.create()
        self.api.pods["pod1"]["name"] = "unrelated"
        with self.assertRaisesRegex(p.Refused, "cleanup_identity"):
            p.terminate(self.directory, self.api, emergency=True)
        self.assertTrue(self.api.pods and self.api.volumes)

    def test_accepted_delete_does_not_repeat_during_eventual_consistency(self):
        self.create()
        self.api.pending_delete = True
        for _ in range(2):
            with self.assertRaisesRegex(p.Refused, "delete_pending"):
                p.terminate(self.directory, self.api, emergency=True)
        self.assertEqual(sum(v[0] == "DELETE" for v in self.api.calls), 1)
        del self.api.pods["pod1"]
        self.api.pending_delete = False
        self.assertEqual(p.terminate(self.directory, self.api, emergency=True)["phase"], "CLOSED")

    def test_volume_shared_by_unrelated_pod_is_preserved(self):
        self.create()
        self.api.pods["other"] = {"id": "other", "name": "other", "mounts": {"network": [{"volumeId": "volume1", "path": "/workspace"}]}}
        with self.assertRaisesRegex(p.Refused, "volume_still_attached"):
            p.terminate(self.directory, self.api, emergency=True)
        self.assertTrue(self.api.volumes and "other" in self.api.pods)

    def test_unallocated_guard_can_close_without_resources(self):
        self.assertEqual(p.terminate(self.directory, self.api, emergency=True)["phase"], "CLOSED")
        self.assertFalse(any(v[0] in ("POST", "DELETE") for v in self.api.calls))

    def test_native_pod_configuration_drift_refused(self):
        value = pod(self.plan)
        for field, changed in (("image", "wrong"), ("ports", ["22/tcp", "23832/tcp"]), ("cost", 99),
                               ("cpu", {"id": "cpu3c", "vcpuCount": 8, "memory": 16}),
                               ("mounts", {"network": [{"volumeId": "other", "path": "/var/lib/pqbtc"}]})):
            bad = copy.deepcopy(value)
            bad[field] = changed
            with self.subTest(field=field), self.assertRaises(p.Refused):
                p.pod_projection(bad, self.plan, "volume1", "pod1")

    def test_hostkey_obtained_through_scoped_provider_exec(self):
        self.create()
        transport = p.ssh_transport(self.directory, self.api)
        self.assertEqual(transport["pod_id"], "pod1")
        self.assertIn("StrictHostKeyChecking=yes", transport["argv"])
        self.assertNotIn("StrictHostKeyChecking=no", transport["argv"])
        self.assertEqual(transport["hostkey_source"], "AUTHENTICATED_PROVIDER_EXEC_PUBLIC_KEY_ONLY")
        self.assertEqual(sum(v[1].endswith("/exec") for v in self.api.calls), 1)

    def test_port22_known_host_uses_plain_address(self):
        self.create()
        self.api.pods["pod1"]["ssh"]["direct"]["port"] = 22
        p.ssh_transport(self.directory, self.api)
        content = next(self.directory.glob("known-hosts-*")).read_text()
        self.assertTrue(content.startswith("8.8.8.8 ssh-ed25519 "))
        self.assertNotIn("[8.8.8.8]", content)

    def test_same_generation_changed_public_key_is_refused(self):
        self.create()
        p.ssh_transport(self.directory, self.api)
        known = next(self.directory.glob("known-hosts-*"))
        known.write_bytes(b"other\n")
        with self.assertRaisesRegex(p.Refused, "hostkey_changed_within_generation"):
            p.ssh_transport(self.directory, self.api)

    def test_provider_restart_requires_new_generation_same_id_and_volume(self):
        self.create()
        result = p.restart(self.directory, self.api)
        self.assertEqual(result["schema"], "PQBTC-RUNPOD-RESTART-1")
        self.assertTrue(result["provider_restart"] and result["same_persistent_volume"])
        self.assertNotEqual(result["before_generation"], result["after_generation"])
        self.assertEqual(result["transport"]["pod_id"], "pod1")

    def test_generation_requires_timezone(self):
        with self.assertRaisesRegex(p.Refused, "provider_generation"):
            p.generation_epoch("2026-11-14T17:01:00")

    def test_restart_retries_hostkey_read_without_repeating_restart(self):
        self.create()
        self.api.hostkey_unavailable_once = True
        result = p.restart(self.directory, self.api, sleep=lambda seconds: None)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(sum(v[0] == "POST" and v[1].endswith("/action") for v in self.api.calls), 1)
        self.assertEqual(sum(v[0] == "POST" and v[1].endswith("/exec") for v in self.api.calls), 2)

    def test_ssh_endpoint_refuses_private_address(self):
        value = pod(self.plan)
        value["ssh"]["direct"]["host"] = "127.0.0.1"
        with self.assertRaisesRegex(p.Refused, "ssh_endpoint"):
            p.pod_projection(value, self.plan, "volume1", "pod1")

    def test_readiness_bound_to_pod_id(self):
        self.create()
        receipt = self.directory / "ready.json"
        p.put(receipt, {"result": "PASS", "pod_id": "unrelated"})
        with self.assertRaisesRegex(p.Refused, "readiness_receipt"):
            p.ready(self.directory, receipt)
        p.put(receipt, {"result": "PASS", "pod_id": "pod1"})
        self.assertTrue(p.ready(self.directory, receipt)["ready"])

    def test_state_symlink_and_duplicate_json_refused(self):
        target = self.directory / "target"
        p.put(target, {})
        link = self.directory / "link"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            p.read(link)
        with self.assertRaisesRegex(p.Refused, "duplicate_json_key"):
            p.decode(b'{"a":1,"a":2}')


class APIProtocolTest(unittest.TestCase):
    def client(self, response):
        opener = Opener([response])
        return p.API(p.Credential(KEY), opener), opener

    def test_auth_is_header_only_and_proxy_scope_canonical(self):
        client, opener = self.client(Response(b'{}'))
        self.assertEqual(client.call("GET", "/v2/catalog/datacenters")[0], 200)
        request = opener.requests[0]
        self.assertEqual(request.full_url, p.ORIGIN + "/v2/catalog/datacenters")
        self.assertNotIn(KEY, request.full_url)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)

    def test_disallowed_endpoint_and_exec_refused_before_request(self):
        client, opener = self.client(Response(b'{}'))
        for method, path, body in (("GET", "/v2/account", None), ("GET", "/v2/billing", None),
                                  ("POST", "/v2/pods/pod1/exec", {"command": ["env"]})):
            with self.subTest(path=path), self.assertRaisesRegex(p.Refused, "api_scope"):
                client.call(method, path, body)
        self.assertFalse(opener.requests)

    def test_raw_and_escaped_credential_echo_refused(self):
        for raw in (json.dumps({"value": KEY}).encode(), ('{"value":"' + ''.join('\\u%04x' % ord(c) for c in KEY) + '"}').encode()):
            client, _ = self.client(Response(raw))
            with self.assertRaisesRegex(p.Refused, "credential_echo"):
                client.call("GET", "/v2/catalog/datacenters")

    def test_oversized_response_refused(self):
        client, _ = self.client(Response(b" " * (p.MAX_BYTES + 1)))
        with self.assertRaisesRegex(p.Refused, "response_limit"):
            client.call("GET", "/v2/catalog/datacenters")

    def test_pagination_complete_and_cursor_loops_refused(self):
        good = {"pods": [{"id": "one", "name": "first"}], "pagination": {"hasNextPage": True, "nextCursor": "abc"}}
        last = {"pods": [{"id": "two", "name": "second"}], "pagination": {"hasNextPage": False, "nextCursor": None}}
        opener = Opener([Response(json.dumps(v).encode()) for v in (good, last)])
        client = p.API(p.Credential(KEY), opener)
        self.assertEqual([v["id"] for v in client.collection("pods")], ["one", "two"])
        looping = {"pods": [{"id": "two", "name": "second"}], "pagination": {"hasNextPage": True, "nextCursor": "abc"}}
        opener = Opener([Response(json.dumps(v).encode()) for v in (good, looping)])
        with self.assertRaisesRegex(p.Refused, "pagination"):
            p.API(p.Credential(KEY), opener).collection("pods")

    def test_unproven_404_is_not_terminal_confirmation(self):
        with tempfile.TemporaryDirectory() as t:
            api = FakeAPI()
            directory = Path(t) / "state"
            plan = p.make_plan(directory, api, PIN)
            api.plan = plan
            binding = p.load(directory)[1]
            binding.update(pod_id="pod1", volume_id="volume1", phase="ACTIVE", intents={"volume": 1, "pod": 2})
            p.save_binding(directory, binding)
            with self.assertRaisesRegex(p.Refused, "unproven_absence"):
                p.terminate(directory, api, emergency=True)


if __name__ == "__main__":
    unittest.main()
