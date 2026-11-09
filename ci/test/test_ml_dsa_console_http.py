import importlib.util
import json
from pathlib import Path
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "contrib/ml-dsa-console/app.py"


class ControllerFixture:
    def __init__(self):
        self.phase = "stopped"
        self.actions = []

    def status(self):
        return {"phase": self.phase, "ready": self.phase == "running"}

    def action(self, action, params):
        self.actions.append((action, params))
        if action == "start":
            self.phase = "running"
        return {"status": self.status(), "result": {"action": action}}


class ConsoleHTTPTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(APP.is_file(), "local console server is not implemented")
        spec = importlib.util.spec_from_file_location("mldsa_console_app", APP)
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)
        self.controller = ControllerFixture()
        self.token = "public-test-only-console-token"
        self.server = app.make_server(self.controller, "127.0.0.1", 0, self.token)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)

    def request(self, payload=None, headers=None, path="/api/action"):
        defaults = {
            "Content-Type": "application/json",
            "Origin": self.origin,
            "X-Console-Token": self.token,
        }
        defaults.update(headers or {})
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(self.origin + path, data=data, headers=defaults)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response), response.headers
        except HTTPError as error:
            with error:
                return error.code, json.load(error), error.headers

    def test_status_reports_actual_controller_state(self):
        code, body, _ = self.request(path="/api/status")
        self.assertEqual(code, 200)
        self.assertEqual(body, {"ok": True, "data": {"phase": "stopped", "ready": False}})

    def test_valid_action_changes_state_and_duplicate_is_not_reexecuted(self):
        payload = {"action": "start", "params": {}, "request_id": "request-1234567890"}
        first = self.request(payload)
        second = self.request(payload)
        self.assertEqual(first[0], 200)
        self.assertEqual(first[:2], second[:2])
        self.assertEqual(first[1]["data"]["status"]["phase"], "running")
        self.assertEqual(self.controller.actions, [("start", {})])

    def test_reused_request_id_with_changed_action_is_refused(self):
        payload = {"action": "start", "params": {}, "request_id": "request-1234567890"}
        self.assertEqual(self.request(payload)[0], 200)
        payload["action"] = "stop"
        self.assertEqual(self.request(payload)[0], 409)
        self.assertEqual(self.controller.phase, "running")

    def test_expired_response_never_reexecutes_an_earlier_send(self):
        payload = {"action": "send", "params": {"address": "rq1fixture", "amount_sats": 1000},
                   "request_id": "original-send-1234567890"}
        self.assertEqual(self.request(payload)[0], 200)
        for index in range(129):
            self.assertEqual(self.request({"action": "receive", "params": {},
                                           "request_id": "later-request-" + str(index)})[0], 200)
        self.assertEqual(self.request(payload)[0], 409)
        self.assertEqual(sum(action == "send" for action, _ in self.controller.actions), 1)

    def test_cross_origin_request_cannot_mutate_the_lab(self):
        code, body, _ = self.request(
            {"action": "start", "params": {}, "request_id": "request-1234567890"},
            {"Origin": "https://unrelated.example"},
        )
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])
        self.assertEqual(self.controller.actions, [])

    def test_missing_or_wrong_token_cannot_mutate_the_lab(self):
        for token in ("", "wrong-token"):
            with self.subTest(token=token):
                code, _, _ = self.request(
                    {"action": "start", "params": {}, "request_id": "request-1234567890"},
                    {"X-Console-Token": token},
                )
                self.assertEqual(code, 403)
        self.assertEqual(self.controller.actions, [])

    def test_wrong_host_is_refused(self):
        code, _, _ = self.request(path="/api/status", headers={"Host": "unrelated.example"})
        self.assertEqual(code, 403)

    def test_invalid_send_amounts_do_not_reach_controller(self):
        for amount in (-1, 0, True, 1.25, "1000", 2100000000000001):
            with self.subTest(amount=amount):
                code, _, _ = self.request({
                    "action": "send", "params": {"address": "rq1fixture", "amount_sats": amount},
                    "request_id": "request-1234567890",
                })
                self.assertEqual(code, 400)
        self.assertEqual(self.controller.actions, [])

    def test_unknown_actions_and_backup_paths_are_refused(self):
        for action, params in (("rpc", {}), ("recover", {"backup_id": "../../other"})):
            code, _, _ = self.request({
                "action": action, "params": params, "request_id": "request-1234567890",
            })
            self.assertEqual(code, 400)
        self.assertEqual(self.controller.actions, [])

    def test_plain_text_mutations_are_refused(self):
        code, _, _ = self.request(
            {"action": "start", "params": {}, "request_id": "request-1234567890"},
            {"Content-Type": "text/plain"},
        )
        self.assertEqual(code, 415)
        self.assertEqual(self.controller.actions, [])


if __name__ == "__main__":
    unittest.main()
