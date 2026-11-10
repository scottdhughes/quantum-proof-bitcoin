"""Real loopback tests for reopening a console; no native host execution."""
import importlib.util
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("console_launcher_app", ROOT / "contrib/ml-dsa-console/app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class Controller:
    def __init__(self):
        self.phase = "stopped"
        self.actions = []

    def status(self):
        return {"phase": self.phase, "ready": self.phase == "running"}

    def action(self, action, params):
        self.actions.append(action)
        if getattr(self, "fail", False):
            raise ValueError("Current fixture wallet record is missing")
        if action == "start":
            self.phase = "running"
        return {"status": self.status(), "result": {}}


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.identity = {"schema": "PQBTC-MLDSA44-LOCAL-CONSOLE-1", "state_id": "ab" * 32,
                         "container": "pqbtc-mldsa-local", "managed": True}
        self.controller = Controller()
        self.server = app.make_server(self.controller, port=0, identity=self.identity)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)

    def test_repeat_launch_resumes_stopped_console_once(self):
        self.assertTrue(app.reopen_existing(self.url, self.identity, autostart=True))
        self.assertTrue(app.reopen_existing(self.url, self.identity, autostart=True))
        self.assertEqual(self.controller.actions, ["start"])
        self.assertEqual(self.controller.phase, "running")

    def test_launch_without_autostart_only_opens_existing_console(self):
        self.assertTrue(app.reopen_existing(self.url, self.identity, autostart=False))
        self.assertEqual(self.controller.actions, [])

    def test_public_reopen_handles_bounded_soak_sized_status(self):
        self.controller.status = lambda: {"phase": "running", "ready": True,
                                          "wallet": {"utxos": [{"txid": "ab" * 32, "metadata": "x" * 300}] * 720}}
        with self.assertRaises(app.LaunchError):
            app.read_local(self.url + "/api/status")
        self.assertTrue(app.reopen_existing(self.url, self.identity, max_bytes=2 * 1024 * 1024))
        self.assertEqual(self.controller.actions, [])

    def test_failed_auto_resume_keeps_http_recovery_controls_available(self):
        self.controller.fail = True
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertFalse(app.start_network(self.controller, self.server))
        value = json.loads(app.read_local(self.url + "/api/status"))
        self.assertIn("record is missing", value["data"]["startup_error"])
        self.assertEqual(value["data"]["phase"], "stopped")
        with redirect_stdout(output):
            self.assertTrue(app.reopen_existing(self.url, self.identity, autostart=True))
        self.assertIn("recovery controls", output.getvalue())

    def test_other_wallet_or_unrelated_service_is_not_reused(self):
        other = {**self.identity, "state_id": "cd" * 32}
        with self.assertRaisesRegex(app.LaunchError, "another"):
            app.reopen_existing(self.url, other, autostart=True)
        self.assertEqual(self.controller.actions, [])

    def test_state_identity_tracks_directory_and_native_container(self):
        first = app.console_identity(Path("/tmp/fixture-a"), "a", False)
        self.assertEqual(first, app.console_identity(Path("/tmp/fixture-a"), "a", False))
        self.assertNotEqual(first, app.console_identity(Path("/tmp/fixture-b"), "a", False))
        self.assertNotEqual(first, app.console_identity(Path("/tmp/fixture-a"), "b", False))

    def test_optimized_restart_driver_refuses_before_any_docker_action(self):
        result = subprocess.run([sys.executable, "-O", str(ROOT / "contrib/ml-dsa-console/test_restart_end_to_end.py"), "--help"],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Optimized Python is not permitted", result.stderr)


if __name__ == "__main__":
    unittest.main()
