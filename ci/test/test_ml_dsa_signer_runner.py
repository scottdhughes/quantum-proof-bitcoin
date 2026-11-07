#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Signer command-runner controls; execute only in contained Linux."""

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-signer/run_signer_tests.py"
OUTPUT_LIMIT = 2 * 1024 * 1024


def load_runner():
    spec = importlib.util.spec_from_file_location("signer_command_runner", RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def process_identity(pid):
    try:
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]), "pgid": int(fields[2]),
            "sid": int(fields[3]), "starttime": int(fields[19])}


def stop_fixture_process(expected):
    """Only the controller's current direct child may be signalled."""
    if expected["ppid"] != os.getpid():
        raise RuntimeError("fixture cleanup refused non-child identity")
    try:
        descriptor = os.pidfd_open(expected["pid"], 0)
    except ProcessLookupError:
        return
    try:
        current = process_identity(expected["pid"])
        if current is not None and current["ppid"] == os.getpid() and all(
                current[key] == expected[key] for key in ("pid", "pgid", "sid", "starttime")):
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
    finally:
        os.close(descriptor)


def descendant_probe(directory, mode):
    """Independent subreaper controller; the old runner cannot orphan this fixture."""
    if mode not in ("timeout", "success"):
        raise ValueError("unknown descendant fixture mode")
    # Public libc only, inside the Linux-only child controller. The outer test
    # remains a separate process and can request this fixture's cleanup.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "test subreaper setup failed")
    path = Path(directory) / "owned-processes.json"
    cleaned = False

    def cleanup():
        nonlocal cleaned
        if cleaned:
            return
        # A missing/partial readiness file cannot remove cleanup authority.
        # This dedicated subreaper has no unrelated workloads: enumerate only
        # its kernel-listed direct children, then rescan for adopted heirs.
        children = Path("/proc/self/task") / str(os.getpid()) / "children"
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            owned = [int(pid) for pid in children.read_text().split()]
            for pid in owned:
                expected = process_identity(pid)
                if expected is not None and expected["ppid"] == os.getpid():
                    stop_fixture_process(expected)
            for pid in owned:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass  # The runner may already have reaped its direct child.
            if not children.read_text().split():
                cleaned = True
                return
            time.sleep(0.01)
        raise RuntimeError("fixture process cleanup not confirmed")

    def requested_cleanup(signum, frame):
        try:
            cleanup()
        finally:
            os._exit(99)

    signal.signal(signal.SIGTERM, requested_cleanup)
    program = r'''
import json, os, signal, sys, time
from pathlib import Path
def identity(pid):
    f = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'pgid': int(f[2]), 'sid': int(f[3]), 'starttime': int(f[19])}
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = os.fork()
if child == 0:
    # A surviving heir must not keep communicate() waiting in the old runner.
    for fd in (0, 1, 2):
        os.close(fd)
    while True:
        time.sleep(1)
Path(sys.argv[1]).write_text(json.dumps([identity(os.getpid()), identity(child)]))
print('fixture-ready', flush=True)
if sys.argv[2] == 'success':
    raise SystemExit(0)
while True:
    time.sleep(1)
'''
    failure = None
    stdout = None
    try:
        try:
            stdout = load_runner().run([sys.executable, "-c", program, str(path), mode], timeout=0.3)
        except Exception as error:
            failure = type(error).__name__
        if not path.exists():
            raise RuntimeError("fixture readiness record missing")
        records = json.loads(path.read_text())
        expected = records[1]
        observation_deadline = time.monotonic() + 0.25
        while True:
            heir = process_identity(expected["pid"])
            if heir is None:
                stopped = True
                break
            if any(heir[key] != expected[key] for key in ("pid", "pgid", "sid", "starttime")):
                raise RuntimeError("fixture heir identity changed during observation")
            if heir["state"] == "Z":
                stopped = True
                break
            remaining = observation_deadline - time.monotonic()
            if remaining <= 0:
                stopped = False
                break
            time.sleep(min(0.005, remaining))
        # A stopped zombie is reaped by this controller before it exits; a live
        # heir exposes missing same-group cleanup on timeout or successful exit.
        result = {"command_rejected": failure is not None, "stdout": stdout,
                  "descendant_stopped_before_fixture_cleanup": stopped}
    finally:
        cleanup()
    result["fixture_cleanup_confirmed"] = cleaned
    print(json.dumps(result, sort_keys=True))


@unittest.skipUnless(sys.platform == "linux", "contained Linux command-runner controls")
class SignerRunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = load_runner()

    def command(self, program, *arguments):
        return [sys.executable, "-c", program, *arguments]

    def test_finite_oversized_stdout_is_rejected(self):
        # Removing the output bound would accept this finite three-MiB result.
        command = self.command("import os; os.write(1, b'x' * (3 * 1024 * 1024))")
        with self.assertRaises(RuntimeError):
            self.runner.run(command)

    def test_finite_oversized_stderr_has_bounded_failure_text(self):
        command = self.command("import os; os.write(2, b'e' * (3 * 1024 * 1024))")
        with self.assertRaises(RuntimeError) as failure:
            self.runner.run(command)
        self.assertLessEqual(len(str(failure.exception).encode("utf-8")), OUTPUT_LIMIT + 4096)

    def test_stdout_at_the_cap_is_rejected(self):
        command = self.command("import os; os.write(1, b'x' * (2 * 1024 * 1024))")
        with self.assertRaises(RuntimeError):
            self.runner.run(command)

    def test_stdout_below_the_cap_is_preserved(self):
        command = self.command("import os; os.write(1, b'x' * (2 * 1024 * 1024 - 1))")
        self.assertEqual(self.runner.run(command), "x" * (OUTPUT_LIMIT - 1))

    def test_fast_empty_success_is_preserved(self):
        self.assertEqual(self.runner.run(self.command("pass")), "")

    def test_stdout_whitespace_and_existing_text_newlines_are_preserved(self):
        command = self.command("import os; os.write(1, b'  result\\r\\n\\n')")
        self.assertEqual(self.runner.run(command), "  result\n\n")

    def test_utf8_split_across_writes_is_preserved(self):
        command = self.command("import os,time; os.write(1, b'a' * 65535 + b'\\xc3'); "
                               "time.sleep(0.03); os.write(1, b'\\xa9\\n')")
        self.assertEqual(self.runner.run(command), "a" * 65535 + "é\n")

    def test_invalid_utf8_output_is_rejected(self):
        with self.assertRaises((RuntimeError, UnicodeError)):
            self.runner.run(self.command("import os; os.write(1, b'\\xff')"))

    def test_stderr_with_success_exit_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.runner.run(self.command("import os; os.write(2, b'diagnostic\\n')"))

    def test_nonzero_exit_without_stderr_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.runner.run(self.command("raise SystemExit(7)"))

    def test_timeout_is_finite_and_rejected(self):
        started = time.monotonic()
        with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
            self.runner.run(self.command("import time; time.sleep(10)"), timeout=0.1)
        self.assertLess(time.monotonic() - started, 3)

    def descendant_result(self, mode):
        with tempfile.TemporaryDirectory(prefix="signer-runner-heir-") as temporary:
            controller = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                           "--descendant-probe", temporary, mode],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, start_new_session=True)
            try:
                stdout, stderr = controller.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                controller.terminate()  # Its handler cleans only named fixture children.
                try:
                    controller.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.communicate(timeout=2)
                self.fail("independent descendant controller exceeded its deadline")
            self.assertEqual(controller.returncode, 0, stderr.decode("utf-8", "replace"))
            self.assertEqual(stderr, b"")
            return json.loads(stdout)

    def test_timeout_stops_same_group_descendant(self):
        result = self.descendant_result("timeout")
        self.assertTrue(result["command_rejected"])
        self.assertTrue(result["fixture_cleanup_confirmed"])
        self.assertTrue(result["descendant_stopped_before_fixture_cleanup"])

    def test_successful_exit_preserves_stdout_and_stops_same_group_descendant(self):
        result = self.descendant_result("success")
        self.assertFalse(result["command_rejected"])
        self.assertEqual(result["stdout"], "fixture-ready\n")
        self.assertTrue(result["fixture_cleanup_confirmed"])
        self.assertTrue(result["descendant_stopped_before_fixture_cleanup"])

    def test_fixed_environment_cwd_and_argv_override_inheritance(self):
        program = ("import json,os,sys; print(json.dumps({'cwd':os.getcwd(), 'argv':sys.argv[1:], "
                   "'asan':os.getenv('ASAN_OPTIONS'), 'ubsan':os.getenv('UBSAN_OPTIONS'), "
                   "'conf':os.getenv('OPENSSL_CONF'), 'modules':os.getenv('OPENSSL_MODULES'), "
                   "'inherited':os.getenv('SIGNER_RUNNER_UNTRUSTED_MARKER')}))")
        with mock.patch.dict(os.environ, {"ASAN_OPTIONS": "detect_leaks=0:log_path=/tmp/not-proof",
                                          "SIGNER_RUNNER_UNTRUSTED_MARKER": "not-in-child"}):
            result = json.loads(self.runner.run(self.command(program, Path("relative argument"), "--literal")))
        self.assertEqual(result, {"cwd": str(ROOT), "argv": ["relative argument", "--literal"],
                                 "asan": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0",
                                 "ubsan": "halt_on_error=1:print_stacktrace=1:symbolize=0",
                                 "conf": "/dev/null", "modules": "/nonexistent", "inherited": None})


if __name__ == "__main__":
    if sys.argv[1:2] == ["--descendant-probe"]:
        descendant_probe(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
