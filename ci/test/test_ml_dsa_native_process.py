# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Python-only controls for native harness process/resource containment."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "contrib/ml-dsa-qualification/native_process.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("tested_native_process", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeProcessTests(unittest.TestCase):
    def setUp(self):
        self.helper = load_helper()

    def command(self, text):
        return [sys.executable, "-c", text]

    def test_stdout_flood_is_bounded_and_keeps_actual_prefix_and_hash(self):
        with self.assertRaises(self.helper.CaptureError) as failure:
            self.helper.checked(self.command("import os; os.write(1, b'x' * 200000)"),
                                output_limit=65536, prefix_limit=128)
        data = failure.exception.details
        self.assertEqual(data["failure"], "stdout output limit")
        self.assertGreaterEqual(data["stdout"]["observed_bytes"], 65536)
        self.assertLessEqual(data["stdout"]["observed_bytes"], 65536 + 65535)
        self.assertEqual(data["stdout"]["prefix_hex"], (b"x" * 128).hex())
        self.assertEqual(data["stdout"]["prefix_sha256"], hashlib.sha256(b"x" * 128).hexdigest())
        self.assertLess(len(str(failure.exception)), 4096)

    def test_stderr_flood_cannot_become_a_success_or_unbounded_exception(self):
        with self.assertRaises(self.helper.CaptureError) as failure:
            self.helper.capture(self.command("import os; os.write(2, b'e' * 200000)"),
                                output_limit=65536, prefix_limit=128)
        self.assertEqual(failure.exception.details["failure"], "stderr output limit")
        self.assertLess(len(str(failure.exception)), 4096)

    def test_exact_output_cap_is_rejected_and_one_below_preserved(self):
        for count in (4095, 4096):
            argv = self.command(f"import os; os.write(1, b'x' * {count})")
            if count == 4096:
                with self.assertRaises(self.helper.CaptureError):
                    self.helper.checked(argv, output_limit=4096)
            else:
                self.assertEqual(self.helper.checked(argv, output_limit=4096), "x" * count)

    def test_timeout_reaps_only_the_owned_child_even_after_pipe_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pid"
            code = (f"import os,time; from pathlib import Path; Path({str(path)!r}).write_text(str(os.getpid())); "
                    "os.close(1); os.close(2); time.sleep(30)")
            started = time.monotonic()
            with self.assertRaises(self.helper.CaptureError) as failure:
                self.helper.checked(self.command(code), timeout=0.3)
            self.assertEqual(failure.exception.details["failure"], "timeout")
            self.assertLess(time.monotonic() - started, 3)
            pid = int(path.read_text())
            self.assertEqual(pid, failure.exception.details["pid"])
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_utf8_split_across_writes_and_text_newlines_are_preserved(self):
        code = "import os,time; os.write(1,b'  a\\xc3');time.sleep(.01);os.write(1,b'\\xa9\\r\\n\\n')"
        self.assertEqual(self.helper.checked(self.command(code)), "  aé\n\n")

    def test_success_stops_an_owned_same_group_heartbeat_heir(self):
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "heartbeat"
            heir = ("import time;from pathlib import Path;end=time.monotonic()+2;"
                    f"p=Path({str(heartbeat)!r});"
                    "exec('while time.monotonic()<end:\\n p.write_text(str(time.monotonic()))\\n time.sleep(.02)')")
            parent = (f"import subprocess,time;from pathlib import Path;p=Path({str(heartbeat)!r});"
                      f"subprocess.Popen([{sys.executable!r},'-c',{heir!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                      "end=time.monotonic()+1;exec('while not p.exists() and time.monotonic()<end: time.sleep(.01)');"
                      "assert p.exists();print('ready')")
            self.assertEqual(self.helper.checked(self.command(parent), timeout=2), "ready\n")
            observed = heartbeat.read_text()
            time.sleep(.1)
            self.assertEqual(heartbeat.read_text(), observed)

    def test_invalid_utf8_is_refused_with_raw_prefix_retained(self):
        with self.assertRaises(self.helper.CaptureError) as failure:
            self.helper.checked(self.command("import os;os.write(1,b'\\xff')"))
        self.assertIn("UTF-8", failure.exception.details["failure"])
        self.assertEqual(failure.exception.details["stdout"]["prefix_hex"], "ff")

    def test_empty_success_unexpected_stderr_and_nonzero_status(self):
        self.assertEqual(self.helper.checked(self.command("pass")), "")
        for program in ("raise SystemExit(7)", "import sys;print('warning',file=sys.stderr)"):
            with self.subTest(program=program), self.assertRaises(self.helper.CaptureError):
                self.helper.checked(self.command(program))
        observed = self.helper.capture(self.command("import sys;print('expected rejection',file=sys.stderr);sys.exit(1)"))
        self.assertEqual((observed.returncode, observed.stderr), (1, "expected rejection\n"))

    def test_link_layout_is_scoped_to_gcc_sanitized_linux_x86_executables(self):
        for compiler in ("gcc", "clang"):
            for sanitized in (False, True):
                for system in ("Linux", "Darwin"):
                    for machine in ("x86_64", "aarch64"):
                        expected = ["-no-pie"] if (compiler, sanitized, system, machine) == ("gcc", True, "Linux", "x86_64") else []
                        with self.subTest(compiler=compiler, sanitized=sanitized, system=system, machine=machine):
                            self.assertEqual(self.helper.sanitizer_executable_link_flags(
                                compiler, sanitized, system=system, architecture=machine), expected)

    def test_elf_type_requires_one_actual_header_type(self):
        self.assertEqual(self.helper.elf_type("  Type: DYN (Position-Independent Executable file)\n"), "DYN")
        self.assertEqual(self.helper.elf_type("  Type: EXEC (Executable file)\n"), "EXEC")
        for text in ("", "Type: EXEC\nType: DYN\n"):
            with self.assertRaises(ValueError):
                self.helper.elf_type(text)
        with self.assertRaises(ValueError):
            self.helper.executable_layout("Type: DYN (Shared object file)\n", ["-no-pie"])
        with self.assertRaises(ValueError):
            self.helper.executable_layout("Type: REL (Relocatable file)\n", [])


if __name__ == "__main__":
    unittest.main()
