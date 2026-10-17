"""Compile the real CMake recipes to bound a pinned-vendor warning exception."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "ci/test/data/shrincs_warning_scope"
CLANG = shutil.which("clang-20") or shutil.which("clang")
CLANGXX = shutil.which("clang++-20") or shutil.which("clang++")


@unittest.skipUnless(os.name != "nt" and shutil.which("cmake") and shutil.which("ninja") and CLANG and CLANGXX,
                     "requires POSIX compile recipes, CMake, Ninja and Clang C/C++ compilers")
class ShrincsWarningScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        build = Path(cls.temporary.name)
        configured = subprocess.run(
            ["cmake", "-S", str(FIXTURE), "-B", str(build), "-G", "Ninja",
             f"-DPQBTC_SOURCE_DIR={REPO_ROOT}", f"-DCMAKE_C_COMPILER={CLANG}",
             f"-DCMAKE_CXX_COMPILER={CLANGXX}"],
            capture_output=True, text=True, check=False,
        )
        if configured.returncode:
            raise RuntimeError(configured.stdout + configured.stderr)
        cls.commands = json.loads((build / "compile_commands.json").read_text())

    def compile_source(self, source, replacement=None):
        entry = next(item for item in self.commands if Path(item["file"]).resolve() == source.resolve())
        command = shlex.split(entry["command"])
        if replacement is not None:
            command[command.index(entry["file"])] = str(replacement)
        return subprocess.run(
            command, cwd=entry["directory"],
            capture_output=True, text=True, check=False,
        )

    def test_pinned_vendor_panic_fallback_is_not_fatal(self):
        result = self.compile_source(REPO_ROOT / "src/crypto/shrincs/third_party/libshrincs/src/util.c")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("-Wunreachable-code", result.stderr)

    def test_project_unreachable_code_is_still_fatal(self):
        result = self.compile_source(FIXTURE / "unreachable_control.c")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-Werror,-Wunreachable-code", result.stderr)

    def test_other_project_warnings_are_still_fatal(self):
        result = self.compile_source(FIXTURE / "warnings_control.c")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-Werror,-Wunused-variable", result.stderr)

    def test_other_warnings_in_vendor_recipe_are_still_fatal(self):
        result = self.compile_source(
            REPO_ROOT / "src/crypto/shrincs/third_party/libshrincs/src/util.c",
            replacement=FIXTURE / "warnings_control.c",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-Werror,-Wunused-variable", result.stderr)
