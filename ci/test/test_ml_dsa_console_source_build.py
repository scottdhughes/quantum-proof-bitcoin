"""Clean source-export tests; no native prototype executes on the host."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("console_source_build", ROOT / "contrib/ml-dsa-console/source_build.py")
source_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_build)


class SourceExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Public fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "hello.txt").write_text("public source\n")
        (self.repo / ".gitignore").write_text("ignored-file\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Public fixture source")
        self.destination = Path(self.temp.name) / "export"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.STDOUT).decode().strip()

    def test_export_preserves_exact_clean_head_without_original_git_configuration(self):
        self.git("config", "remote.origin.url", "https://example.invalid/public-fixture.git")
        (self.repo / "ignored-file").write_text("must not be copied\n")
        identity = source_build.stage_source(self.repo, self.destination)
        self.assertEqual(identity["source_head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(identity["source_tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual((self.destination / "hello.txt").read_text(), "public source\n")
        self.assertFalse((self.destination / "ignored-file").exists())
        copied = subprocess.check_output(["git", "-C", str(self.destination), "rev-parse", "HEAD"]).decode().strip()
        self.assertEqual(copied, identity["source_head"])
        self.assertEqual(subprocess.check_output(["git", "-C", str(self.destination), "status", "--porcelain"]), b"")
        config = (self.destination / ".git/config").read_text()
        self.assertNotIn("remote", config)
        self.assertNotIn("example.invalid", config)
        self.assertFalse((self.destination / ".git/objects/info/alternates").exists())

    def test_modified_or_untracked_source_is_refused(self):
        (self.repo / "hello.txt").write_text("modified\n")
        with self.assertRaisesRegex(source_build.BuildError, "clean"):
            source_build.stage_source(self.repo, self.destination)
        self.git("checkout", "--", "hello.txt")
        (self.repo / "untracked").write_text("not part of a source commit\n")
        with self.assertRaisesRegex(source_build.BuildError, "clean"):
            source_build.stage_source(self.repo, self.destination)

    def test_private_umask_exports_readable_tracked_modes_without_touching_source(self):
        scripts = self.repo / "scripts"
        scripts.mkdir()
        executable = scripts / "build.sh"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        (self.repo / "script-link").symlink_to("scripts/build.sh")
        (self.repo / "directory-link").symlink_to("scripts")
        self.git("add", ".")
        self.git("commit", "-qm", "Public executable and internal links")
        executable.chmod(0o700)
        original = self.repo / "hello.txt"
        original.chmod(0o600)
        ignored = self.repo / "ignored-file"
        ignored.write_text("ignored public fixture remains private\n")
        ignored.chmod(0o600)
        outer = Path(self.temp.name)
        outer_mode = stat.S_IMODE(outer.stat().st_mode)
        previous = os.umask(0o077)
        try:
            identity = source_build.stage_source(self.repo, self.destination)
            self.assertEqual(os.umask(0o077), 0o077)
            expected_executable = self.destination / "scripts/build.sh"
            for path in [self.destination, *self.destination.rglob("*")]:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                expected = 0o755 if stat.S_ISDIR(info.st_mode) or path == expected_executable else 0o644
                self.assertEqual(stat.S_IMODE(info.st_mode), expected, str(path.relative_to(self.destination)))
        finally:
            os.umask(previous)
        self.assertEqual(identity["source_head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(identity["source_tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(subprocess.check_output(["git", "-C", str(self.destination), "status", "--porcelain"]), b"")
        self.assertEqual(stat.S_IMODE(outer.stat().st_mode), outer_mode)
        self.assertEqual(stat.S_IMODE(original.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(ignored.stat().st_mode), 0o600)
        self.assertFalse((self.destination / "ignored-file").exists())
        self.assertEqual(os.readlink(self.destination / "script-link"), "scripts/build.sh")
        self.assertEqual(os.readlink(self.destination / "directory-link"), "scripts")

    def test_symlink_chain_cannot_escape_via_an_internal_directory_alias(self):
        (self.repo / "alias").symlink_to(".")
        (self.repo / "directory").mkdir()
        (self.repo / "directory/link").symlink_to("../alias/..")
        self.git("add", ".")
        self.git("commit", "-qm", "Bounded source link-chain refusal fixture")
        outside = Path(self.temp.name) / "outside"
        outside.write_text("unrelated public fixture\n")
        outside.chmod(0o600)
        with self.assertRaisesRegex(source_build.BuildError, "symlink"):
            source_build.stage_source(self.repo, self.destination)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o600)

    def test_tracked_credential_named_path_is_refused(self):
        (self.repo / "credentials").write_text("public refusal fixture\n")
        self.git("add", "credentials")
        self.git("commit", "-qm", "Refusal fixture")
        with self.assertRaisesRegex(source_build.BuildError, "sensitive"):
            source_build.stage_source(self.repo, self.destination)

    def test_escape_symlink_is_refused_without_following_it(self):
        (self.repo / "external").symlink_to("../outside-fixture")
        self.git("add", "external")
        self.git("commit", "-qm", "Symlink refusal fixture")
        with self.assertRaisesRegex(source_build.BuildError, "symlink"):
            source_build.stage_source(self.repo, self.destination)

    def test_existing_destination_is_preserved(self):
        self.destination.mkdir()
        (self.destination / "preserve").write_text("existing\n")
        with self.assertRaises(source_build.BuildError):
            source_build.stage_source(self.repo, self.destination)
        self.assertEqual((self.destination / "preserve").read_text(), "existing\n")

    def test_build_uses_fresh_context_and_binds_exact_manifest_bytes(self):
        self.exercise_build_context()

    def test_live_recipe_edit_after_export_cannot_change_attested_build(self):
        self.exercise_build_context(mutate_after_export=True)

    def exercise_build_context(self, mutate_after_export=False):
        recipe = self.repo / "contrib/ml-dsa-console/container"
        recipe.mkdir(parents=True)
        (recipe / "Dockerfile").write_text("FROM scratch\n")
        (recipe / "build_native.sh").write_text("#!/bin/sh\nexit 0\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Public build recipe fixture")
        image = "sha256:" + "ab" * 32
        manifest = {"schema": "PQBTC-MLDSA44-SOURCE-BUILD-1", "compiler": "gcc",
                    "source_head": self.git("rev-parse", "HEAD"), "source_tree": self.git("rev-parse", "HEAD^{tree}")}
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        original = subprocess.run
        original_stage = source_build.stage_source
        commands = []

        def stage(repo, destination):
            identity = original_stage(repo, destination)
            if mutate_after_export:
                (recipe / "Dockerfile").write_text("FROM unexpected-live-edit\n")
                (recipe / "build_native.sh").write_text("#!/bin/sh\nexit 99\n")
            return identity

        def run(command, **kwargs):
            if command[0] != "docker":
                return original(command, **kwargs)
            commands.append(command)
            context = Path(command[-1])
            self.assertEqual((context / "source/hello.txt").read_text(), "public source\n")
            self.assertEqual((context / "Dockerfile").read_text(), "FROM scratch\n")
            self.assertEqual((context / "build_native.sh").read_text(), "#!/bin/sh\nexit 0\n")
            self.assertNotIn("remote", (context / "source/.git/config").read_text())
            self.assertIn("--no-cache", command)
            self.assertIn("--pull", command)
            return subprocess.CompletedProcess(command, 0)

        def output(command, **kwargs):
            return image + "\n" if command[1] == "image" else raw

        with patch.object(source_build, "stage_source", side_effect=stage), \
                patch.object(subprocess, "run", side_effect=run), patch.object(subprocess, "check_output", side_effect=output):
            descriptor = source_build.build_image(self.repo, no_cache=True, progress=lambda _: None)
        self.assertEqual(len(commands), 1)
        self.assertEqual(descriptor["image"], image)
        self.assertEqual(descriptor["manifest"], manifest)
        self.assertEqual(descriptor["manifest_sha256"], hashlib.sha256(raw).hexdigest())

    def test_invalid_compiler_or_tag_cannot_start_docker(self):
        with patch.object(subprocess, "run", side_effect=AssertionError("No external operation permitted")):
            with self.assertRaises(source_build.BuildError):
                source_build.build_image(self.repo, compiler="other")
            with self.assertRaises(source_build.BuildError):
                source_build.build_image(self.repo, image_tag="unsafe tag")


if __name__ == "__main__":
    unittest.main()
