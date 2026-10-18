"""Regression tests for fail-closed verify-commits ancestry handling."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_COMMITS_SOURCE = REPO_ROOT / "contrib" / "verify-commits"
ZERO_COMMIT = "0" * 40


class VerifyCommitsAncestryTest(unittest.TestCase):
    def setUp(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.fail("git is required for verify-commits ancestry tests")
        self.git = git

        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temporary_path = Path(self.temporary_directory.name)
        self.repository = self.temporary_path / "repository"
        self.home = self.temporary_path / "home"
        self.home.mkdir()
        self.gnupg_home = self.temporary_path / "gnupg"
        self.gnupg_home.mkdir(mode=0o700)

        self.git_environment = os.environ.copy()
        for name in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GPG_AGENT_INFO",
            "GPG_TTY",
        ):
            self.git_environment.pop(name, None)
        for name in tuple(self.git_environment):
            if name == "GIT_CONFIG_COUNT" or name.startswith(
                ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
            ):
                self.git_environment.pop(name)
        self.git_environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GNUPGHOME": str(self.gnupg_home),
                "HOME": str(self.home),
                "LC_ALL": "C",
                "GIT_AUTHOR_NAME": "Verify Commits Tests",
                "GIT_AUTHOR_EMAIL": "verify-commits@example.invalid",
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
                "GIT_COMMITTER_NAME": "Verify Commits Tests",
                "GIT_COMMITTER_EMAIL": "verify-commits@example.invalid",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            }
        )

        subprocess.run(
            [self.git, "init", "-q", "--object-format=sha1", str(self.repository)],
            check=True,
            env=self.git_environment,
        )
        self.run_git("config", "maintenance.auto", "false")
        self.run_git("config", "gc.auto", "0")

        self.verify_commits_directory = self.temporary_path / "verify-commits"
        shutil.copytree(VERIFY_COMMITS_SOURCE, self.verify_commits_directory)
        self.verify_commits_script = (
            self.verify_commits_directory / "verify-commits.py"
        )

        tree = self.run_git("mktree", input_text="")
        self.base = self.commit_tree(tree, "base")
        self.trusted_git_root = self.commit_tree(
            tree, "trusted Git root", parent=self.base
        )
        self.candidate = self.commit_tree(
            tree, "candidate", parent=self.trusted_git_root
        )
        self.divergent = self.commit_tree(
            tree, "divergent", parent=self.base
        )

    def run_git(self, *arguments: str, input_text: str | None = None) -> str:
        completed = subprocess.run(
            [self.git, *arguments],
            cwd=self.repository,
            env=self.git_environment,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"git {' '.join(arguments)} failed:\n{completed.stderr}",
        )
        return completed.stdout.strip()

    def commit_tree(self, tree: str, message: str, *, parent: str | None = None) -> str:
        arguments = ["commit-tree", tree]
        if parent is not None:
            arguments.extend(("-p", parent))
        arguments.extend(("-m", message))
        return self.run_git(*arguments)

    def configure_roots(self, git_root: str, tree_sha512_root: str) -> None:
        (self.verify_commits_directory / "trusted-git-root").write_text(
            f"{git_root}\n", encoding="utf8"
        )
        (
            self.verify_commits_directory / "trusted-sha512-root-commit"
        ).write_text(f"{tree_sha512_root}\n", encoding="utf8")

    def run_verify_commits(self, commit: str) -> subprocess.CompletedProcess[str]:
        environment = self.git_environment.copy()
        environment["GIT"] = self.git
        environment.pop("CI", None)
        environment.pop("BITCOIN_VERIFY_COMMITS_ALLOW_SHA1", None)
        return subprocess.run(
            [sys.executable, str(self.verify_commits_script), commit],
            cwd=self.repository,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_missing_exact_trusted_git_root_fails_closed(self) -> None:
        self.configure_roots(ZERO_COMMIT, self.base)

        completed = self.run_verify_commits(ZERO_COMMIT)

        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("Failed to determine ancestry", completed.stderr)
        self.assertIn("for the trusted Git root", completed.stderr)
        self.assertNotIn("There is a valid path", completed.stdout)

    def test_missing_requested_commit_fails_closed(self) -> None:
        self.configure_roots(self.trusted_git_root, self.base)

        completed = self.run_verify_commits(ZERO_COMMIT)

        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("Failed to determine ancestry", completed.stderr)
        self.assertIn("for the trusted Git root", completed.stderr)
        self.assertNotIn("predates the trusted root", completed.stdout)

    def test_divergent_git_root_fails_closed(self) -> None:
        self.configure_roots(self.trusted_git_root, self.base)

        completed = self.run_verify_commits(self.divergent)

        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn(
            f'"{self.divergent}" diverges from the trusted Git root '
            f'"{self.trusted_git_root}"',
            completed.stderr,
        )
        self.assertNotIn("predates the trusted root", completed.stdout)

    def test_missing_tree_sha512_root_fails_closed(self) -> None:
        self.configure_roots(self.trusted_git_root, ZERO_COMMIT)

        completed = self.run_verify_commits(self.candidate)

        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("Failed to determine ancestry", completed.stderr)
        self.assertIn("for the trusted Tree-SHA512 root", completed.stderr)
        self.assertNotIn("not signed with a trusted key", completed.stderr)
        self.assertNotIn("disabling tree verification", completed.stdout)

    def test_divergent_tree_sha512_root_fails_closed(self) -> None:
        self.configure_roots(self.trusted_git_root, self.divergent)

        completed = self.run_verify_commits(self.candidate)

        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn(
            f'"{self.candidate}" diverges from the trusted Tree-SHA512 root '
            f'"{self.divergent}"',
            completed.stderr,
        )
        self.assertNotIn("not signed with a trusted key", completed.stderr)
        self.assertNotIn("disabling tree verification", completed.stdout)

    def test_valid_git_root_boundaries_are_preserved(self) -> None:
        self.configure_roots(self.trusted_git_root, self.base)

        cases = (
            (self.trusted_git_root, "There is a valid path"),
            (self.base, "predates the trusted root, stopping!"),
        )
        for commit, expected_output in cases:
            with self.subTest(commit=commit):
                completed = self.run_verify_commits(commit)
                self.assertEqual(
                    completed.returncode, 0, completed.stdout + completed.stderr
                )
                self.assertIn(expected_output, completed.stdout)


if __name__ == "__main__":
    unittest.main()
