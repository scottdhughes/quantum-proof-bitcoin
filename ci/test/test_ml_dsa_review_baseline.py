#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_DIR = REPO_ROOT / "contrib" / "ml-dsa-ref"
VALIDATOR = VALIDATOR_DIR / "validate_review_baseline.py"

sys.path.insert(0, str(VALIDATOR_DIR))
import validate_review_baseline as baseline_validator  # noqa: E402


class MlDsaReviewBaselineTest(unittest.TestCase):
    def setUp(self):
        if shutil.which("git") is None:
            self.skipTest("Git unavailable")
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Review Baseline Test")
        self.git(
            "config",
            "user.email",
            "review-baseline@example.invalid",
        )
        self.pointer = self.repository / "review-baseline"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def git(
        self,
        *arguments,
        repository=None,
        input_text=None,
        check=True,
    ):
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository or self.repository),
                *arguments,
            ],
            check=False,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if check and result.returncode != 0:
            self.fail(
                f"git {' '.join(arguments)} failed:\n"
                f"{result.stdout}{result.stderr}"
            )
        return result

    def commit_file(self, relative_path, contents, message):
        path = self.repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf8")
        self.git("add", "--", relative_path)
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def write_pointer(self, commit):
        self.pointer.write_bytes(commit.encode("ascii") + b"\n")

    def validate(self, *, pointer=None, head, base, mode):
        return baseline_validator.validate_review_baseline(
            repository=self.repository,
            pointer_path=pointer or self.pointer,
            head=head,
            base=base,
            mode=mode,
        )

    def linear_pull_request(self):
        baseline = self.commit_file("payload", "baseline\n", "baseline")
        base = self.commit_file("payload", "base\n", "base")
        head = self.commit_file("payload", "head\n", "head")
        return baseline, base, head

    def test_pointer_bytes_are_strict(self):
        baseline, base, head = self.linear_pull_request()
        invalid_pointers = {
            "missing LF": baseline.encode("ascii"),
            "CRLF": baseline.encode("ascii") + b"\r\n",
            "extra LF": baseline.encode("ascii") + b"\n\n",
            "uppercase": baseline.upper().encode("ascii") + b"\n",
            "leading space": b" " + baseline.encode("ascii") + b"\n",
            "trailing space": baseline.encode("ascii") + b" \n",
            "short": b"a" * 39 + b"\n",
            "long": b"a" * 41 + b"\n",
            "nonhex": b"g" * 40 + b"\n",
        }
        for label, contents in invalid_pointers.items():
            with self.subTest(label=label):
                self.pointer.write_bytes(contents)
                with self.assertRaisesRegex(
                    baseline_validator.BaselineValidationError,
                    "exactly 40 lowercase hexadecimal",
                ):
                    self.validate(
                        head=head,
                        base=base,
                        mode="pull_request",
                    )

    def test_missing_pointer_file_is_rejected(self):
        _baseline, base, head = self.linear_pull_request()
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "cannot inspect baseline pointer",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_pointer_must_be_a_plain_regular_file(self):
        baseline, base, head = self.linear_pull_request()
        target = self.repository / "pointer-target"
        target.write_text(baseline + "\n", encoding="ascii")
        self.pointer.symlink_to(target)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "must be a regular file.*must not be a symbolic link",
        ):
            self.validate(head=head, base=base, mode="pull_request")

        self.pointer.unlink()
        self.pointer.mkdir()
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "must be a regular file.*must not be a symbolic link",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_missing_and_noncommit_pointer_objects_are_rejected(self):
        _baseline, base, head = self.linear_pull_request()
        self.write_pointer("f" * 40)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "full Git history is required",
        ):
            self.validate(head=head, base=base, mode="pull_request")

        blob = self.git(
            "hash-object",
            "-w",
            "--stdin",
            input_text="not a commit\n",
        ).stdout.strip()
        self.write_pointer(blob)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "does not name a commit.*found blob",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_base_and_head_must_name_commits(self):
        baseline, base, head = self.linear_pull_request()
        self.write_pointer(baseline)
        blob = self.git(
            "hash-object",
            "-w",
            "--stdin",
            input_text="not a commit\n",
        ).stdout.strip()
        for label, candidate_base, candidate_head in (
            ("base", blob, head),
            ("head", base, blob),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    baseline_validator.BaselineValidationError,
                    f"{label} .* does not name a commit",
                ):
                    self.validate(
                        head=candidate_head,
                        base=candidate_base,
                        mode="pull_request",
                    )

    def test_shallow_repository_fails_explicitly(self):
        baseline = self.commit_file("payload", "baseline\n", "baseline")
        self.commit_file("review-baseline", baseline + "\n", "head")
        shallow = self.root / "shallow"
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--depth",
                "1",
                self.repository.as_uri(),
                str(shallow),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        shallow_head = self.git(
            "rev-parse",
            "HEAD",
            repository=shallow,
        ).stdout.strip()
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "repository is shallow; full Git history is required",
        ):
            baseline_validator.validate_review_baseline(
                repository=shallow,
                pointer_path="review-baseline",
                head=shallow_head,
                base=shallow_head,
                mode="main",
            )

    def test_pointer_must_not_equal_head(self):
        _baseline, base, head = self.linear_pull_request()
        self.write_pointer(head)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "must not equal the head commit",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_base_must_be_an_ancestor_of_head(self):
        baseline = self.commit_file("payload", "baseline\n", "baseline")
        main_branch = self.git(
            "symbolic-ref",
            "--short",
            "HEAD",
        ).stdout.strip()
        self.git("switch", "-q", "-c", "side")
        head = self.commit_file("side", "side\n", "side head")
        self.git("switch", "-q", main_branch)
        base = self.commit_file("main", "main\n", "main base")
        self.write_pointer(baseline)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "base commit .* is not an ancestor of head commit",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_side_branch_pointer_is_rejected(self):
        root = self.commit_file("payload", "root\n", "root")
        main_branch = self.git(
            "symbolic-ref",
            "--short",
            "HEAD",
        ).stdout.strip()
        self.git("switch", "-q", "-c", "side", root)
        side = self.commit_file("side", "side\n", "side")
        self.git("switch", "-q", main_branch)
        base = self.commit_file("payload", "base\n", "base")
        head = self.commit_file("payload", "head\n", "head")
        self.write_pointer(side)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "not on the base first-parent chain",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_second_parent_pointer_is_rejected(self):
        root = self.commit_file("payload", "root\n", "root")
        main_branch = self.git(
            "symbolic-ref",
            "--short",
            "HEAD",
        ).stdout.strip()
        self.git("switch", "-q", "-c", "side", root)
        side = self.commit_file("side", "side\n", "side")
        self.git("switch", "-q", main_branch)
        self.commit_file("main", "main\n", "main")
        self.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
        base = self.git("rev-parse", "HEAD").stdout.strip()
        head = self.commit_file("main", "head\n", "PR head")
        self.write_pointer(side)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "not on the base first-parent chain",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_pointer_created_inside_pull_request_is_rejected(self):
        _root = self.commit_file("payload", "root\n", "root")
        base = self.commit_file("payload", "base\n", "base")
        pull_request_commit = self.commit_file(
            "payload",
            "inside PR\n",
            "inside PR",
        )
        head = self.commit_file("payload", "head\n", "head")
        self.write_pointer(pull_request_commit)
        with self.assertRaisesRegex(
            baseline_validator.BaselineValidationError,
            "not on the base first-parent chain",
        ):
            self.validate(head=head, base=base, mode="pull_request")

    def test_valid_pull_request_uses_base_first_parent_chain(self):
        baseline, base, head = self.linear_pull_request()
        self.write_pointer(baseline)
        self.assertEqual(
            self.validate(head=head, base=base, mode="pull_request"),
            baseline,
        )

    def test_valid_main_pointer_only_promotion_and_cli_output(self):
        self.commit_file("payload", "baseline\n", "baseline")
        reviewed = self.commit_file("payload", "reviewed\n", "reviewed")
        promoted = self.commit_file(
            "review-baseline",
            reviewed + "\n",
            "advance review baseline",
        )
        changed_paths = self.git(
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            promoted,
        ).stdout.splitlines()
        self.assertEqual(changed_paths, ["review-baseline"])
        self.assertEqual(
            self.validate(
                pointer=self.repository / "review-baseline",
                head=promoted,
                base=reviewed,
                mode="main",
            ),
            reviewed,
        )

        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--pointer",
                "review-baseline",
                "--head",
                promoted,
                "--base",
                reviewed,
                "--mode",
                "main",
            ],
            cwd=self.repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, reviewed + "\n")
        self.assertEqual(result.stderr, "")

    def test_cli_failure_uses_stderr_and_keeps_stdout_empty(self):
        _baseline, base, head = self.linear_pull_request()
        self.pointer.write_bytes(b"A" * 40 + b"\n")
        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--pointer",
                str(self.pointer),
                "--head",
                head,
                "--base",
                base,
                "--mode",
                "pull_request",
            ],
            cwd=self.repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn(
            "error: baseline pointer must contain exactly 40 lowercase",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
