#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Validate the immutable-history anchor for ML-DSA review evidence."""

import argparse
from pathlib import Path
import re
import stat
import subprocess
import sys


POINTER_PATTERN = re.compile(rb"[0-9a-f]{40}\n")
VALID_MODES = ("pull_request", "main")


class BaselineValidationError(RuntimeError):
    """Raised when the review baseline cannot be trusted."""


def _run_git(repository, *arguments):
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise BaselineValidationError(
            "Git is required to validate the review baseline"
        ) from exc


def _run_git_bytes(repository, *arguments):
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise BaselineValidationError(
            "Git is required to validate the review baseline"
        ) from exc


def _git_error(result):
    detail = result.stderr.strip()
    if isinstance(detail, bytes):
        detail = detail.decode("utf8", errors="replace")
    return f": {detail}" if detail else ""


def _require_full_history(repository):
    result = _run_git(repository, "rev-parse", "--is-shallow-repository")
    if result.returncode != 0:
        raise BaselineValidationError(
            "cannot inspect the Git repository for full history"
            f"{_git_error(result)}"
        )
    shallow = result.stdout.strip()
    if shallow == "true":
        raise BaselineValidationError(
            "the Git repository is shallow; full Git history is required"
        )
    if shallow != "false":
        raise BaselineValidationError(
            "Git returned an unknown shallow-repository status; "
            "full Git history is required"
        )


def _read_pointer(repository, pointer_path):
    path = Path(pointer_path)
    if not path.is_absolute():
        path = Path(repository) / path
    try:
        status = path.lstat()
    except OSError as exc:
        raise BaselineValidationError(
            f"cannot inspect baseline pointer {path}: {exc}"
        ) from exc
    if not stat.S_ISREG(status.st_mode):
        raise BaselineValidationError(
            "baseline pointer must be a regular file and must not be a "
            "symbolic link"
        )
    try:
        contents = path.read_bytes()
    except OSError as exc:
        raise BaselineValidationError(
            f"cannot read baseline pointer {path}: {exc}"
        ) from exc
    if POINTER_PATTERN.fullmatch(contents) is None:
        raise BaselineValidationError(
            "baseline pointer must contain exactly 40 lowercase hexadecimal "
            "characters followed by one LF"
        )
    return contents[:-1].decode("ascii")


def _repository_relative_pointer(repository, pointer_path):
    repository = Path(repository).resolve()
    path = Path(pointer_path)
    if not path.is_absolute():
        path = repository / path
    try:
        relative = path.resolve().relative_to(repository)
    except (OSError, ValueError) as exc:
        raise BaselineValidationError(
            "baseline pointer must be inside the Git repository"
        ) from exc
    relative_text = relative.as_posix()
    if not relative_text or ":" in relative_text:
        raise BaselineValidationError(
            "baseline pointer has an unsupported repository-relative path"
        )
    return relative_text


def _read_pointer_at_revision(repository, pointer_path, revision):
    relative = _repository_relative_pointer(repository, pointer_path)
    tree_result = _run_git_bytes(
        repository,
        "ls-tree",
        "-z",
        "--full-tree",
        revision,
        "--",
        relative,
    )
    if tree_result.returncode != 0:
        raise BaselineValidationError(
            "cannot inspect the baseline pointer in the pull-request base tree"
            f"{_git_error(tree_result)}"
        )
    records = tree_result.stdout.split(b"\0")
    if len(records) != 2 or records[1] != b"" or b"\t" not in records[0]:
        raise BaselineValidationError(
            "pull-request base tree must contain exactly one baseline pointer"
        )
    metadata, tree_path = records[0].split(b"\t", 1)
    metadata_fields = metadata.split(b" ")
    if (
        metadata_fields[:2] != [b"100644", b"blob"]
        or len(metadata_fields) != 3
        or tree_path != relative.encode("utf8")
    ):
        raise BaselineValidationError(
            "pull-request base baseline pointer must be a plain 100644 blob"
        )
    blob_result = _run_git_bytes(
        repository,
        "cat-file",
        "blob",
        metadata_fields[2].decode("ascii"),
    )
    if blob_result.returncode != 0:
        raise BaselineValidationError(
            "cannot read the baseline pointer blob from the pull-request base"
            f"{_git_error(blob_result)}"
        )
    if POINTER_PATTERN.fullmatch(blob_result.stdout) is None:
        raise BaselineValidationError(
            "the pull-request base baseline pointer must contain exactly 40 "
            "lowercase hexadecimal characters followed by one LF"
        )
    return blob_result.stdout[:-1].decode("ascii")


def _require_commit(repository, revision, label):
    result = _run_git(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{object}}",
    )
    if result.returncode != 0:
        raise BaselineValidationError(
            f"{label} {revision!r} is unavailable; full Git history is "
            f"required{_git_error(result)}"
        )
    object_id = result.stdout.strip()
    type_result = _run_git(repository, "cat-file", "-t", "--", object_id)
    if type_result.returncode != 0:
        raise BaselineValidationError(
            f"cannot inspect {label} {revision!r}; full Git history is "
            f"required{_git_error(type_result)}"
        )
    object_type = type_result.stdout.strip()
    if object_type != "commit":
        raise BaselineValidationError(
            f"{label} {revision!r} does not name a commit "
            f"(found {object_type or 'unknown object type'})"
        )
    return object_id


def _require_base_ancestor(repository, base, head):
    result = _run_git(repository, "merge-base", "--is-ancestor", base, head)
    if result.returncode == 1:
        raise BaselineValidationError(
            f"base commit {base} is not an ancestor of head commit {head}"
        )
    if result.returncode != 0:
        raise BaselineValidationError(
            "cannot verify that base is an ancestor of head; full Git "
            f"history is required{_git_error(result)}"
        )


def _require_first_parent(repository, pointer, start, mode):
    result = _run_git(repository, "rev-list", "--first-parent", start)
    if result.returncode != 0:
        raise BaselineValidationError(
            f"cannot inspect the {mode} first-parent chain; full Git history "
            f"is required{_git_error(result)}"
        )
    if pointer not in result.stdout.splitlines():
        chain_name = "base" if mode == "pull_request" else "head"
        raise BaselineValidationError(
            f"baseline pointer {pointer} is not on the {chain_name} "
            f"first-parent chain for {mode}"
        )


def validate_review_baseline(
    *,
    repository,
    pointer_path,
    head,
    base,
    mode,
):
    """Validate and return the baseline commit named by ``pointer_path``."""

    if mode not in VALID_MODES:
        raise BaselineValidationError(
            f"unsupported validation mode {mode!r}; expected one of "
            f"{', '.join(VALID_MODES)}"
        )
    repository = Path(repository)
    _require_full_history(repository)
    pointer_text = _read_pointer(repository, pointer_path)
    pointer_commit = _require_commit(
        repository,
        pointer_text,
        "baseline pointer",
    )
    base_commit = _require_commit(repository, base, "base")
    head_commit = _require_commit(repository, head, "head")
    if pointer_commit == head_commit:
        raise BaselineValidationError(
            "baseline pointer must not equal the head commit"
        )
    _require_base_ancestor(repository, base_commit, head_commit)
    chain_start = base_commit if mode == "pull_request" else head_commit
    _require_first_parent(
        repository,
        pointer_commit,
        chain_start,
        mode,
    )
    if mode == "pull_request":
        base_pointer_text = _read_pointer_at_revision(
            repository,
            pointer_path,
            base_commit,
        )
        base_pointer_commit = _require_commit(
            repository,
            base_pointer_text,
            "pull-request base baseline pointer",
        )
        _require_first_parent(
            repository,
            base_pointer_commit,
            base_commit,
            mode,
        )
        if pointer_commit not in (base_pointer_commit, base_commit):
            raise BaselineValidationError(
                "pull-request baseline pointer must be unchanged from the "
                "base tree or advance exactly to the base commit"
            )
    return pointer_commit


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate the ML-DSA review baseline pointer",
    )
    parser.add_argument("--pointer", required=True, type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--mode", required=True, choices=VALID_MODES)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        pointer = validate_review_baseline(
            repository=Path.cwd(),
            pointer_path=args.pointer,
            head=args.head,
            base=args.base,
            mode=args.mode,
        )
    except BaselineValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(pointer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
