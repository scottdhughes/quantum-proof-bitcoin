#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Receive one hash-pinned public code archive through private SSH stdin."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

MAX_BYTES = 2 * 1024 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def extract(archive, destination, prefix):
    """Flatten only regular files/directories inside the one declared root."""
    total, seen = 0, set()
    with tarfile.open(archive) as source:
        for item in source:
            path = Path(item.name)
            need(item.name not in seen and not path.is_absolute() and ".." not in path.parts and
                 path.parts and path.parts[0] == prefix, "Unsafe archive path")
            seen.add(item.name)
            need(len(seen) <= 20000, "Archive has too many members")
            need(item.isfile() or item.isdir(), "Archive links/special files are refused")
            target = Path(destination) / path
            if item.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            total += item.size
            need(item.size <= 256 * 1024 * 1024 and total <= MAX_BYTES and len(seen) <= 20000,
                 "Archive exceeds resource bounds")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            stream = source.extractfile(item)
            need(stream is not None, "Archive file missing")
            with target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            target.chmod(0o555 if item.mode & 0o111 else 0o444)
    need(seen and (Path(destination) / prefix).is_dir(), "Archive root missing")


def owned(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
         "Installation directory ownership differs")


def verify_installed(archive, target, prefix, *, owner=0):
    """Verify a complete installed tree, including replay after a lost marker."""
    target = Path(target)
    root_info = target.lstat()
    need(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == owner and not root_info.st_mode & 0o022,
         "Installed root ownership differs")
    expected = set()
    with tarfile.open(archive) as source:
        for item in source:
            relative = Path(item.name)
            need(relative.parts and relative.parts[0] == prefix and not relative.is_absolute() and
                 ".." not in relative.parts and (item.isdir() or item.isfile()), "Installed archive path differs")
            parts = relative.parts[1:]
            if not parts:
                continue
            name = str(Path(*parts))
            need(name not in expected, "Duplicate installed archive member")
            expected.add(name)
            path = target.joinpath(*parts)
            info = path.lstat()
            need(info.st_uid == owner and not info.st_mode & 0o022 and
                 (stat.S_ISDIR(info.st_mode) if item.isdir() else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                 "Installed member ownership/type differs")
            if item.isfile():
                # Git may refresh its stat cache; tracked source/object contents
                # and the complete file set are still checked. Git below checks
                # that this index describes the exact pinned clean tree.
                if prefix == "control" and name == ".git/index":
                    continue
                expected_data = source.extractfile(item)
                need(expected_data is not None and info.st_size == item.size, "Installed member size differs")
                with path.open("rb") as actual:
                    need(hashlib.file_digest(actual, "sha256").hexdigest() ==
                         hashlib.file_digest(expected_data, "sha256").hexdigest(), "Installed bytes differ")
    observed = {str(path.relative_to(target)) for path in target.rglob("*")}
    need(observed == expected, "Installed tree has missing or extra members")


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    need(len(args) == 6 and os.geteuid() == 0 and sys.platform.startswith("linux"), "Contained Linux root required")
    role, expected_hash, expected_size, control_head, control_tree, root_value = args
    need(role in ("control", "a3", "c") and re.fullmatch(r"[0-9a-f]{64}", expected_hash) and
         expected_size.isdigit() and 0 < int(expected_size) <= MAX_BYTES and
         re.fullmatch(r"[0-9a-f]{40}", control_head) and re.fullmatch(r"[0-9a-f]{40}", control_tree),
         "Installation arguments refused")
    root = Path(root_value)
    need(root == Path("/opt/pqbtc-runpod"), "Installation root refused")
    root.mkdir(mode=0o755, exist_ok=True)
    owned(root)
    uploads = root / "uploads"
    uploads.mkdir(mode=0o700, exist_ok=True)
    owned(uploads)
    with tempfile.TemporaryDirectory(prefix="stage-", dir=root) as temporary:
        temporary = Path(temporary)
        archive = temporary / "payload.tar"
        count, sha = 0, hashlib.sha256()
        with archive.open("xb") as output:
            while True:
                block = sys.stdin.buffer.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                need(count <= int(expected_size), "Upload exceeds declared size")
                sha.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        need(count == int(expected_size) and sha.hexdigest() == expected_hash, "Uploaded archive differs")
        marker = root / ("installed-" + role + ("-" + control_head if role == "control" else "") + ".json")
        target = root / ("control-" + control_head[:16]) if role == "control" else root / "versions" / role
        if marker.exists():
            info = marker.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                 not info.st_mode & 0o022 and info.st_size < 4096, "Installation marker refused")
            prior = json.loads(marker.read_text())
            need(prior == {"role": role, "archive_sha256": expected_hash, "target": str(target)} and target.is_dir(),
                 "Existing installation differs; preserved")
        elif not target.exists() and not target.is_symlink():
            extract(archive, temporary / "files", role)
            staged = temporary / "files" / role
            if role == "control":
                def git(*command):
                    return subprocess.check_output(["git", "-C", str(staged), *command], text=True, encoding="utf8", timeout=30).strip()
                need(git("rev-parse", "HEAD") == control_head and git("rev-parse", "HEAD^{tree}") == control_tree and
                     git("status", "--porcelain=v1", "--untracked-files=all") == "", "Control source identity differs")
            else:
                descriptor = json.loads((staged / "descriptor.json").read_text())
                need(descriptor.get("version") == role and descriptor.get("schema") == "PQBTC-RUNPOD-PAYLOAD-1",
                     "Native payload descriptor differs")
                observed = set()
                for path in (staged / "seed").rglob("*"):
                    if path.is_file():
                        name = str(path.relative_to(staged))
                        need(name in descriptor["files"], "Unlisted native payload file")
                        with path.open("rb") as handle:
                            need(hashlib.file_digest(handle, "sha256").hexdigest() == descriptor["files"][name],
                                 "Native payload content differs")
                        observed.add(name)
                need(observed == set(descriptor["files"]), "Native payload member missing")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            owned(target.parent)
            staged.chmod(0o755)
            os.rename(staged, target)
        # Revalidate even an idempotent receipt. An interrupted rename can be
        # completed only after proving the existing public-code tree identical.
        verify_installed(archive, target, role)
        if role == "control":
            def installed_git(*command):
                return subprocess.check_output(["git", "-C", str(target), *command], text=True, encoding="utf8", timeout=30).strip()
            need(installed_git("rev-parse", "HEAD") == control_head and installed_git("rev-parse", "HEAD^{tree}") == control_tree and
                 installed_git("status", "--porcelain=v1", "--untracked-files=all") == "", "Installed control source differs")
        if not marker.exists():
            with marker.open("x") as handle:
                json.dump({"role": role, "archive_sha256": expected_hash, "target": str(target)}, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            marker.chmod(0o444)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    print(json.dumps({"result": "PASS", "role": role, "target": str(target), "archive_sha256": expected_hash}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Pinned public-code installation refused") from None
