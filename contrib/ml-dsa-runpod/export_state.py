#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Stream a private state archive only while native custody is quiescent."""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('runpod_export_capture', HERE.parent / 'ml-dsa-qualification/native_process.py')
capture_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture_module)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
ALLOWED_IDS = frozenset((0, 1000, 1001))


def need(value, reason):
    if not value:
        raise ValueError(reason)


def quiescent_inventory(root, *, owner=0):
    result = {}
    for path in sorted(Path(root).rglob('native-processes.json')):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4 * 1024 * 1024,
             'Native registry ownership refused')
        raw = path.read_bytes()
        value = json.loads(raw)
        need(type(value) is dict and value.get('groups') == [] and
             str(value.get('namespace', '')).startswith('pqbtc-runpod-'), 'Native custody is not quiescent')
        result[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
    need(result, 'No retained native process registry exists')
    return result


def tar_command(root):
    return ['tar', '--format=posix', '-C', str(root), '--exclude=.cookie*', '--exclude=*.sock', '-cf', '-', '.']


@contextlib.contextmanager
def owner_identity(uid, gid):
    """A single-threaded root helper uses only the actual retained owner IDs."""
    need(uid in ALLOWED_IDS and gid in ALLOWED_IDS, 'Archive owner is outside the native roles')
    original_uid, original_gid = os.geteuid(), os.getegid()
    if (uid, gid) == (original_uid, original_gid):
        yield
        return
    need(original_uid == 0, 'Archive role switching requires root')
    groups = os.getgroups()
    try:
        os.setgroups([])
        os.setegid(gid)
        os.seteuid(uid)
        yield
    finally:
        os.seteuid(original_uid)
        os.setegid(original_gid)
        os.setgroups(groups)


def require_traversal(uid, gid, ancestors):
    for info in ancestors:
        bit = stat.S_IXUSR if uid == info.st_uid else stat.S_IXGRP if gid == info.st_gid else stat.S_IXOTH
        need(info.st_mode & bit, 'Archive mixed ownership would bypass a private parent')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ArchiveOutput:
    def __init__(self, fd, maximum, deadline):
        self.fd, self.maximum, self.deadline = fd, maximum, deadline
        self.count, self.checksum = 0, hashlib.sha256()

    def tell(self):
        return self.count

    def write(self, data):
        need(time.monotonic() < self.deadline and self.count + len(data) <= self.maximum,
             'Private archive time/byte bound exceeded')
        offset = 0
        while offset < len(data):
            count = os.write(self.fd, memoryview(data)[offset:])
            need(count > 0, 'Private archive write interrupted')
            self.checksum.update(memoryview(data)[offset:offset + count])
            self.count += count
            offset += count
        return len(data)


class ArchiveInput:
    def __init__(self, handle, deadline):
        self.handle, self.deadline = handle, deadline

    def read(self, size):
        need(time.monotonic() < self.deadline, 'Private archive read deadline')
        return self.handle.read(size)


def build_archive(root, archive, *, maximum=MAX_ARCHIVE_BYTES, max_members=20000, timeout=135):
    """Preserve role-owned POSIX data without asking root to bypass NFS squash."""
    root, archive = Path(root), Path(archive)
    need(root.is_absolute() and archive.is_absolute() and '..' not in archive.parts and
         type(maximum) is int and 0 < maximum <= MAX_ARCHIVE_BYTES and
         type(max_members) is int and 0 < max_members <= 20000 and 0 < timeout <= 135,
         'Private archive arguments refused')
    root_info = root.lstat()
    need(stat.S_ISDIR(root_info.st_mode), 'Private archive source is not a directory')
    root = root.resolve(strict=True)
    parent = archive.parent.resolve(strict=True)
    parent_info = parent.lstat()
    need(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.geteuid() and
         stat.S_IMODE(parent_info.st_mode) == 0o700 and not (parent / archive.name).is_relative_to(root),
         'Private archive destination is not outside the source in a private directory')
    archive = parent / archive.name
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = time.monotonic() + timeout
    output = ArchiveOutput(fd, maximum, deadline)
    members = 0
    try:
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as stream:
            def walk(path, relative, info, ancestors):
                nonlocal members
                members += 1
                need(members <= max_members and len(relative.parts) <= 64 and time.monotonic() < deadline,
                     'Private archive member/depth/time bound exceeded')
                name = '.' if not relative.parts else './' + relative.as_posix()
                need(len(name.encode('utf8')) <= 4096 and not any(char in name for char in ('\0', '\n', '\r')) and
                     '..' not in relative.parts, 'Private archive member name refused')
                if path.name.startswith('.cookie'):
                    return
                need(info.st_uid in ALLOWED_IDS and info.st_gid in ALLOWED_IDS, 'Private archive contains an unknown owner')
                if stat.S_ISSOCK(info.st_mode) and path.name.endswith('.sock'):
                    return
                need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Private archive links/special files refused')
                require_traversal(info.st_uid, info.st_gid, ancestors)
                with owner_identity(info.st_uid, info.st_gid):
                    need(identity(path.lstat()) == identity(info), 'Private archive source changed')
                    item = tarfile.TarInfo(name)
                    item.uid, item.gid, item.mode, item.mtime = info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), int(info.st_mtime)
                    if stat.S_ISDIR(info.st_mode):
                        item.type = tarfile.DIRTYPE
                        stream.addfile(item)
                        directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        try:
                            need(identity(os.fstat(directory_fd)) == identity(info), 'Private archive directory changed')
                            entries = []
                            with os.scandir(directory_fd) as iterator:
                                for entry in iterator:
                                    need(len(entries) + members < max_members, 'Private archive directory exceeds member bound')
                                    entries.append((entry.name, entry.stat(follow_symlinks=False)))
                            need(identity(os.fstat(directory_fd)) == identity(info), 'Private archive directory changed during listing')
                        finally:
                            os.close(directory_fd)
                    else:
                        need(info.st_nlink == 1 and 0 <= info.st_size <= maximum, 'Private archive hardlink/size refused')
                        item.size = info.st_size
                        file_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                        with os.fdopen(file_fd, 'rb') as handle:
                            need(identity(os.fstat(handle.fileno())) == identity(info), 'Private archive file changed')
                            stream.addfile(item, ArchiveInput(handle, deadline))
                            need(identity(os.fstat(handle.fileno())) == identity(info), 'Private archive file changed during read')
                # Every switch has restored root before selecting another branch.
                if stat.S_ISDIR(info.st_mode):
                    for child, child_info in sorted(entries):
                        walk(path / child, relative / child, child_info, [*ancestors, info])
            walk(root, Path(), root_info, [])
        os.fsync(fd)
        need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o600, 'Private archive destination mode changed')
    finally:
        os.close(fd)
    return {'schema': 'PQBTC-BOUNDED-BINARY-STREAM-1', 'result': 'PASS', 'path': str(archive),
            'bytes': output.count, 'sha256': output.checksum.hexdigest(), 'members': members}


def main():
    need(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Contained Linux root required')
    root = Path('/var/lib/pqbtc')
    if len(sys.argv) != 1:
        need(len(sys.argv) == 3 and sys.argv[1] == '--archive', 'Private archive helper arguments refused')
        archive = Path(sys.argv[2])
        need(archive.name == 'state.tar' and archive.parent.parent == Path('/tmp') and
             archive.parent.name.startswith('pqbtc-private-export-'), 'Private archive helper destination refused')
        print(json.dumps(build_archive(root, archive), sort_keys=True))
        return
    lock = Path('/opt/pqbtc-runtime/.native-backend.lock')
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, 'Native runtime lock refused')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = quiescent_inventory(root)
        with tempfile.TemporaryDirectory(prefix='pqbtc-private-export-', dir='/tmp') as directory:
            archive = Path(directory) / 'state.tar'
            command = [sys.executable, '-B', str(HERE / 'export_state.py'), '--archive', str(archive)]
            result = capture_module.capture(command, output_limit=65536, fail_on_stderr=True, prefix_limit=0, timeout=145)
            receipt = json.loads(result.stdout)
            info = archive.lstat()
            with archive.open('rb') as handle:
                checksum = hashlib.file_digest(handle, 'sha256').hexdigest()
            need(result.returncode == 0 and receipt.get('schema') == 'PQBTC-BOUNDED-BINARY-STREAM-1' and
                 receipt.get('result') == 'PASS' and receipt.get('path') == str(archive) and
                 stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and
                 receipt.get('bytes') == info.st_size <= MAX_ARCHIVE_BYTES and receipt.get('sha256') == checksum,
                 'Private native state archive failed')
            need(quiescent_inventory(root) == before, 'Native registry changed during export')
            with archive.open('rb') as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()
            need(quiescent_inventory(root) == before, 'Native registry changed during state transfer')
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        raise SystemExit('Private state export refused; custody must be stopped') from None
