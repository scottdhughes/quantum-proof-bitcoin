#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Stream a private state archive only while native custody is quiescent."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('runpod_export_capture', HERE.parent / 'ml-dsa-qualification/native_process.py')
capture_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture_module)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


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


def main():
    need(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Contained Linux root required')
    root = Path('/var/lib/pqbtc')
    lock = Path('/opt/pqbtc-runtime/.native-backend.lock')
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, 'Native runtime lock refused')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = quiescent_inventory(root)
        with tempfile.TemporaryDirectory(prefix='pqbtc-private-export-') as directory:
            archive = Path(directory) / 'state.tar'
            command = [sys.executable, '-B', str(HERE / 'bounded_stream.py'), '--output', str(archive),
                       '--maximum', str(MAX_ARCHIVE_BYTES), '--timeout', '135', '--', *tar_command(root)]
            result = capture_module.capture(command, output_limit=65536, fail_on_stderr=True, prefix_limit=0, timeout=145)
            receipt = json.loads(result.stdout)
            need(result.returncode == 0 and receipt.get('result') == 'PASS' and
                 receipt.get('bytes') == archive.stat().st_size <= MAX_ARCHIVE_BYTES,
                 'Private native state archive failed')
            need(quiescent_inventory(root) == before, 'Native registry changed during export')
            with archive.open('rb') as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    sys.stdout.buffer.write(block)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Private state export refused; custody must be stopped') from None
