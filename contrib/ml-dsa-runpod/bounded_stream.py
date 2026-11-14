#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Binary-to-private-file adapter inside an owned, unreaped capture session.

Invoke this through native_process.capture. Its session ownership and cleanup
remain outside this adapter, including when a command leader leaves descendants.
Only a small UTF-8 JSON receipt reaches that outer capture utility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

MAX_BYTES = 512 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def stream(command, output, *, maximum=MAX_BYTES, timeout=150):
    need(type(maximum) is int and 0 < maximum <= MAX_BYTES and 0 < timeout <= 300,
         'Binary stream bounds refused')
    path = Path(output)
    need(path.is_absolute(), 'Binary destination must be absolute')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process = None
    total, diagnostics, checksum = 0, 0, hashlib.sha256()
    deadline = time.monotonic() + timeout
    try:
        with os.fdopen(fd, 'wb', closefd=False) as destination, selectors.DefaultSelector() as selector:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for stream_name in ('stdout', 'stderr'):
                source = getattr(process, stream_name)
                os.set_blocking(source.fileno(), False)
                selector.register(source, selectors.EVENT_READ, stream_name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'Binary stream deadline')
                for key, _ in selector.select(min(remaining, 0.1)):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    elif key.data == 'stdout':
                        need(total + len(block) <= maximum, 'Binary stream exceeds its byte limit')
                        destination.write(block)
                        checksum.update(block)
                        total += len(block)
                    else:
                        diagnostics += len(block)
                        # Neither SSH nor the archive command is expected to
                        # emit diagnostics for a successful private snapshot.
                        need(diagnostics <= 65536, 'Binary stream diagnostics limit')
            need(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0 and
                 diagnostics == 0 and total > 0, 'Binary stream command failed')
            destination.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for name in ('stdout', 'stderr'):
                source = getattr(process, name)
                if source is not None and not source.closed:
                    source.close()
    return {'schema': 'PQBTC-BOUNDED-BINARY-STREAM-1', 'result': 'PASS', 'path': str(path),
            'bytes': total, 'sha256': checksum.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--maximum', type=int, default=MAX_BYTES)
    parser.add_argument('--timeout', type=float, default=150)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    need(command, 'Binary stream command missing')
    print(json.dumps(stream(command, args.output, maximum=args.maximum, timeout=args.timeout), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Bounded binary stream refused') from None
