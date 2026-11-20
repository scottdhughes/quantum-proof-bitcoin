#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded POSIX test processes and narrowly scoped sanitizer link layout.

No native code executes on import. Callers own environment and admission rules;
negative controls can inspect a bounded nonzero result instead of suppressing it.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import time

OUTPUT_LIMIT = 2 * 1024 * 1024
PREFIX_LIMIT = 64 * 1024


class CaptureError(RuntimeError):
    def __init__(self, details):
        self.details = details
        super().__init__("native command refused: " + json.dumps(details, sort_keys=True))


def sanitizer_executable_link_flags(compiler, sanitized, *, system=None, architecture=None):
    system = platform.system() if system is None else system
    architecture = platform.machine() if architecture is None else architecture
    if sanitized and Path(compiler).name in ("gcc", "g++") and system == "Linux" and architecture in ("x86_64", "amd64"):
        return ["-no-pie"]
    return []


def elf_type(header):
    kinds = re.findall(r"^\s*Type:\s+([A-Z]+)\b", header, re.MULTILINE)
    if len(kinds) != 1:
        raise ValueError("one actual ELF header type is required")
    return kinds[0]


def executable_layout(header, link_flags):
    kind = elf_type(header)
    if kind not in ("EXEC", "DYN"):
        raise ValueError("an ELF executable type is required")
    if link_flags and kind != "EXEC":
        raise ValueError("requested non-PIE sanitizer executable is not ELF EXEC")
    return {"link_flags": list(link_flags), "elf_type": kind}


def capture(command, *, cwd=None, env=None, timeout=120, output_limit=OUTPUT_LIMIT,
            prefix_limit=PREFIX_LIMIT, fail_on_stderr=False):
    if timeout <= 0 or output_limit <= 0 or prefix_limit < 0:
        raise ValueError("invalid process bounds")
    prefix_limit = min(prefix_limit, output_limit)
    if not all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG")):
        raise RuntimeError("unreaped-child ownership requires POSIX waitid/WNOWAIT")
    argv = list(map(str, command))
    buffers = {name: bytearray() for name in ("stdout", "stderr")}
    counts = {name: 0 for name in buffers}
    hashes = {name: hashlib.sha256() for name in buffers}
    process = None
    owned = True
    failure = None
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            for name in buffers:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() and failure is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    counts[name] += len(block)
                    hashes[name].update(block)
                    buffers[name].extend(block[:output_limit - len(buffers[name])])
                    if counts[name] >= output_limit:
                        failure = name + " output limit"
                    elif name == "stderr" and fail_on_stderr:
                        failure = "unexpected stderr"
                    if failure is not None:
                        break
            while failure is None:
                try:
                    exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    owned = False
                    failure = "command ownership lost"
                    break
                if exited is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                time.sleep(min(remaining, 0.01))
        finally:
            if process is not None:
                try:
                    # The unreaped session leader reserves this PID/group. Stop
                    # same-group heirs even on success before releasing ownership.
                    if owned:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except PermissionError:
                            # Darwin returns EPERM for an unreaped zombie-only
                            # group. A live same-UID heir remains signalable.
                            # Linux qualification retains the strict failure.
                            if platform.system() != "Darwin" or os.waitid(
                                    os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                                raise
                    process.wait(timeout=5)
                finally:
                    for name in buffers:
                        stream = getattr(process, name)
                        if stream is not None and not stream.closed:
                            stream.close()
    details = {"argv": argv, "pid": process.pid, "returncode": process.returncode,
               "failure": failure, "output_limit_per_stream": output_limit, "timeout_seconds": timeout}
    for name, buffer in buffers.items():
        prefix = bytes(buffer[:prefix_limit])
        details[name] = {"observed_bytes": counts[name], "captured_bytes": len(buffer),
                         "observed_sha256": hashes[name].hexdigest(),
                         "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                         "prefix_hex": prefix.hex(), "prefix_utf8": prefix.decode("utf8", "replace")}
    if failure:
        raise CaptureError(details)
    values = {}
    for name, buffer in buffers.items():
        try:
            values[name] = bytes(buffer).decode("utf8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as error:
            details["failure"] = name + " invalid UTF-8"
            raise CaptureError(details) from error
    result = subprocess.CompletedProcess(argv, process.returncode, values["stdout"], values["stderr"])
    result.capture_details = details
    return result


def checked(command, **options):
    result = capture(command, fail_on_stderr=True, **options)
    if result.returncode:
        result.capture_details["failure"] = "unexpected exit status"
        raise CaptureError(result.capture_details)
    return result.stdout
