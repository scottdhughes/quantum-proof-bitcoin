#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Root-owned native process sessions; operator data is carried only by FDs."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

SCHEMA = "PQBTC-RUNPOD-NATIVE-PROCESSES-2"
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": "/nonexistent"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path, *, maximum=4 * 1024 * 1024, owner=None, private=True):
    owner = os.geteuid() if owner is None else owner
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1 and
                info.st_size <= maximum and stat.S_IMODE(info.st_mode) & 0o022 == 0 and
                (not private or stat.S_IMODE(info.st_mode) == 0o600), "Unsafe native metadata file")
        raw = os.read(fd, maximum + 1)
        require(len(raw) <= maximum, "Native metadata exceeds bound")
        def pairs(items):
            value = {}
            for key, item in items:
                require(key not in value, "Duplicate native metadata member")
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=pairs)
    finally:
        os.close(fd)


def write_json(path, value):
    path = Path(path)
    if path.exists() or path.is_symlink():
        read_json(path)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(len(raw) <= 4 * 1024 * 1024, "Native metadata exceeds bound")
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inspect_as_uid(pid, uid, *, executable_hash=False):
    require(os.geteuid() == 0 and uid in (1000, 1001), "Native metadata delegation refused")
    command = [sys.executable, str(Path(__file__).resolve()), "--uid", str(uid), "--inspect-pid", str(pid)]
    if executable_hash:
        command.append("--inspect-hash")
    value = subprocess.run(command, capture_output=True, timeout=10, env=SAFE_ENV)
    require(value.returncode == 0 and len(value.stdout) <= 4096, "Same-UID native metadata read failed")
    return json.loads(value.stdout)


def signer_metadata_identity(value, record, *, proc=Path("/proc")):
    """Bind a non-dumpable signer to its root-recorded immutable FD launch.

    This is deliberately not a post-exec /proc/exe observation. Unknown or
    unbound processes never receive this permission-denial fallback.
    """
    validate_record(record)
    require(record["role"] == "signer" and value["pid"] == record["pid"] and value["start"] == record["start"] and
            value["uid"] == record["uid"] == 1000 and value["session"] == record["session"] and
            value["pgid"] == record["pgid"] and not value["zombie"] and value["no_new_privileges"] == 1 and
            all(item is not None and int(item, 16) == 0 for item in value["capabilities"].values()),
            "Non-dumpable signer ownership proof mismatch")
    require(proc == Path("/proc") and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "Non-dumpable signer requires live Linux pidfd proof")
    fd = os.pidfd_open(value["pid"])
    try:
        fields = (proc / str(value["pid"]) / "stat").read_text().rsplit(")", 1)[1].split()
        require(fields[0] != "Z" and fields[19] == value["start"] and int(fields[2]) == value["pgid"] and
                int(fields[3]) == value["session"], "Signer changed during pidfd binding")
        signal.pidfd_send_signal(fd, 0)
    finally:
        os.close(fd)
    return dict(value, proof_kind="PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD",
                pre_exec_sha256=record["pre_exec"]["sha256"], pidfd_live=True,
                post_exec_executable_observable=False)


def proc_identity(pid, *, proc=Path("/proc"), executable_hash=False, signer_record=None):
    require(type(pid) is int and pid > 1, "Unsafe native PID")
    root = proc / str(pid)
    try:
        raw = (root / "stat").read_text()
        fields = raw.rsplit(")", 1)[1].split()
        status = {}
        for line in (root / "status").read_text().splitlines():
            name, _, value = line.partition(":")
            status[name] = value.strip()
        uids = [int(item) for item in status["Uid"].split()]
        require(len(uids) == 4 and len(set(uids)) == 1, "Native process UID transition is not stable")
        uid = uids[0]
        value = {"pid": pid, "start": fields[19], "pgid": int(fields[2]), "session": int(fields[3]),
                 "uid": uid, "zombie": fields[0] == "Z", "no_new_privileges": int(status.get("NoNewPrivs", "0")),
                 "capabilities": {name: status.get(name) for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")}}
        if not value["zombie"]:
            try:
                value["executable"] = str((root / "exe").resolve(strict=True))
                if executable_hash:
                    with (root / "exe").open("rb") as handle:
                        value["executable_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
            except PermissionError:
                if signer_record is not None:
                    return signer_metadata_identity(value, signer_record, proc=proc)
                require(proc == Path("/proc") and os.geteuid() == 0 and uid in (1000, 1001),
                        "Native executable metadata is unavailable")
                delegated = inspect_as_uid(pid, uid, executable_hash=executable_hash)
                require(delegated is not None and all(delegated[key] == value[key] for key in value),
                        "Native process changed during metadata delegation")
                return delegated
        require((root / "stat").read_text().rsplit(")", 1)[1].split()[19] == value["start"],
                "Native PID changed during observation")
        return value
    except (FileNotFoundError, ProcessLookupError):
        return None


def session_members(session, *, proc=Path("/proc"), signer_record=None):
    result = []
    for item in proc.iterdir():
        if item.name.isdigit() and int(item.name) > 1:
            # Identify the session before requesting executable/capability
            # metadata. Unrelated provider services may intentionally deny
            # those deeper reads even to the pod's root process.
            try:
                fields = (item / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[3]) != session:
                    continue
                start = fields[19]
            except (FileNotFoundError, ProcessLookupError):
                continue
            bound = signer_record if signer_record is not None and int(item.name) == signer_record["pid"] else None
            value = proc_identity(int(item.name), proc=proc, signer_record=bound)
            if value and value["session"] == session and value["start"] == start and not value["zombie"]:
                result.append(value)
    return sorted(result, key=lambda value: value["pid"])


def validate_record(value):
    require(type(value) is dict and set(value) == {"role", "pid", "start", "uid", "session", "pgid", "executables", "wrapper", "pre_exec"},
            "Native process ownership record shape refused")
    require(value["role"] in ("worker", "signer", "bridge") and
            value["uid"] == (1000 if value["role"] == "signer" else 1001) and
            type(value["pid"]) is int and value["pid"] > 1 and value["session"] == value["pgid"] == value["pid"] and
            type(value["start"]) is str and value["start"].isdigit(), "Native process ownership record refused")
    require(type(value["executables"]) is list and 1 <= len(value["executables"]) <= 3 and
            all(type(item) is str and item.startswith("/") for item in value["executables"]) and
            type(value["wrapper"]) is str and value["wrapper"].startswith("/"), "Native executable ownership refused")
    proof = value["pre_exec"]
    if value["role"] == "signer":
        require(type(proof) is dict and set(proof) == {"sha256", "path", "device", "inode", "size"} and
                type(proof["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]) and
                proof["path"] in value["executables"] and
                type(proof["device"]) is int and proof["device"] >= 0 and
                type(proof["inode"]) is int and proof["inode"] > 0 and
                type(proof["size"]) is int and 0 < proof["size"] <= 128 * 1024 * 1024,
                "Immutable signer FD launch proof refused")
    else:
        require(proof is None, "Unexpected immutable signer proof on another role")
    return value


def verified_members(record, *, proc=Path("/proc")):
    record = validate_record(record)
    signer_record = record if record["role"] == "signer" else None
    leader = proc_identity(record["pid"], proc=proc, signer_record=signer_record)
    if leader is not None:
        require(leader["start"] == record["start"] and leader["session"] == record["session"] and
                leader["pgid"] == record["pgid"], "Native process/session identity changed; preserved")
    members = session_members(record["session"], proc=proc, signer_record=signer_record)
    python = str(Path(sys.executable).resolve())
    for member in members:
        regular = (member["uid"] == record["uid"] and member.get("executable") in record["executables"] and
                   member["no_new_privileges"] == 1 and
                   all(value is not None and int(value, 16) == 0 for value in member["capabilities"].values()))
        hardened_signer = (record["role"] == "signer" and member["pid"] == record["pid"] and
                           member.get("proof_kind") == "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD" and
                           member.get("pre_exec_sha256") == record["pre_exec"]["sha256"] and member.get("pidfd_live") is True)
        launching = False
        if member["pid"] == record["pid"] and member.get("executable") == python and member["uid"] in (0, record["uid"]):
            argv = (proc / str(member["pid"]) / "cmdline").read_bytes().split(b"\0")
            launching = record["wrapper"].encode() in argv
        require(member["pgid"] == record["pgid"] and (regular or launching or hardened_signer),
                "Native session contains an unverified process; preserved")
    return members


def execution_context():
    require(sys.platform.startswith("linux"), "Native process context requires Linux")
    value = {"pid_namespace": os.readlink("/proc/self/ns/pid"),
             "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    return validate_context(value)


def validate_context(value):
    require(type(value) is dict and set(value) == {"pid_namespace", "boot_id"} and
            type(value["pid_namespace"]) is str and re.fullmatch(r"pid:\[[0-9]+\]", value["pid_namespace"]) and
            type(value["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]),
            "Native execution context refused")
    return value


def registry(path, namespace):
    require(type(namespace) is str and re.fullmatch(r"pqbtc-runpod-[a-zA-Z0-9_.-]{1,64}", namespace), "Unsafe native namespace")
    if Path(path).exists() or Path(path).is_symlink():
        value = read_json(path)
        require(type(value) is dict and set(value) == {"schema", "namespace", "context", "previous_empty_contexts", "groups"} and
                value["schema"] == SCHEMA and value["namespace"] == namespace and type(value["groups"]) is list and
                len(value["groups"]) <= 32, "Native registry ownership mismatch")
        validate_context(value["context"])
        require(type(value["previous_empty_contexts"]) is list and len(value["previous_empty_contexts"]) <= 16,
                "Native execution-context history refused")
        for context in value["previous_empty_contexts"]:
            validate_context(context)
        current = execution_context()
        if current != value["context"]:
            # Never inspect or signal a PID from another kernel/PID namespace.
            # A cleanly closed registry is independently recorded empty before
            # a declared provider restart and can safely begin a new context.
            require(not value["groups"], "Native execution context changed with retained processes; preserved")
            require(len(value["previous_empty_contexts"]) < 16, "Native execution-context history exhausted")
            value["previous_empty_contexts"].append(value["context"])
            value["context"] = current
        for group in value["groups"]:
            validate_record(group)
        return value
    return {"schema": SCHEMA, "namespace": namespace, "context": execution_context(),
            "previous_empty_contexts": [], "groups": []}


def with_registry(path, namespace, operation):
    path = Path(path)
    fd = os.open(path.with_suffix(path.suffix + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, "Unsafe native registry lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        value = registry(path, namespace)
        result = operation(value)
        write_json(path, value)
        return result
    finally:
        os.close(fd)


def signal_members(record, signum, *, deadline=10):
    require(sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "Linux pidfd signalling is required")
    require(signum in (signal.SIGTERM, signal.SIGKILL), "Unsupported native signal")
    limit = time.monotonic() + deadline
    count = 0
    while True:
        members = verified_members(record)
        if not members:
            return count
        handles = []
        try:
            for member in members:
                try:
                    fd = os.pidfd_open(member["pid"])
                except ProcessLookupError:
                    continue
                current = proc_identity(member["pid"], signer_record=record if record["role"] == "signer" else None)
                if current is None:
                    os.close(fd)
                    continue
                require(current == member, "Native process changed during pidfd binding; preserved")
                handles.append(fd)
            for fd in handles:
                try:
                    signal.pidfd_send_signal(fd, signum)
                    count += 1
                except ProcessLookupError:
                    pass
        finally:
            for fd in handles:
                os.close(fd)
        require(time.monotonic() < limit, "Native process cleanup deadline exceeded")
        time.sleep(0.02)


def immutable_exec_fd(path, expected_sha256, *, owner=0):
    """Open and hash the exact ELF FD later supplied to execveat/fexecve."""
    require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256),
            "Immutable signer executable digest refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and not before.st_mode & 0o022 and
                before.st_mode & 0o111 and 0 < before.st_size <= 128 * 1024 * 1024,
                "Immutable signer executable file refused")
        require(os.read(fd, 4) == b"\x7fELF", "Signer executable must be ELF")
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), "rb") as handle:
            require(hashlib.file_digest(handle, "sha256").hexdigest() == expected_sha256,
                    "Immutable signer executable digest mismatch")
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "Signer executable changed during FD verification")
        os.lseek(fd, 0, os.SEEK_SET)
        retained = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 5)
        proof = {"sha256": expected_sha256, "path": os.readlink("/proc/self/fd/" + str(fd)) if sys.platform.startswith("linux") else str(Path(path).resolve()),
                 "device": before.st_dev, "inode": before.st_ino, "size": before.st_size}
        return retained, proof
    finally:
        os.close(fd)


def launch(args):
    require(sys.platform.startswith("linux") and os.geteuid() == 0, "Native launcher requires contained Linux root")
    require(args.uid in (1000, 1001) and (args.inspect_pid is not None or
            args.command and not args.command[0].startswith("-")), "Native command refused")
    parent = os.getppid()
    os.setsid()
    exec_fd, pre_exec = None, None
    if args.signer_fd_exec:
        require(args.role == "signer" and args.uid == 1000 and args.expected_sha256 and
                os.execve in os.supports_fd and args.command and Path(args.command[0]).is_absolute(),
                "Immutable signer FD execution is unavailable")
        require("--operator-fd" in args.command and args.command[args.command.index("--operator-fd") + 1] == "3" and
                "--operator-out-fd" in args.command and args.command[args.command.index("--operator-out-fd") + 1] == "4",
                "Immutable signer operator FD contract changed")
        exec_fd, pre_exec = immutable_exec_fd(args.command[0], args.expected_sha256)
    require((args.role == "signer") == bool(args.signer_fd_exec), "Signer must use immutable FD execution")
    if args.role:
        require(args.registry and args.namespace and args.allowed_executable, "Native ownership registry required")
        current = proc_identity(os.getpid())
        entry = {"role": args.role, "pid": current["pid"], "start": current["start"], "uid": args.uid,
                 "session": current["session"], "pgid": current["pgid"],
                 "executables": sorted(set(str(Path(item).resolve(strict=True)) for item in args.allowed_executable)),
                 "wrapper": str(Path(__file__).resolve()), "pre_exec": pre_exec}
        validate_record(entry)
        def insert(value):
            value["groups"] = [record for record in value["groups"] if verified_members(record)]
            require(len(value["groups"]) < 32, "Native session registry is full")
            value["groups"].append(entry)
        with_registry(args.registry, args.namespace, insert)
    os.setgroups([])
    os.setgid(1000)
    os.setuid(args.uid)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(38, 1, 0, 0, 0) == 0, "Native no-new-privileges setup failed")
    require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent, "Native parent lifetime changed")
    os.umask(0o077)
    if args.inspect_pid is not None:
        value = proc_identity(args.inspect_pid, executable_hash=args.inspect_hash)
        require(value is None or value["uid"] == args.uid, "Native delegated metadata UID mismatch")
        print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)
        return
    if exec_fd is not None:
        current = proc_identity(os.getpid())
        print(json.dumps({"pid": current["pid"], "start": current["start"],
                          "pre_exec_sha256": pre_exec["sha256"],
                          "proof_kind": "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD"}, separators=(",", ":")), flush=True)
        os.dup2(0, 3)
        os.dup2(1, 4)
        os.execve(exec_fd, args.command, SAFE_ENV)
    os.execvpe(args.command[0], args.command, SAFE_ENV)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--role", choices=("worker", "signer", "bridge"))
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--namespace")
    parser.add_argument("--inspect-pid", type=int)
    parser.add_argument("--inspect-hash", action="store_true")
    parser.add_argument("--signer-fd-exec", action="store_true")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--allowed-executable", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        launch(args)
    except (OSError, ValueError):
        # Child stderr is deliberately fixed: argv may contain public metadata,
        # and stdin may already carry an operator frame.
        print("Native process launch refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
