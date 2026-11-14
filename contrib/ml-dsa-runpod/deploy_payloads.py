#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Install pinned public payloads and restore them after an owned pod restart."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
_capture_spec = importlib.util.spec_from_file_location("runpod_deployment_capture", HERE.parent / "ml-dsa-qualification/native_process.py")
_capture = importlib.util.module_from_spec(_capture_spec)
_capture_spec.loader.exec_module(_capture)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def bounded(command, *, timeout=240, stdin_path=None, limit=2 * 1024 * 1024, fail_on_stderr=False):
    # The frozen capture utility owns the unreaped session and all descendants.
    # Only public code archives use the optional file stdin wrapper. Operator
    # secrets never enter this deployment process or its argv/environment.
    if stdin_path is not None:
        launcher = ('import os,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);'
                    'os.dup2(fd,0);os.close(fd) if fd!=0 else None;os.execvp(sys.argv[2],sys.argv[2:])')
        command = [sys.executable, "-B", "-c", launcher, str(stdin_path), *command]
    try:
        result = _capture.capture(command, timeout=timeout, output_limit=limit,
                                  prefix_limit=0, fail_on_stderr=fail_on_stderr)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        raise ValueError("Bounded deployment operation failed") from None
    need(result.returncode == 0, "Bounded deployment operation failed")
    return result


def read_plan(path):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < 1024 * 1024, "Private deployment plan refused")
    value = json.loads(path.read_text())
    need(value.get("schema") == "PQBTC-RUNPOD-DEPLOYMENT-1" and
         set(value["archives"]) == {"control", "a3", "c"}, "Deployment plan shape differs")
    need(re.fullmatch(r"[0-9a-f]{40}", value["control_head"]) and re.fullmatch(r"[0-9a-f]{40}", value["control_tree"]),
         "Control source identity differs")
    for entry in value["archives"].values():
        archive = Path(entry["path"])
        need(archive.is_absolute() and archive.is_file() and not archive.is_symlink() and
             archive.stat().st_size == entry["size"] and sha(archive) == entry["sha256"], "Local code archive differs")
    need(sha(HERE / "provider_control.py") == value["provider_script_sha256"] and
         sha(HERE / "install_payload.py") == value["installer_sha256"], "Deployment helper changed")
    return value


def provider(plan, operation):
    result = bounded([sys.executable, "-B", str(HERE / "provider_control.py"), operation,
                      "--state", plan["provider_state"]], timeout=240)
    need(result.returncode == 0 and len(result.stdout) < 1024 * 1024, "Scoped provider operation refused")
    value = json.loads(result.stdout)
    need(type(value) is dict and value.get("error") is None, "Scoped provider response refused")
    return value


def ssh_command(transport, arguments):
    argv = transport.get("argv")
    need(transport.get("kind") == "ssh" and transport.get("hostkey_source") == "AUTHENTICATED_PROVIDER_EXEC_PUBLIC_KEY_ONLY" and
         type(argv) is list and all(type(v) is str and "\n" not in v and "\0" not in v for v in argv) and
         argv[0] == "ssh" and "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv and
         "ForwardAgent=no" in argv and any(v.startswith("UserKnownHostsFile=/") for v in argv), "Pinned SSH transport refused")
    return [*argv, shlex.join([str(v) for v in arguments])]


def install(plan, transport):
    # Only public packages are installed; no registry credentials or user files
    # enter the pod. Runpod's base image already supplies the SSH service.
    command = ["sh", "-c", "dpkg-query -W python3 git util-linux libevent-dev ca-certificates >/dev/null 2>&1 || "
               "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
               "python3 git util-linux libevent-dev ca-certificates)"]
    result = bounded(ssh_command(transport, command), timeout=300)
    need(result.returncode == 0, "Pod runtime packages unavailable")
    installer = (HERE / "install_payload.py").read_text()
    receipts = []
    for role in ("a3", "c", "control"):
        entry = plan["archives"][role]
        command = ["python3", "-B", "-c", installer, role, entry["sha256"], str(entry["size"]),
                   plan["control_head"], plan["control_tree"], "/opt/pqbtc-runpod"]
        result = bounded(ssh_command(transport, command), stdin_path=entry["path"], timeout=300)
        need(result.returncode == 0 and len(result.stdout) < 4096, "Pinned pod installation failed")
        receipt = json.loads(result.stdout)
        need(receipt.get("result") == "PASS" and receipt.get("role") == role and
             receipt.get("archive_sha256") == entry["sha256"], "Pod installation receipt differs")
        receipts.append(receipt)
    return receipts


def prepare(repo, provider_state, payload_a3, payload_c, output):
    """Export a clean committed control checkout without unrelated ignored data."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("runpod_source_export", HERE.parent / "ml-dsa-console/source_build.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    output = Path(output)
    need(not output.exists() and not output.is_symlink(), "Choose a fresh deployment directory")
    output.mkdir(mode=0o700, parents=True)
    with tempfile.TemporaryDirectory(prefix="pqbtc-runpod-control-") as temporary:
        temporary = Path(temporary)
        identity = builder.stage_source(repo, temporary / "control")
        archive = output / "control.tar.gz"
        with tarfile.open(archive, "w:gz", compresslevel=3) as tar:
            for path in [temporary / "control", *sorted((temporary / "control").rglob("*"))]:
                info = tar.gettarinfo(str(path), str(path.relative_to(temporary)))
                need(info.isfile() or info.isdir(), "Control source links must be materialized before deployment")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o555 if info.isdir() or info.mode & 0o111 else 0o444
                if info.isfile():
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)
                else:
                    tar.addfile(info)
    archives = {"control": archive, "a3": Path(payload_a3).resolve(), "c": Path(payload_c).resolve()}
    value = {"schema": "PQBTC-RUNPOD-DEPLOYMENT-1", "provider_state": str(Path(provider_state).resolve()),
             "provider_script_sha256": sha(HERE / "provider_control.py"), "installer_sha256": sha(HERE / "install_payload.py"),
             "control_head": identity["source_head"], "control_tree": identity["source_tree"],
             "archives": {role: {"path": str(path), "size": path.stat().st_size, "sha256": sha(path)}
                          for role, path in archives.items()}}
    plan = output / "deployment.json"
    with plan.open("x") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
    plan.chmod(0o600)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "install", "restart", "export"))
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--provider-state", type=Path)
    parser.add_argument("--a3", type=Path)
    parser.add_argument("--c", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "prepare":
        value = prepare(args.repo, args.provider_state, args.a3, args.c, args.output)
        print(json.dumps({"result": "PASS", "plan": str(args.output / "deployment.json"), "control_head": value["control_head"]}))
        return
    plan = read_plan(args.plan)
    if args.operation in ("install", "restart"):
        result = provider(plan, "restart") if args.operation == "restart" else {"transport": provider(plan, "ssh")}
        result["installation"] = install(plan, result["transport"])
        result["control_repo"] = "/opt/pqbtc-runpod/control-" + plan["control_head"][:16]
        result["result"] = "PASS"
    else:
        before = provider(plan, "get")
        transport = provider(plan, "ssh")
        need(transport["pod_id"] == before["id"] and transport["generation"] == before["started_at"],
             "State export provider generation changed")
        need(not args.output.exists() and not args.output.is_symlink(), "Export target already exists")
        control_repo = "/opt/pqbtc-runpod/control-" + plan["control_head"][:16]
        command = ["python3", "-B", control_repo + "/contrib/ml-dsa-runpod/export_state.py"]
        capture_command = [sys.executable, "-B", str(HERE / "bounded_stream.py"), "--output", str(args.output),
                           "--maximum", str(MAX_ARCHIVE_BYTES), "--timeout", "170", "--", *ssh_command(transport, command)]
        status = bounded(capture_command, limit=65536, fail_on_stderr=True, timeout=180)
        stream = json.loads(status.stdout)
        need(stream.get("result") == "PASS" and stream.get("path") == str(args.output) and
             stream.get("bytes") == args.output.stat().st_size and 0 < stream["bytes"] <= MAX_ARCHIVE_BYTES and
             stream.get("sha256") == sha(args.output), "Private state export failed")
        after = provider(plan, "get")
        need(all(after[key] == before[key] for key in ("id", "name", "started_at", "mounts")),
             "State export crossed a provider restart")
        mounts = before["mounts"].get("network", [])
        need(len(mounts) == 1 and mounts[0]["path"] == "/var/lib/pqbtc", "State export mount differs")
        result = {"schema": "PQBTC-RUNPOD-STATE-EXPORT-1", "result": "PASS", "path": str(args.output),
                  "sha256": sha(args.output), "bytes": args.output.stat().st_size, "task_generated_auth_cookies_excluded": True,
                  "quiescent_native_sessions": True,
                  "binding": {"task": before["name"], "pod_id": before["id"],
                              "volume_id": mounts[0]["volumeId"], "generation": before["started_at"]}}
        args.output = args.output.with_suffix(args.output.suffix + ".receipt.json")
    with args.output.open("x") as handle:
        json.dump(result, handle, sort_keys=True, indent=2)
        handle.write("\n")
    args.output.chmod(0o600)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Scoped Runpod deployment refused; inspect task evidence") from None
