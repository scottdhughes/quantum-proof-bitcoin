#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded stdio control for the declared Docker/native Runpod public test.

The native identity describes application payloads and processes. It does not
claim that a Docker daemon or an outer provider-image replacement occurred.
Disposable operator input travels only through this process's stdin.
"""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-console"))
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-qualification"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = load("runpod_agent_public_base", ROOT / "contrib/ml-dsa-qualification/public_soak_agent.py")
require = base.require
PROFILE = base.PROFILE
SCOPE = base.SCOPE


def owned_directory(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "Unsafe native control state directory")
    return path


def read_json(path, maximum=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
                "Unsafe bounded public JSON")
        raw = os.read(fd, maximum + 1)
        require(len(raw) <= maximum, "Public JSON bound")
        return json.loads(raw, object_pairs_hook=base.strict_pairs)
    finally:
        os.close(fd)


def native_process(binary_name, uid, *, optional=False):
    """Inspect only the test node/signer UID and public executable metadata."""
    import native_exec
    rows = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            values = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines())
            if int(values["Uid"].split()[0]) != uid:
                continue
            identity = native_exec.proc_identity(int(path.name))
            if identity is None or identity["zombie"] or Path(identity["executable"]).name != binary_name:
                continue
            identity = native_exec.proc_identity(int(path.name), executable_hash=True)
            if identity is None or identity["zombie"]:
                continue
            ticks = (path / "stat").read_text().rsplit(")", 1)[1].split()
            require(identity["uid"] == uid and identity["start"] == ticks[19], "Native sample process changed during observation")
            rows.append({"pid": int(path.name), "uid": uid, "start_ticks": ticks[19],
                         "executable": identity["executable"], "sha256": identity["executable_sha256"],
                         "rss_bytes": int(values["VmRSS"].split()[0]) * 1024,
                         "peak_rss_bytes": int(values["VmHWM"].split()[0]) * 1024,
                         "user_ticks": int(ticks[11]), "system_ticks": int(ticks[12])})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    require(len(rows) == 1 or optional and not rows, "Owned native process count mismatch")
    return rows[0] if rows else None


def cpuset_count(raw):
    cpus = set()
    for part in raw.split(","):
        match = re.fullmatch(r"([0-9]{1,4})(?:-([0-9]{1,4}))?", part)
        require(match is not None, "Kernel effective CPU-set syntax refused")
        first, last = int(match[1]), int(match[2] or match[1])
        require(0 <= first <= last < 4096, "Kernel effective CPU-set bound refused")
        cpus.update(range(first, last + 1))
    require(cpus, "Kernel effective CPU set is empty")
    return len(cpus)


def cgroup_snapshot():
    """Kernel provider-container counters; these are not whole-host metrics."""
    root = Path("/sys/fs/cgroup")
    require((root / "cgroup.controllers").is_file(), "Runpod qualification requires cgroup v2 counters")
    def value(name):
        return (root / name).read_text().strip()
    quota, period = value("cpu.max").split()
    require(int(period) > 0 and (quota == "max" or int(quota) > 0), "Provider CPU allocation syntax unavailable")
    effective = root / "cpuset.cpus.effective"
    cpus = cpuset_count(effective.read_text().strip()) if effective.is_file() else None
    require(quota != "max" or cpus is not None, "Provider CPU hard allocation unavailable")
    cores = min(int(quota) / int(period) if quota != "max" else float("inf"), cpus or float("inf"))
    memory = value("memory.max")
    require(memory != "max" and int(memory) > 0, "Provider memory hard allocation unavailable")
    stats = dict(line.split() for line in value("cpu.stat").splitlines())
    pids = value("pids.max")
    return {"cpu_quota": None if quota == "max" else int(quota), "cpu_period": int(period), "cpu_cores": cores,
            "cpuset_cpu_count": cpus,
            "memory_max_bytes": int(memory), "memory_current_bytes": int(value("memory.current")),
            "pids_max": None if pids == "max" else int(pids), "pids_current": int(value("pids.current")),
            "cpu_usage_usec": int(stats["usage_usec"]), "cpu_nr_throttled": int(stats.get("nr_throttled", 0)),
            "scope": "PROVIDER_CONTAINER_CGROUP_V2"}


def quarantine_records(controller):
    """Actually remove both selected records while preserving the floor journal."""
    controller.action("lock", {})
    require(controller.journal["checkpoint"] is not None, "Missing-record test needs independent floors")
    point = dict(controller.journal["checkpoint"])
    controller._stop_worker()
    import public_controller
    data = str(getattr(controller.manager, "data_root", public_controller.DATA))
    token = uuid.uuid4().hex
    script = ('import os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);name=sys.argv[2];'
              'fd=os.open(p/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
              'assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600 '
              'and s.st_nlink==1 and s.st_size<=16777216;'
              'current=os.stat(p/name,follow_symlinks=False);assert (s.st_ino,s.st_dev)==(current.st_ino,current.st_dev);'
              'destination=p/("quarantined-"+sys.argv[3]+"-"+name);assert not destination.exists();'
              'os.rename(p/name,destination);os.close(fd);'
              'fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);assert not (p/name).exists()')
    controller._invoke("1000:1000", "/usr/bin/python3", "-c", script,
                       data + "/signer/current", "wallet.dat", token)
    controller._invoke("1001:1000", "/usr/bin/python3", "-c", script,
                       data + "/node/public", "public-wallet.json", token)
    require(controller.journal["checkpoint"] == point, "Missing-record test changed public floors")
    return {"selected_record_missing": True, "public_record_missing": True,
            "independent_journal_preserved": True, **point}


class DockerAgent(base.Agent):
    def act(self, action, params):
        if action == "quarantine_record":
            require(not params, "Missing-record action takes no parameters")
            return quarantine_records(self.controller)
        return super().act(action, params)


class NativeAgent(base.Agent):
    def __init__(self, controller, state_dir, deadline, pod_id):
        super().__init__(controller, state_dir, deadline)
        self.pod_id, self.bridge_info, self.bridge_reader = pod_id, None, None
        self.bridge_error = None

    def bridge_stop(self):
        if self.bridge is not None:
            if self.bridge.poll() is None:
                self.controller._signal(self.bridge_info)
                self.bridge.wait(timeout=15)
            if self.bridge_reader:
                self.bridge_reader.join(15)
                require(not self.bridge_reader.is_alive(), "Native bridge output did not close")
            require(self.bridge_error is None, "Native bridge public-output bound failed")
            for pipe in (self.bridge.stdin, self.bridge.stdout, self.bridge.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            self.bridge_log.close()
            self.bridge = self.bridge_info = self.bridge_reader = self.bridge_log = None
        return {"stopped": True}

    def bridge_start(self, params):
        from public_transport import PublicEndpoint
        require(set(params) == {"hostname", "public_ips", "port", "until_utc"}, "Bridge parameter members")
        endpoint = PublicEndpoint(params["hostname"], params["port"], tuple(params["public_ips"]))
        end = datetime.fromisoformat(params["until_utc"])
        require(end.tzinfo is not None and end.utcoffset().total_seconds() == 0 and
                time.time() < end.timestamp() <= self.deadline, "Bounded bridge deadline required")
        self.bridge_stop()
        import public_controller
        source = str(getattr(self.controller, "_public_module", public_controller).SOURCE)
        path = self.state_dir / ("native-public-transport-" + str(time.monotonic_ns()) + ".jsonl")
        self.bridge_log = path.open("xb")
        instance = uuid.uuid4().hex
        args = [source + "/contrib/ml-dsa-qualification/public_transport.py", "bridge", "--hostname", endpoint.hostname,
                "--port", str(endpoint.port), "--until-utc", end.isoformat(), "--instance-id", instance]
        for address in endpoint.addresses:
            args += ["--public-ip", address]
        self.bridge, self.bridge_info = self.controller._spawn("1001:1000", "/usr/bin/python3", *args, stderr=self.bridge_log)
        self.bridge_error = None
        process, output = self.bridge, self.bridge_log
        def drain():
            total = 0
            try:
                while part := process.stdout.read(65536):
                    total += len(part)
                    require(total <= 8 * 1024 * 1024, "Native bridge output bound")
                    output.write(part)
                    output.flush()
            except BaseException as error:
                self.bridge_error = type(error).__name__
        self.bridge_reader = threading.Thread(target=drain, daemon=True)
        self.bridge_reader.start()
        return {"bridge_process_started": True, "log": path.name, "loopback_endpoint": "127.0.0.1:23834",
                "backend": "native", "process": self.bridge_info}

    def sample(self):
        row = native_process("pqbtcd", 1001)
        row.update(self.controller._request("sample"))
        before, started = cgroup_snapshot(), time.monotonic()
        time.sleep(0.2)
        after = cgroup_snapshot()
        row["provider_container"] = after
        row["pod_cpu_percent"] = ((after["cpu_usage_usec"] - before["cpu_usage_usec"]) /
                                  ((time.monotonic() - started) * 1_000_000 * after["cpu_cores"]) * 100)
        row["bridge_alive"] = self.bridge is not None and self.bridge.poll() is None and self.bridge_error is None
        return row

    def act(self, action, params):
        require(time.time() < self.deadline and time.monotonic() < self.monotonic_deadline,
                "Native agent shutdown deadline passed")
        if action == "identity":
            require(not params, "Identity takes no parameters")
            value = self.controller.manager.identity()
            running = self.controller._signer is not None and self.controller._signer.poll() is None
            signer = value.get("signer_execution_proof")
            require(not running or type(signer) is dict and signer.get("pid") == self.controller._signer.pid and
                    signer.get("start") == self.controller._signer_info["start"], "Live signer execution proof is missing")
            value.update(pod_id=self.pod_id, architecture=platform.machine(),
                         running_node=native_process("pqbtcd", 1001),
                         signer_running=running, running_signer=signer if running else None)
            return base.public_result(value)
        if action == "quarantine_record":
            require(not params, "Missing-record action takes no parameters")
            return quarantine_records(self.controller)
        if action in ("crash", "upgrade", "rollback"):
            self.bridge_stop()
            if action in ("upgrade", "rollback"):
                require(set(params) == {"payload_version"} and params["payload_version"] in ("a3", "c"),
                        "Native replacement needs a preinstalled payload version")
                descriptor = read_json(self.controller.manager.versions_root / params["payload_version"] / "descriptor.json",
                                       maximum=16 * 1024 * 1024)
                params = {"descriptor": descriptor}
            return base.public_result(self.controller.action(action, params))
        return super().act(action, params)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("docker", "native"), required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--p2p-port", type=int, default=23833)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--sudo-docker", action="store_true")
    parser.add_argument("--versions-root", type=Path, default=Path("/opt/pqbtc-runpod/versions"))
    parser.add_argument("--runtime-root", type=Path, default=Path("/opt/pqbtc-runtime"))
    parser.add_argument("--data-root", type=Path, default=Path("/var/lib/pqbtc"))
    parser.add_argument("--pod-id")
    parser.add_argument("--until-utc", required=True)
    args = parser.parse_args(argv)
    end = datetime.fromisoformat(args.until_utc)
    require(end.tzinfo is not None and end.utcoffset().total_seconds() == 0 and
            0 < end.timestamp() - time.time() <= 27 * 3600, "UTC deadline within 27 hours required")
    if args.backend == "native":
        require(sys.platform.startswith("linux") and os.geteuid() == 0 and not args.sudo_docker and not args.bootstrap,
                "Native follower requires the isolated Linux root supervisor")
        require(type(args.pod_id) is str and re.fullmatch(r"[a-zA-Z0-9_-]{4,80}", args.pod_id), "Owned pod identity required")
        require(os.environ.get("RUNPOD_POD_ID") == args.pod_id, "Actual provider pod identity differs")
        from native_backend import NativeController
        controller = NativeController(args.state_dir, read_json(args.descriptor, maximum=16 * 1024 * 1024), versions_root=args.versions_root,
                                      runtime_root=args.runtime_root, data_root=args.data_root, namespace=args.namespace)
        agent = NativeAgent(controller, args.state_dir, end.timestamp(), args.pod_id)
        cleanup = controller.manager.emergency_stop
    else:
        require(args.pod_id is None, "Docker backend cannot claim a provider pod")
        from public_controller import PublicController
        from source_runtime import load_descriptor
        controller = PublicController(args.state_dir, load_descriptor(args.descriptor), container=args.namespace,
                                      p2p_port=args.p2p_port, bootstrap=args.bootstrap,
                                      docker=("sudo", "-n", "docker") if args.sudo_docker else ("docker",))
        agent = DockerAgent(controller, args.state_dir, end.timestamp())
        def cleanup():
            return base.stop_owned_public(controller.manager)
    guard = base.DeadlineGuard(agent.deadline, agent.monotonic_deadline, cleanup)
    guard.start()
    expected_id, prior_hash, prior_response = 0, None, None
    control_input = base.ControlInput(sys.stdin.fileno())
    def emit(value):
        return base.write_control_response(sys.stdout.fileno(), (value + "\n").encode(), agent.deadline, agent.monotonic_deadline)
    try:
        require(emit(json.dumps({"event": "agent_ready", "scope": SCOPE, "until_utc": end.isoformat(),
                                "backend": args.backend})), "Agent readiness output deadline")
        while True:
            raw = control_input.line(agent.deadline, agent.monotonic_deadline)
            if raw is None:
                break
            value = base.request(raw)
            fingerprint = hashlib.sha256(raw).hexdigest()
            if value["id"] == expected_id - 1 and fingerprint == prior_hash:
                if not emit(prior_response):
                    break
                continue
            require(value["id"] == expected_id, "Nonsequential or substituted agent request")
            try:
                response = {"id": expected_id, "ok": True, "data": agent.act(value["action"], value["params"])}
            except Exception as error:
                response = {"id": expected_id, "ok": False, "error_class": type(error).__name__}
            prior_response = json.dumps(response, separators=(",", ":"), allow_nan=False)
            prior_hash, expected_id = fingerprint, expected_id + 1
            if not emit(prior_response):
                break
            del value, raw
    finally:
        try:
            agent.close()
        finally:
            try:
                controller.close()
            finally:
                guard.cancel()


if __name__ == "__main__":
    main()
