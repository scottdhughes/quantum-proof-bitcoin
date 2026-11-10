#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Persistent local/SSH control agent for an explicitly owned public-test node.

Control requests use stdin, including disposable test-wallet operator input.
Neither requests nor secrets are logged. Only compact public results go to
stdout. EOF stops this agent's owned node and bridge; it never targets the
existing offline wallet or an unrelated container.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import uuid
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-console"))
MAX_REQUEST = 1024 * 1024
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate agent request field")
        result[key] = value
    return result


def request(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST and raw.endswith(b"\n"), "Bounded complete request required")
    value = json.loads(raw, object_pairs_hook=strict_pairs)
    require(type(value) is dict and set(value) == {"id", "action", "params"}, "Agent request members")
    require(type(value["id"]) is int and value["id"] >= 0 and type(value["action"]) is str and
            re.fullmatch(r"[a-z_]{1,32}", value["action"]) and type(value["params"]) is dict, "Agent request shape")
    return value


class ControlInput:
    """Incremental bounded framing; an unfinished pipe cannot defeat expiry."""
    def __init__(self, fd):
        self.fd, self.pending = fd, bytearray()
        os.set_blocking(fd, False)

    def line(self, wall_deadline, monotonic_deadline):
        while time.time() < wall_deadline and time.monotonic() < monotonic_deadline:
            require(len(self.pending) <= MAX_REQUEST, "Agent request bound exceeded")
            split = self.pending.find(b"\n")
            if split >= 0:
                raw = bytes(self.pending[:split + 1])
                del self.pending[:split + 1]
                return raw
            remaining = max(0, min(1, wall_deadline - time.time(), monotonic_deadline - time.monotonic()))
            if not select.select([self.fd], [], [], remaining)[0]:
                continue
            try:
                part = os.read(self.fd, min(65536, MAX_REQUEST + 1 - len(self.pending)))
            except BlockingIOError:
                continue
            if not part:
                require(not self.pending, "Agent request truncated at EOF")
                return None
            self.pending.extend(part)
        return None


def write_control_response(fd, data, wall_deadline, monotonic_deadline):
    """A silent/unread owner pipe cannot keep the agent past its deadline."""
    require(type(data) is bytes and len(data) <= 20 * 1024 * 1024, "Public response bound exceeded")
    os.set_blocking(fd, False)
    offset = 0
    while offset < len(data):
        remaining = min(1, wall_deadline - time.time(), monotonic_deadline - time.monotonic())
        if remaining <= 0:
            return False
        if not select.select([], [fd], [], remaining)[1]:
            continue
        try:
            count = os.write(fd, data[offset:offset + 65536])
        except BlockingIOError:
            continue
        except BrokenPipeError:
            return False
        require(count > 0, "Public control output closed")
        offset += count
    return True


def stop_owned_public(manager):
    """Deadline path bypasses a blocked controller mutex, not ownership checks."""
    from public_controller import COMPATIBILITY
    require(type(manager.container) is str and
            re.fullmatch(r"pqbtc-mldsa-public[a-zA-Z0-9_.-]{0,64}", manager.container),
            "Deadline public container ownership namespace refused")
    volume = manager.container + "-data-v1"
    require(manager.volume == volume, "Deadline public volume ownership namespace refused")
    directory_fd = record_fd = None
    try:
        try:
            directory_fd = os.open(manager.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return  # An uninitialized state directory conveys no ownership.
        info = os.fstat(directory_fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Deadline runtime ownership directory is unsafe")
        try:
            record_fd = os.open("public-runtime.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                dir_fd=directory_fd)
        except FileNotFoundError:
            return  # Matching labels cannot adopt another attempt's old node.
        info = os.fstat(record_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4 * 1024 * 1024,
                "Deadline runtime ownership record is unsafe")
        with os.fdopen(record_fd, "rb", closefd=False) as handle:
            raw = handle.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, "Deadline runtime ownership record bound")
        retained = json.loads(raw.decode("utf8"), object_pairs_hook=strict_pairs)
    except OSError as error:
        raise ValueError("Deadline runtime ownership record could not be safely read") from error
    finally:
        for fd in (record_fd, directory_fd):
            if fd is not None:
                os.close(fd)
    require(type(retained) is dict and retained.get("schema") == "PQBTC-MLDSA44-PUBLIC-RUNTIME-1" and
            retained.get("compatibility") == COMPATIBILITY and retained.get("container") == manager.container and
            retained.get("volume") == volume, "Deadline retained runtime ownership check failed")
    volume_id = retained.get("volume_id")
    require(type(volume_id) is str and re.fullmatch(r"[0-9a-f]{32}", volume_id) and volume_id != "00" * 16,
            "Deadline retained volume identity is missing")
    result = manager.run(["inspect", "--format", "{{json .}}", manager.container], check=False, timeout=5)
    if result.returncode:
        detail = result.stderr.decode("utf8", "replace")
        require("No such object:" in detail or "No such container:" in detail,
                "Deadline could not determine owned container liveness")
        return
    require(len(result.stdout) <= 1024 * 1024, "Deadline ownership response bound")
    value = json.loads(result.stdout, object_pairs_hook=strict_pairs)
    require(type(value) is dict, "Deadline container ownership object required")
    labels = value.get("Config", {}).get("Labels", {}) or {}
    require(value.get("Name") == "/" + manager.container and
            labels.get("org.pqbtc.console.schema") == "public-test-1" and
            labels.get("org.pqbtc.console.profile") == PROFILE and
            labels.get("org.pqbtc.console.build") == "source-1", "Deadline container ownership check failed")
    mounts = value.get("Mounts")
    require(value.get("HostConfig", {}).get("ReadonlyRootfs") is True and type(mounts) is list and len(mounts) == 1 and
            mounts[0].get("Type") == "volume" and mounts[0].get("Name") == volume and
            mounts[0].get("Destination") == "/var/lib/pqbtc" and mounts[0].get("RW") is True,
            "Deadline owned volume mount check failed")
    identity = value.get("Id")
    require(type(identity) is str and re.fullmatch(r"[0-9a-f]{64}", identity), "Deadline immutable container identity missing")
    running = value.get("State", {}).get("Running")
    require(type(running) is bool, "Deadline owned container liveness missing")
    if running:
        # Bind this public read to the immutable instance too: the name can be
        # reused during an upgrade after the initial inspect has returned.
        script = ('import os,stat,sys;fd=os.open("/var/lib/pqbtc/identity.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);'
                  's=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and '
                  'stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=1024;data=os.read(fd,1025);'
                  'assert len(data)<=1024;os.close(fd);sys.stdout.buffer.write(data)')
        result = manager.run(["exec", "--user", "1001:1000", identity, "python3", "-c", script], check=False, timeout=5)
        if result.returncode:
            detail = result.stderr.decode("utf8", "replace")
            if "No such object:" in detail or "No such container:" in detail:
                return  # This exact instance disappeared; do not stop its replacement.
            raise ValueError("Deadline could not verify the owned public volume marker")
        require(len(result.stdout) <= 1024, "Deadline public volume marker bound")
        marker = json.loads(result.stdout, object_pairs_hook=strict_pairs)
        require(type(marker) is dict and marker == {"volume_id": volume_id, "profile_sha256": PROFILE},
                "Deadline public volume identity ownership check failed")
        # Image equality is deliberately not an ownership condition: a
        # compatible replacement keeps the same owned volume throughout.
        # An intentional stop suppresses the container's unless-stopped policy.
        # This is the terminal watchdog path; ordinary exit stops cleanly first.
        manager.run(["stop", "--time", "1", identity], timeout=15)


class DeadlineGuard:
    """Independent of main request/response I/O and a blocked custody action."""
    def __init__(self, wall_deadline, monotonic_deadline, cleanup):
        self.wall_deadline, self.monotonic_deadline, self.cleanup = wall_deadline, monotonic_deadline, cleanup
        self.event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.expired, self.error_class = False, None

    def start(self):
        self.thread.start()

    def _run(self):
        while not self.event.is_set():
            remaining = min(self.wall_deadline - time.time(), self.monotonic_deadline - time.monotonic())
            if remaining > 0:
                self.event.wait(min(0.2, remaining))
                continue
            self.expired = True
            try:
                self.cleanup()
                self.error_class = None
            except Exception as error:
                self.error_class = type(error).__name__
            # Keep checking while a pre-deadline Docker replacement finishes.
            # The main action cannot restore public service after this guard.
            self.event.wait(0.2)

    def cancel(self):
        self.event.set()
        self.thread.join(30)
        require(not self.thread.is_alive(), "Independent public deadline cleanup is still active")
        require(self.error_class is None, "Independent public deadline ownership or cleanup failed")


def compact_status(value):
    """Avoid duplicating the growing public-key/address inventory every minute."""
    require(type(value) is dict, "Public status object required")
    result = {key: value[key] for key in ("phase", "ready", "scope", "nodes", "startup_error") if key in value}
    wallet = value.get("wallet", {})
    result["wallet"] = {key: wallet[key] for key in
                        ("wallet_id", "locked", "signer_connected", "balance_sats", "spendable_sats",
                         "confirmed_sats", "pending_sats", "next_receive", "next_change") if key in wallet}
    result["wallet"]["addresses_count"] = len(wallet.get("addresses", []))
    result["wallet"]["utxos_count"] = len(wallet.get("utxos", []))
    return result


def public_result(value):
    require(type(value) is dict, "Public action result object required")
    result = dict(value)
    if "status" in result:
        result["status"] = compact_status(result["status"])
    # Recovery ciphertext and operator input are never control-plane receipts.
    def inspect(item):
        if type(item) is dict:
            require(not {"password", "passphrase", "secret", "ciphertext", "operator_input"} & set(item),
                    "Private field refused in public agent response")
            for nested in item.values():
                inspect(nested)
        elif type(item) is list:
            for nested in item:
                inspect(nested)
    inspect(result)
    return result


class Agent:
    def __init__(self, controller, state_dir, deadline):
        self.controller, self.state_dir, self.deadline = controller, Path(state_dir), deadline
        self.monotonic_deadline = time.monotonic() + max(0, deadline - time.time())
        self.bridge = self.bridge_log = None
        self.bridge_pid = self.bridge_id = None
        self.bridge_container = None

    def bridge_stop(self):
        if self.bridge is not None:
            if self.bridge_pid is not None:
                from public_controller import SOURCE
                script = ('import os,pathlib,signal,sys;p=pathlib.Path("/proc")/sys.argv[1];'
                          'expected=[sys.argv[2].encode(),sys.argv[3].encode()];'
                          'assert not p.exists() or (int((p/"status").read_text().split("Uid:",1)[1].split()[0])==1001 '
                          'and all(x in (p/"cmdline").read_bytes().split(bytes([0])) for x in expected));'
                          'os.kill(int(sys.argv[1]),signal.SIGTERM) if p.exists() else None')
                manager = self.controller.manager
                # A stopped/replaced container has already destroyed its old
                # bridge. Otherwise signal only the exact contained instance.
                state = manager.inspect()
                generation = (state.get("Id"), state.get("State", {}).get("StartedAt")) if state else None
                if state and state["State"]["Running"] and generation == self.bridge_container:
                    manager.run(["exec", "--user", "1001:1000", manager.container, "python3", "-c", script,
                                 str(self.bridge_pid), SOURCE + "/contrib/ml-dsa-qualification/public_transport.py", self.bridge_id])
            if self.bridge.poll() is None:
                try:
                    self.bridge.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.bridge.terminate()
                    try:
                        self.bridge.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.bridge.kill()
                        self.bridge.wait(timeout=5)
            self.bridge = None
            self.bridge_log.close()
            self.bridge_log = None
            self.bridge_pid = self.bridge_id = None
            self.bridge_container = None
        return {"stopped": True}

    def bridge_start(self, params):
        from public_controller import SOURCE
        from public_transport import PublicEndpoint
        require(set(params) == {"hostname", "public_ips", "port", "until_utc"}, "Bridge parameter members")
        endpoint = PublicEndpoint(params["hostname"], params["port"], tuple(params["public_ips"]))
        end = datetime.fromisoformat(params["until_utc"])
        require(end.tzinfo is not None and end.utcoffset().total_seconds() == 0 and
                datetime.now(timezone.utc).timestamp() < end.timestamp() <= self.deadline,
                "Bridge deadline must be within the agent shutdown deadline")
        self.bridge_stop()
        manager = self.controller.manager
        state = manager.inspect()
        require(state and state.get("State", {}).get("Running") and type(state.get("Id")) is str and
                type(state["State"].get("StartedAt")) is str, "Running public container generation is required")
        self.bridge_container = (state["Id"], state["State"]["StartedAt"])
        path = self.state_dir / ("public-transport-" + str(time.monotonic_ns()) + ".jsonl")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.bridge_log = os.fdopen(fd, "wb")
        self.bridge_id = uuid.uuid4().hex
        launcher = ('import json,os,sys;print(json.dumps({"bridge_pid":os.getpid(),"instance_id":sys.argv[1]}),flush=True);'
                    'os.execv(sys.executable,[sys.executable,*sys.argv[2:]])')
        command = [*manager.docker, "exec", "--user", "1001:1000", manager.container,
                   "python3", "-c", launcher, self.bridge_id,
                   SOURCE + "/contrib/ml-dsa-qualification/public_transport.py", "bridge", "--hostname", endpoint.hostname,
                   "--port", str(endpoint.port), "--until-utc", end.isoformat(), "--instance-id", self.bridge_id]
        for address in endpoint.addresses:
            command += ["--public-ip", address]
        self.bridge = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.bridge_log,
                                       stderr=self.bridge_log, close_fds=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with path.open("rb") as log:
                first = log.readline(1024)
            if first.endswith(b"\n"):
                identity = json.loads(first)
                require(identity.get("instance_id") == self.bridge_id and type(identity.get("bridge_pid")) is int and
                        identity["bridge_pid"] > 1, "Contained bridge process identity missing")
                self.bridge_pid = identity["bridge_pid"]
                break
            require(self.bridge.poll() is None, "Contained bridge failed before launch")
            time.sleep(0.02)
        else:
            raise ValueError("Contained bridge identity deadline")
        # Readiness is observed by an actual peer action; a live exec alone
        # cannot establish an authenticated TLS/public P2P route.
        return {"bridge_process_started": True, "log": path.name, "loopback_endpoint": "127.0.0.1:23834"}

    def sample(self):
        # Read only this newly deployed node's resource counters, never argv,
        # environment or other processes' files.
        script = '''import json,os,pathlib
rows=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  if pathlib.Path(os.readlink(p/'exe')).name!='pqbtcd': continue
  s=dict(x.split(':',1) for x in (p/'status').read_text().splitlines())
  if int(s['Uid'].split()[0])!=1001: continue
  t=(p/'stat').read_text().split(')',1)[1].split()
  rows.append({'pid':int(p.name),'rss_bytes':int(s['VmRSS'].split()[0])*1024,'peak_rss_bytes':int(s['VmHWM'].split()[0])*1024,'user_ticks':int(t[11]),'system_ticks':int(t[12])})
 except (FileNotFoundError,ProcessLookupError,PermissionError): pass
assert len(rows)==1
print(json.dumps(rows[0],sort_keys=True))'''
        manager = self.controller.manager
        row = json.loads(manager.run(["exec", "--user", "1001:1000", manager.container, "python3", "-c", script]).stdout)
        row.update(self.controller._request("sample"))
        if sys.platform.startswith("linux"):
            def cpu():
                values = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
                return sum(values), values[3] + values[4]
            before = cpu()
            time.sleep(0.2)
            after = cpu()
            delta = after[0] - before[0]
            row["whole_host_cpu_percent"] = 100 * (delta - (after[1] - before[1])) / delta if delta else 0
        if self.bridge is not None:
            row["bridge_alive"] = self.bridge.poll() is None
        return row

    def act(self, action, params):
        require(time.time() < self.deadline and time.monotonic() < self.monotonic_deadline,
                "Agent independent shutdown deadline passed")
        if action == "status":
            require(not params, "Status takes no parameters")
            return compact_status(self.controller.status())
        if action == "sample":
            require(not params, "Sample takes no parameters")
            return self.sample()
        if action == "identity":
            require(not params, "Identity takes no parameters")
            manager = self.controller.manager
            manager.ensure(self.controller.descriptor)
            manager.layout(manager.inspect())
            value = manager.descriptor
            manifest = value["manifest"]
            return {"image": value["image"], "source_head": manifest["source_head"],
                    "source_tree": manifest["source_tree"], "architecture": manifest["architecture"],
                    "sha256": manifest["sha256"]}
        if action == "quarantine_record":
            require(not params, "Missing-record control takes no parameters")
            from public_controller import DATA
            self.controller.action("lock", {})
            require(self.controller.journal["checkpoint"] is not None,
                    "A retained public checkpoint is required before the missing-record control")
            point = dict(self.controller.journal["checkpoint"])
            manager = self.controller.manager
            manager.layout(manager.inspect())
            token = uuid.uuid4().hex
            script = ('import os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);'
                      'fd=os.open(p/"wallet.dat",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                      'assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o600 '
                      'and s.st_nlink==1 and s.st_size==167;'
                      'current=os.stat(p/"wallet.dat",follow_symlinks=False);assert (s.st_ino,s.st_dev)==(current.st_ino,current.st_dev);'
                      'destination=p/("quarantined-wallet-"+sys.argv[2]+".dat");assert not destination.exists();'
                      'os.rename(p/"wallet.dat",destination);os.close(fd);'
                      'fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);assert not (p/"wallet.dat").exists()')
            manager.run(["exec", "--user", "1000:1000", manager.container, "python3", "-c", script,
                         DATA + "/signer/current", token])
            require(self.controller.journal["checkpoint"] == point, "Missing-record control changed retained public floors")
            return {"selected_record_missing": True, "independent_journal_preserved": True,
                    "wallet_id": point["wallet_id"], "next_receive": point["next_receive"], "next_change": point["next_change"]}
        if action == "hostile":
            from public_transport import PublicEndpoint, probe
            require(set(params) == {"hostname", "public_ips", "port"}, "Hostile endpoint parameter members")
            endpoint = PublicEndpoint(params["hostname"], params["port"], tuple(params["public_ips"]))
            return probe(endpoint, owned_oversize_control=True)
        if action == "bridge_start":
            return self.bridge_start(params)
        if action == "bridge_stop":
            require(not params, "Bridge stop takes no parameters")
            return self.bridge_stop()
        require(action in {"start", "stop", "setup", "unlock", "lock", "receive", "send", "mine", "fund", "backup",
                           "recover", "peer", "network", "reindex", "upgrade", "rollback", "adverse", "crash",
                           "transaction", "clear_bans"},
                "Unknown public agent action")
        return public_result(self.controller.action(action, params))

    def close(self):
        try:
            self.bridge_stop()
        finally:
            self.controller.action("stop", {})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--container", required=True)
    parser.add_argument("--p2p-port", type=int, default=23833)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--sudo-docker", action="store_true")
    parser.add_argument("--until-utc", required=True)
    args = parser.parse_args()
    from public_controller import PublicController
    from source_runtime import load_descriptor
    end = datetime.fromisoformat(args.until_utc)
    require(end.tzinfo is not None and end.utcoffset().total_seconds() == 0 and
            0 < end.timestamp() - time.time() <= 27 * 3600, "A UTC shutdown deadline within 27 hours is required")
    controller = PublicController(args.state_dir, load_descriptor(args.descriptor), container=args.container,
                                  p2p_port=args.p2p_port, bootstrap=args.bootstrap,
                                  docker=("sudo", "-n", "docker") if args.sudo_docker else ("docker",))
    agent = Agent(controller, args.state_dir, end.timestamp())
    guard = DeadlineGuard(agent.deadline, agent.monotonic_deadline, lambda: stop_owned_public(controller.manager))
    guard.start()
    expected_id, prior_hash, prior_response = 0, None, None
    control_input = ControlInput(sys.stdin.fileno())
    def emit(value):
        return write_control_response(sys.stdout.fileno(), (value + "\n").encode(),
                                      agent.deadline, agent.monotonic_deadline)
    try:
        require(emit(json.dumps({"event": "agent_ready", "scope": SCOPE, "until_utc": end.isoformat()})),
                "Public control output deadline before readiness")
        while True:
            raw = control_input.line(agent.deadline, agent.monotonic_deadline)
            if raw is None:
                break
            value = request(raw)
            fingerprint = hashlib.sha256(raw).hexdigest()
            if value["id"] == expected_id - 1 and fingerprint == prior_hash:
                if not emit(prior_response):
                    break
                continue
            require(value["id"] == expected_id, "Nonsequential or substituted agent request")
            try:
                response = {"id": expected_id, "ok": True, "data": agent.act(value["action"], value["params"])}
            except Exception as error:
                # Secret-bearing request content and exception strings do not
                # cross this channel. Full diagnostics remain scoped locally.
                response = {"id": expected_id, "ok": False, "error_class": type(error).__name__}
            prior_response = json.dumps(response, separators=(",", ":"), allow_nan=False)
            prior_hash = fingerprint
            expected_id += 1
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
