#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Durable public-test controls. Only the named P2P port is published."""
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


legacy = module("public_controller_helpers", HERE / "controller.py")
source = module("public_source_helpers", HERE / "source_runtime.py")
wallet = legacy._public
require, canonical, checkpoint = legacy.require, legacy.canonical, legacy.checkpoint
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
COMPATIBILITY = {"schema": "PQBTC-MLDSA44-PUBLIC-COMPATIBILITY-1", "network": "test",
                 "network_binding": wallet.protocol.binding("test").hex(), "spec_sha256": wallet.SPEC,
                 "profile_sha256": PROFILE, "encrypted_record_bytes": 167, "wallet_format": 1}
SEED = "/opt/pqbtc-runtime/seed"
SOURCE = SEED + "/mldsa-demo-source"
BUILD = SEED + "/mldsa-demo-build"
SERVER = SEED + "/demo-signer-bin/pilot-signer"
DATA = "/var/lib/pqbtc"
SOCKET = "/run/pqbtc-ipc/public/signer.sock"
LABELS = {"org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": PROFILE}
TMPFS = {"/run/pqbtc-ipc": "rw,noexec,nosuid,nodev,size=1048576,mode=1777",
         "/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"}


def validate_manifest(value):
    return wallet.validate_manifest(value, network="test")


def merge_manifests(first, second):
    first, second = validate_manifest(first), validate_manifest(second)
    require(first["wallet_id"] == second["wallet_id"], "Cannot merge different public wallet identities")
    entries = {(item["branch"], item["index"]): item for item in first["entries"]}
    for item in second["entries"]:
        key = item["branch"], item["index"]
        require(key not in entries or entries[key] == item, "Conflicting public address at retained path")
        entries[key] = item
    first["entries"] = [entries[key] for key in sorted(entries)]
    for field in ("next_receive", "next_change"):
        first[field] = max(first[field], second[field])
    return validate_manifest(first)


def validate_backup(value):
    require(type(value) is dict and set(value) == {"schema", "compatibility", "created_at", "checkpoint", "manifest", "ciphertext", "sha256"},
            "Invalid public backup members")
    require(value["schema"] == "PQBTC-MLDSA44-PUBLIC-BACKUP-1" and value["compatibility"] == COMPATIBILITY,
            "Public backup network, specification or format mismatch")
    require(type(value["created_at"]) is str and len(value["created_at"]) <= 40, "Invalid public backup timestamp")
    require(legacy.hex_value(value["ciphertext"], 167), "Public backup encrypted record must be 167 bytes")
    point, manifest = checkpoint(value["checkpoint"]), validate_manifest(value["manifest"])
    require(point["wallet_id"] == manifest["wallet_id"] and all(point[key] >= manifest[key] for key in ("next_receive", "next_change")),
            "Public backup identity or address floors disagree")
    payload = {key: item for key, item in value.items() if key != "sha256"}
    require(value["sha256"] == hashlib.sha256(canonical(payload)).hexdigest(), "Public backup checksum mismatch")
    return copy.deepcopy(value)


class Files:
    _read_json = legacy.Controller._read_json
    _write_json = legacy.Controller._write_json

    def __init__(self, state_dir):
        self.state_dir = source.private_directory(state_dir)


class PublicManager(Files):
    """Immutable image binaries and independently persistent wallet/chain data."""
    def __init__(self, state_dir, *, container="pqbtc-mldsa-public", p2p_port=23833, docker=("docker",)):
        super().__init__(state_dir)
        require(type(container) is str and re.fullmatch(r"pqbtc-mldsa-public[a-zA-Z0-9_.-]{0,64}", container),
                "Public runtime needs a dedicated pqbtc-mldsa-public container name")
        require(type(p2p_port) is int and 1024 <= p2p_port <= 65535, "Invalid local P2P port")
        require(tuple(docker) in (("docker",), ("sudo", "-n", "docker")), "Unsupported Docker command prefix")
        self.container, self.volume, self.port, self.docker = container, container + "-data-v1", p2p_port, tuple(docker)
        self.descriptor = None

    def run(self, args, *, data=None, check=True, timeout=90):
        try:
            result = subprocess.run([*self.docker, *args], input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise legacy.ConsoleError("Public Docker operation unavailable or timed out") from error
        require(not check or result.returncode == 0, "Public Docker operation failed: " + result.stderr[:500].decode("utf8", "replace"))
        return result

    def inspect(self):
        result = self.run(["inspect", "--format", "{{json .}}", self.container], check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def image_check(self, descriptor):
        descriptor = source.validate_descriptor(descriptor)
        require(descriptor["manifest"].get("qualification_scope") != "DEVELOPMENT_ONLY",
                "Development image cannot launch an admitted public runtime")
        checks = descriptor["manifest"].get("checks", {})
        require(all(checks.get(name) == "PASS" for name in ("native_integration", "signer", "mldsa44_node_tests",
                                                          "mldsa44_public_tests", "mldsa44_resource_tests")),
                "Public image is missing actual native/public test receipts")
        script = ('import hashlib,json,pathlib,sys;root=pathlib.Path("/opt/pqbtc-runtime");'
                  'raw=(root/"manifest.json").read_bytes();value=json.loads(raw);'
                  'assert hashlib.sha256(raw).hexdigest()==sys.argv[1];'
                  'assert all(hashlib.sha256((root/"seed"/p.removeprefix("/tmp/")).read_bytes()).hexdigest()==h '
                  'for p,h in value["sha256"].items());'
                  'assert hashlib.sha256((root/"seed/mldsa-demo-source/docs/ML_DSA_44_PUBLIC_TEST_PROFILE.md").read_bytes()).hexdigest()==sys.argv[2];'
                  'assert (root/"seed/mldsa-demo-source/contrib/ml-dsa-console/public_runtime.py").is_file();'
                  'print(json.dumps(value,separators=(",",":"),sort_keys=True))')
        result = self.run(["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt",
                           "no-new-privileges", "--memory", "268435456", "--pids-limit", "64", "--user", "1001:1000",
                           descriptor["image"], "python3", "-c", script, descriptor["manifest_sha256"], PROFILE])
        require(json.loads(result.stdout) == descriptor["manifest"], "Public image manifest mismatch")
        require(descriptor["manifest"]["sha256"]["/tmp/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md"] == wallet.SPEC,
                "Public image sealed contract mismatch")
        return descriptor

    def layout(self, value):
        host, config = value["HostConfig"], value["Config"]
        require(value["Image"] == self.descriptor["image"] and config.get("Labels") == self.container_labels(),
                "Public container image or ownership labels changed")
        require(host["ReadonlyRootfs"] is True and host["NetworkMode"] == "bridge" and
                host["Memory"] == 1073741824 and host["NanoCpus"] == 2000000000 and host["PidsLimit"] == 256 and
                host["CapDrop"] == ["ALL"] and host.get("CapAdd") in (None, []) and host["SecurityOpt"] == ["no-new-privileges"] and
                host["Privileged"] is False and host["Tmpfs"] == TMPFS and host["RestartPolicy"]["Name"] == "unless-stopped",
                "Public container isolation changed")
        require(host.get("PortBindings") == {"23833/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]},
                "Only public P2P may be published, to the declared local transport endpoint")
        mounts = value["Mounts"]
        require(len(mounts) == 1 and mounts[0]["Type"] == "volume" and mounts[0]["Name"] == self.volume and
                mounts[0]["Destination"] == DATA and mounts[0]["RW"] is True, "Public data volume changed")
        require(config.get("Cmd") == ["sleep", "infinity"] and config.get("User", "") in ("", "0"), "Public supervisor command changed")

    def container_labels(self):
        return {**LABELS, "org.pqbtc.console.build": "source-1", "org.pqbtc.console.manifest": self.descriptor["manifest_sha256"]}

    def create(self):
        args = ["create", "--name", self.container, "--network", "bridge", "--read-only", "--cpus", "2", "--memory", "1073741824",
                "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "unless-stopped",
                "--publish", "127.0.0.1:" + str(self.port) + ":23833/tcp",
                "--mount", "type=volume,source=" + self.volume + ",target=" + DATA + ",volume-nocopy"]
        for key, value in TMPFS.items():
            args += ["--tmpfs", key + ":" + value]
        for key, value in self.container_labels().items():
            args += ["--label", key + "=" + value]
        self.run([*args, self.descriptor["image"], "sleep", "infinity"])

    def ensure(self, descriptor=None):
        fd = os.open(self.state_dir / ".public-runtime.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            wallet.PublicStore._owned(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self._ensure(descriptor)
        finally:
            os.close(fd)

    def _ensure(self, descriptor):
        saved = self.state_dir / "public-runtime.json"
        prior = self._read_json(saved.name) if saved.exists() or saved.is_symlink() else None
        if prior:
            require(prior.get("schema") == "PQBTC-MLDSA44-PUBLIC-RUNTIME-1" and prior.get("compatibility") == COMPATIBILITY and
                    prior.get("container") == self.container and prior.get("volume") == self.volume and prior.get("port") == self.port,
                    "Saved public runtime configuration changed")
            prior = self._reconcile_replacement(prior)
        descriptor = source.validate_descriptor(descriptor or (prior or {}).get("descriptor"))
        require(not prior or prior["descriptor"] == descriptor, "Use the explicit compatible upgrade control to change binaries")
        self.descriptor = self.image_check(descriptor)
        self.run(["info", "--format", "{{json .ServerVersion}}"], timeout=15)
        result = self.run(["volume", "inspect", "--format", "{{json .}}", self.volume], check=False)
        if result.returncode:
            require(prior is None, "Existing public data volume is missing; recover the retained backup explicitly")
            args = ["volume", "create"]
            for key, value in LABELS.items():
                args += ["--label", key + "=" + value]
            self.run([*args, self.volume])
            volume_id = uuid.uuid4().hex
            script = ('import json,os,pathlib,sys;p=pathlib.Path(sys.argv[1]);assert not any(p.iterdir());'
                      'os.chmod(p,0o755);'
                      '[(x.mkdir(mode=m),os.chown(x,u,1000)) for x,u,m in [(p/"signer",1000,0o700),(p/"node",1001,0o700)]];'
                      'data=json.dumps({"volume_id":sys.argv[2],"profile_sha256":sys.argv[3]}).encode();'
                      'fd=os.open(p/"identity.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644);os.write(fd,data);os.fsync(fd);os.close(fd)')
            self.run(["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                      "--security-opt", "no-new-privileges", "--mount", "type=volume,source=" + self.volume + ",target=" + DATA + ",volume-nocopy",
                      descriptor["image"], "python3", "-c", script, DATA, volume_id, PROFILE])
            prior = {"schema": "PQBTC-MLDSA44-PUBLIC-RUNTIME-1", "compatibility": COMPATIBILITY, "container": self.container,
                     "volume": self.volume, "volume_id": volume_id, "port": self.port, "descriptor": descriptor, "history": []}
            self._write_json(saved.name, prior)
        else:
            value = json.loads(result.stdout)
            require(prior is not None and value["Driver"] == "local" and value.get("Options") in (None, {}) and value.get("Labels") == LABELS,
                    "Existing public volume lacks matching retained ownership; it was preserved")
        value = self.inspect()
        if value is None:
            self.create()
            value = self.inspect()
        self.layout(value)
        if not value["State"]["Running"]:
            self.run(["start", self.container])
        script = ('import json,os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_size<1024;'
                  'sys.stdout.buffer.write(os.read(fd,1024));os.close(fd)')
        marker = json.loads(self.run(["exec", "--user", "1001:1000", self.container, "python3", "-c", script, DATA + "/identity.json"]).stdout)
        require(marker == {"volume_id": prior["volume_id"], "profile_sha256": PROFILE}, "Public volume marker mismatch")
        return copy.deepcopy(prior)

    def _finish_replacement(self):
        path = self.state_dir / "public-replacement.json"
        os.rename(path, self.state_dir / ("public-replacement-completed-" + uuid.uuid4().hex + ".json"))
        fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _reconcile_replacement(self, prior):
        path = self.state_dir / "public-replacement.json"
        if not path.exists() and not path.is_symlink():
            return prior
        plan = self._read_json(path.name)
        require(type(plan) is dict and set(plan) == {"schema", "volume_id", "previous", "candidate"} and
                plan["schema"] == "PQBTC-MLDSA44-PUBLIC-REPLACEMENT-1" and plan["volume_id"] == prior["volume_id"] and
                prior["descriptor"] in (plan["previous"], plan["candidate"]), "Interrupted binary replacement record mismatch")
        old, candidate = source.validate_descriptor(plan["previous"]), source.validate_descriptor(plan["candidate"])
        current = self.inspect()
        if current is not None and current["Image"] == candidate["image"]:
            self.descriptor = self.image_check(candidate)
            self.layout(current)
            if old not in prior["history"]:
                prior["history"].append(old)
            prior["descriptor"] = candidate
        else:
            # A crash before candidate creation resumes the retained image.
            # No volume snapshot, encrypted record or public floor is reverted.
            require(current is None or current["Image"] == old["image"], "Unexpected container during interrupted replacement; preserved")
            self.descriptor = self.image_check(old)
            if current is not None:
                self.layout(current)
            prior["descriptor"] = old
        self._write_json("public-runtime.json", prior)
        self._finish_replacement()
        return prior

    def upgrade(self, descriptor, *, rollback=False):
        fd = os.open(self.state_dir / ".public-runtime.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            wallet.PublicStore._owned(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self._upgrade(descriptor, rollback=rollback)
        finally:
            os.close(fd)

    def _upgrade(self, descriptor, *, rollback=False):
        prior = self._ensure(None)
        candidate = self.image_check(descriptor)
        old = prior["descriptor"]
        require(candidate["image"] != old["image"] and candidate["manifest"]["source_head"] != old["manifest"]["source_head"],
                "A compatible upgrade requires a genuinely distinct source version and image")
        require(candidate["manifest"]["architecture"] == old["manifest"]["architecture"], "Public upgrade architecture mismatch")
        if rollback:
            require(candidate in prior["history"], "Binary rollback requires a retained previously used descriptor")
        self._write_json("public-replacement.json", {"schema": "PQBTC-MLDSA44-PUBLIC-REPLACEMENT-1",
                         "volume_id": prior["volume_id"], "previous": old, "candidate": candidate})
        self.run(["stop", "--time", "45", self.container])
        self.run(["rm", self.container])
        self.descriptor = candidate
        try:
            self.create()
            self.layout(self.inspect())
            self.run(["start", self.container])
        except Exception:
            # Data remains untouched. The old saved descriptor allows an
            # explicit relaunch/recovery if Docker could not create the image.
            raise legacy.ConsoleError("Public binary replacement failed; data was preserved; relaunch the retained image")
        if old not in prior["history"]:
            prior["history"].append(old)
        prior["descriptor"] = candidate
        self._write_json("public-runtime.json", prior)
        self._finish_replacement()
        return {"previous_image": old["image"], "image": candidate["image"], "volume_id": prior["volume_id"], "data_rollback": False}


class PublicController(Files):
    _line = staticmethod(legacy.Controller._line)
    _spawn = legacy.Controller._spawn
    _signal = legacy.Controller._signal

    def __init__(self, state_dir, descriptor=None, *, container="pqbtc-mldsa-public", p2p_port=23833,
                 bootstrap=False, docker=("docker",)):
        super().__init__(state_dir)
        self.manager = PublicManager(state_dir, container=container, p2p_port=p2p_port, docker=docker)
        self.descriptor, self.bootstrap = descriptor, bool(bootstrap)
        self._mutex = threading.RLock()
        self._worker = self._worker_info = self._signer = self._signer_info = None
        self._log, self._tainted = None, False
        self._restart_needed = False
        self._lock = os.open(self.state_dir / ".public-console.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            wallet.PublicStore._owned(self._lock)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._initialize_journal()
        except BaseException:
            os.close(self._lock)
            self._lock = None
            raise

    def _initialize_journal(self):
        (self.state_dir / "backups").mkdir(mode=0o700, exist_ok=True)
        source.private_directory(self.state_dir / "backups")
        path = self.state_dir / "public-wallet.json"
        self.journal = self._read_json(path.name) if path.exists() or path.is_symlink() else {
            "schema": "PQBTC-MLDSA44-PUBLIC-FLOORS-1", "compatibility": COMPATIBILITY, "checkpoint": None,
            "manifest": None, "signer_clean": False, "backups": [], "activity": []}
        require(type(self.journal) is dict and set(self.journal) == {"schema", "compatibility", "checkpoint", "manifest", "signer_clean", "backups", "activity"} and
                self.journal["schema"] == "PQBTC-MLDSA44-PUBLIC-FLOORS-1" and self.journal["compatibility"] == COMPATIBILITY,
                "Retained public floor journal schema or network mismatch")
        if self.journal["checkpoint"] is not None:
            point = checkpoint(self.journal["checkpoint"])
            if self.journal["manifest"] is not None:
                manifest = validate_manifest(self.journal["manifest"])
                require(manifest["wallet_id"] == point["wallet_id"] and all(point[key] >= manifest[key] for key in ("next_receive", "next_change")),
                        "Retained public floors disagree")
        require(type(self.journal["backups"]) is list and type(self.journal["activity"]) is list and
                len(self.journal["backups"]) <= 10000 and len(self.journal["activity"]) <= 200,
                "Retained public journal bounds exceeded")
        self._save()

    def _save(self):
        self._write_json("public-wallet.json", self.journal)

    def _event(self, kind, message):
        self.journal["activity"].append({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind, "message": message})
        self.journal["activity"] = self.journal["activity"][-200:]
        self._save()

    def _command(self, user, *args):
        return [*self.manager.docker, "exec", "--interactive", "--user", user, self.manager.container, *map(str, args)]

    def _invoke(self, user, *args, data=None, timeout=90):
        try:
            result = subprocess.run(self._command(user, *args), input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise legacy.ConsoleError("Public contained operation unavailable or timed out") from error
        require(result.returncode == 0, "Public contained operation failed: " + result.stderr[:500].decode("utf8", "replace"))
        return result.stdout

    def _retain(self, manifest=None, point=None):
        current = self.journal["checkpoint"]
        if point is not None:
            point = checkpoint(point)
            if current:
                require(point["wallet_id"] == current["wallet_id"], "Signer changed the retained wallet identity")
                for key in ("next_receive", "next_change"):
                    point[key] = max(point[key], current[key])
            self.journal["checkpoint"] = point
        if manifest is not None:
            manifest = validate_manifest(manifest)
            require(self.journal["checkpoint"] is not None and manifest["wallet_id"] == self.journal["checkpoint"]["wallet_id"],
                    "Public manifest identity differs from native checkpoint")
            previous = self.journal["manifest"]
            self.journal["manifest"] = merge_manifests(previous, manifest) if previous else manifest
            for key in ("next_receive", "next_change"):
                self.journal["checkpoint"][key] = max(self.journal["checkpoint"][key], manifest[key])
        self._save()

    def _intent(self, branch):
        require(self.journal["checkpoint"] is not None, "Set up or unlock the public wallet first")
        key = "next_receive" if branch == 0 else "next_change"
        point = self.journal["checkpoint"]
        require(point[key] < 2**31, "Public address branch exhausted")
        point[key] += 1
        # This independent fsync precedes any native issuance or broadcast.
        # If interrupted, restore burns the uncertain index rather than reusing it.
        self._save()

    def _start_worker(self):
        require(self._worker is None, "Public worker already active")
        fd = os.open(self.state_dir / "public-runtime.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        wallet.PublicStore._owned(fd)
        self._log = os.fdopen(fd, "ab", buffering=0)
        args = [SOURCE + "/contrib/ml-dsa-console/public_runtime.py", "--source", SOURCE, "--build", BUILD,
                "--state", DATA + "/node", "--socket", SOCKET]
        if self.bootstrap:
            args += ["--bootstrap"]
        self._worker, self._worker_info = self._spawn("1001:1000", "/usr/bin/python3", *args, stderr=self._log)
        self._tainted = False

    def _request(self, action, params=None):
        require(not self._tainted and self._worker is not None and self._worker.poll() is None, "Public worker is stopped or requires restart")
        try:
            wire = canonical({"action": action, "params": params or {}}) + b"\n"
            offset = 0
            while offset < len(wire):
                count = self._worker.stdin.write(memoryview(wire)[offset:])
                require(type(count) is int and count > 0, "Public worker write interrupted")
                offset += count
            self._worker.stdin.flush()
            value = json.loads(self._line(self._worker, 240, 20 * 1024 * 1024), object_pairs_hook=legacy.strict_pairs)
            require(type(value) is dict and type(value.get("ok")) is bool and
                    set(value) == ({"ok", "result", "manifest"} if value["ok"] else {"ok", "error"}),
                    "Public worker response shape refused")
            if value["ok"] and value["manifest"] is not None:
                self._retain(manifest=value["manifest"])
        except (OSError, ValueError, KeyError, RecursionError) as error:
            self._tainted = True
            raise legacy.ConsoleError("Public worker transport failed; restart before another operation") from error
        require(value["ok"], str(value.get("error", "Public worker operation refused"))[:800])
        return value["result"]

    def _stop_worker(self):
        if self._worker is None:
            return
        process = self._worker
        if process.poll() is None:
            if not self._tainted:
                self._request("stop")
            process.stdin.close()
            process.stdin = None
        try:
            process.communicate(timeout=60)
        except subprocess.TimeoutExpired as error:
            raise legacy.ConsoleError("Public worker cleanup incomplete; preserve its container for inspection") from error
        require(process.returncode == 0, "Public worker did not exit cleanly")
        self._worker = self._worker_info = None
        if self._log:
            self._log.close()
            self._log = None

    def _start_signer(self, password, *, create=False, path=DATA + "/signer/current", point=None, retain=True, public_entries=None):
        require(self._signer is None, "Public signer already active")
        require(type(password) is str and 0 < len(password.encode("utf8")) <= 1024, "Enter a wallet password of 1..1024 UTF-8 bytes")
        point = checkpoint(point or self.journal["checkpoint"]) if not create else None
        script = ('import os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o750,exist_ok=True);'
                  's=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o750;'
                  'p=pathlib.Path(sys.argv[2]);p.mkdir(mode=0o700,exist_ok=True);'
                  's=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o700')
        self._invoke("1000:1000", "python3", "-c", script, str(Path(SOCKET).parent), path)
        flags = ["--valueless-pilot", "--network", "test", "--socket", SOCKET, "--wallet-dir", path,
                 "--node-uid", "1001", "--fee-cap", "20000", "--spec-file", SOURCE + "/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md",
                 "--operator-fd", "3", "--operator-out-fd", "4"]
        if create:
            flags += ["--create"]
        else:
            flags += ["--restore", "--expected-wallet-id", point["wallet_id"], "--min-receive", str(point["next_receive"]),
                      "--min-change", str(point["next_change"]), "--acknowledge-restore-scan-range", "--recovery-public-input"]
        launcher = ('import json,os,sys;print(json.dumps({"pid":os.getpid(),"start":open("/proc/self/stat").read().rsplit(")",1)[1].split()[19]}),flush=True);'
                    'os.dup2(0,3);os.dup2(1,4);os.execv(sys.argv[1],sys.argv[1:])')
        if retain:
            self.journal["signer_clean"] = False
            self._save()
        process = subprocess.Popen(self._command("1000:1000", "python3", "-c", launcher, SERVER, *flags),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self._signer = process
        secret = bytearray(password.encode("utf8"))
        frame = bytearray(struct.pack("<H", len(secret))) + secret
        try:
            if not create:
                entries = public_entries if public_entries is not None else (self.journal["manifest"] or {}).get("entries", [])
                require(type(entries) is list and len(entries) <= 4096, "Native recovery public entry bound exceeded")
                frame.extend(struct.pack("<I", len(entries)))
                for entry in entries:
                    frame.extend(bytes([entry["branch"]]) + struct.pack("<I", entry["index"]) +
                                 bytes.fromhex(entry["public_key"]) + bytes.fromhex(entry["program"]))
            offset = 0
            while offset < len(frame):
                count = process.stdin.write(memoryview(frame)[offset:])
                require(type(count) is int and count > 0, "Native operator FD write interrupted")
                offset += count
            process.stdin.close()
            process.stdin = None
            info = json.loads(self._line(process, 30, 512))
            require(type(info.get("pid")) is int and info["pid"] > 1 and str(info.get("start", "")).isdigit(), "Invalid public signer identity")
            info.update(uid=1000, executable=SERVER)
            self._signer_info = info
            observed = legacy.parse_checkpoint(self._line(process, 45, 512))
            require(create or (observed["wallet_id"] == point["wallet_id"] and all(observed[key] >= point[key] for key in ("next_receive", "next_change"))),
                    "Restored public signer identity or floors mismatch")
            if retain:
                self._retain(point=observed)
            deadline = time.monotonic() + 15
            while self._invoke("1000:1000", "python3", "-c", "import pathlib,sys;print(int(pathlib.Path(sys.argv[1]).is_socket()))", SOCKET).strip() != b"1":
                require(process.poll() is None and time.monotonic() < deadline, "Public signer socket startup deadline")
                time.sleep(0.03)
            return observed
        except Exception as error:
            if process.poll() is None and self._signer_info:
                self._signal(self._signer_info)
            try:
                process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                raise legacy.ConsoleError("Public signer startup cleanup incomplete") from error
            self._signer = self._signer_info = None
            raise legacy.ConsoleError("Public wallet unlock/create refused; encrypted selected record was preserved") from error
        finally:
            secret[:] = b"\0" * len(secret)
            frame[:] = b"\0" * len(frame)

    def _stop_signer(self):
        if self._signer is None:
            return
        process = self._signer
        if process.poll() is None:
            self._signal(self._signer_info)
        try:
            output, error = process.communicate(timeout=30)
        except subprocess.TimeoutExpired as error:
            raise legacy.ConsoleError("Public signer did not stop; no backup was made") from error
        self._signer = self._signer_info = None
        require(process.returncode == 0 and not error, "Public signer shutdown failed; no backup was made")
        point = legacy.parse_checkpoint(getattr(process, "_console_buffer", b"") + output)
        self._retain(point=point)
        self.journal["signer_clean"] = True
        self._save()

    def _start(self):
        self._reconcile_handles()
        self.manager.ensure(self.descriptor)
        self.descriptor = self.manager.descriptor
        if self._restart_needed or (self._worker is None and self.journal["checkpoint"] is not None and not self.journal["signer_clean"]):
            # A lost host/docker-exec connection cannot prove native children
            # stopped. Recreate only this verified owned process namespace.
            self.manager.layout(self.manager.inspect())
            self.manager.run(["restart", "--time", "5", self.manager.container])
            self._discard_handles()
            self._restart_needed = False
        if self._worker is None:
            self._start_worker()
        return self._request("start")

    def _discard_handles(self):
        """After a verified owned-container restart, discard both old handles."""
        for role in ("worker", "signer"):
            process = getattr(self, "_" + role)
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                    process.stdin = None
                process.communicate(timeout=30)
            setattr(self, "_" + role, None)
            setattr(self, "_" + role + "_info", None)
        if self._log is not None:
            self._log.close()
            self._log = None

    def _reconcile_handles(self):
        lost = False
        for role in ("worker", "signer"):
            process = getattr(self, "_" + role)
            if process is None or process.poll() is None:
                continue
            if process.stdin is not None:
                process.stdin.close()
                process.stdin = None
            process.communicate(timeout=3)
            setattr(self, "_" + role, None)
            setattr(self, "_" + role + "_info", None)
            lost = True
        if lost:
            if self._worker is None and self._log is not None:
                self._log.close()
                self._log = None
            self.journal["signer_clean"] = False
            self._restart_needed = True
            self._save()

    def _backup(self):
        require(self.journal["checkpoint"] is not None, "Set up a public wallet first")
        if self._worker is not None:
            self._request("manifest")
        self._stop_signer()
        require(self.journal["signer_clean"] is True and self.journal["manifest"] is not None, "Backup requires a clean checkpoint and retained public addresses")
        script = ('import os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;'
                  'data=os.read(fd,168);assert len(data)==167;sys.stdout.buffer.write(data);os.close(fd)')
        encrypted = self._invoke("1000:1000", "python3", "-c", script, DATA + "/signer/current/wallet.dat")
        value = {"schema": "PQBTC-MLDSA44-PUBLIC-BACKUP-1", "compatibility": COMPATIBILITY,
                 "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "checkpoint": self.journal["checkpoint"], "manifest": self.journal["manifest"], "ciphertext": encrypted.hex()}
        value["sha256"] = hashlib.sha256(canonical(value)).hexdigest()
        validate_backup(value)
        item = {"id": uuid.uuid4().hex, "created_at": value["created_at"], "wallet_id": value["manifest"]["wallet_id"]}
        self._write_json("backups/" + item["id"] + ".json", value)
        self.journal["backups"].append(item)
        self._event("backup", "Encrypted public wallet backup saved; wallet is locked")
        return item

    def _recover(self, backup_id, password):
        require(type(backup_id) is str and re.fullmatch(r"[0-9a-f]{32}", backup_id), "Choose a saved public backup")
        value = validate_backup(self._read_json("backups/" + backup_id + ".json"))
        point = self.journal["checkpoint"]
        require(point is not None and point["wallet_id"] == value["checkpoint"]["wallet_id"],
                "Recovery requires the independent retained floor journal for this wallet")
        if self._worker is not None and not self._tainted:
            self._request("manifest")
        manifest = merge_manifests(value["manifest"], self.journal["manifest"]) if self.journal["manifest"] else value["manifest"]
        point = copy.deepcopy(self.journal["checkpoint"])
        for key in ("next_receive", "next_change"):
            point[key] = max(point[key], value["checkpoint"][key], manifest[key])
            manifest[key] = point[key]
        self._stop_signer()
        self._stop_worker()
        token = uuid.uuid4().hex
        staged = DATA + "/signer/recovery-" + token
        script = ('import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700);data=sys.stdin.buffer.read(168);assert len(data)==167;'
                  'fd=os.open(p/"wallet.dat",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,data);os.fsync(fd);os.close(fd)')
        self._invoke("1000:1000", "python3", "-c", script, staged, data=bytes.fromhex(value["ciphertext"]))
        # Authenticate the old ciphertext before touching selected custody.
        observed = self._start_signer(password, path=staged, point=point, retain=False, public_entries=manifest["entries"])
        try:
            script = ('import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);old=p/"current";'
                      'os.rename(old,p/("retained-"+sys.argv[2])) if old.exists() else None;'
                      'os.rename(p/("recovery-"+sys.argv[2]),old);fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
            self._invoke("1000:1000", "python3", "-c", script, DATA + "/signer", token)
            script = ('import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);q=p/("public-recovery-"+sys.argv[2]);q.mkdir(mode=0o700);'
                      'data=sys.stdin.buffer.read(16777217);assert len(data)<=16777216;'
                      'fd=os.open(q/"public-wallet.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,data);os.fsync(fd);os.close(fd);'
                      'os.rename(p/"public",p/("public-retained-"+sys.argv[2])) if (p/"public").exists() else None;'
                      'os.rename(q,p/"public");fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
            self._invoke("1001:1000", "python3", "-c", script, DATA + "/node", token, data=canonical(manifest) + b"\n")
            self._retain(point=observed, manifest=manifest)
            self.journal["signer_clean"] = False
            self._save()
            self._start_worker()
            self._request("start")
            self._request("status")
            self._event("recover", "Old encrypted backup restored with retained public floors; chain data remains validated by the node")
            return {"id": backup_id, "wallet_id": point["wallet_id"], "next_receive": point["next_receive"], "next_change": point["next_change"], "chain_snapshot_restored": False}
        except Exception:
            self._stop_signer()
            raise

    def status(self):
        with self._mutex:
            self._reconcile_handles()
            if self._worker is not None:
                value = self._request("status")
            else:
                value = legacy.Controller._empty()
            value["scope"] = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
            value["backups"] = copy.deepcopy(self.journal["backups"])
            value["activity"] = copy.deepcopy(self.journal["activity"][-30:])
            value["wallet"]["locked"] = (self._signer is None or value["wallet"].get("locked", True) or
                                           not value["wallet"].get("signer_connected", False))
            if self.journal["checkpoint"]:
                point = self.journal["checkpoint"]
                value["wallet"]["wallet_id"] = point["wallet_id"]
                for key in ("next_receive", "next_change"):
                    value["wallet"][key] = max(value["wallet"].get(key, 0), point[key])
            value["setup_required"] = self.journal["checkpoint"] is None
            value["restart_required"] = self._restart_needed
            return value

    def action(self, action, params=None):
        params = {} if params is None else params
        allowed = {"start": set(), "stop": set(), "setup": {"password"}, "unlock": {"password"}, "lock": set(),
                   "receive": set(), "send": {"address", "amount_sats", "fee_sats"}, "mine": {"address", "blocks"},
                   "fund": {"address"}, "backup": set(), "recover": {"backup_id", "password"}, "peer": {"endpoint"},
                   "network": {"active"}, "reindex": set(), "crash": set(), "adverse": set(), "bootstrap": set(), "clear_bans": set(),
                   "transaction": {"txid", "block_hash"}, "sample": set(), "upgrade": {"descriptor"}, "rollback": {"descriptor"}}
        require(type(action) is str and type(params) is dict and action in allowed and set(params) <= allowed[action], "Unsupported public console action or parameters")
        with self._mutex:
            self._reconcile_handles()
            if action == "start":
                result = self._start()
            elif action == "stop":
                self._stop_signer()
                self._stop_worker()
                result = {"stopped": True}
            elif action in ("setup", "unlock"):
                require(self._worker is not None, "Start the public node first")
                require((action == "setup") == (self.journal["checkpoint"] is None), "Choose setup for a new wallet or unlock for the retained wallet")
                status = self._request("status")
                require(status["nodes"] and status["nodes"][0]["context"]["active"] is True,
                        "Public activation has not been reached; connect a peer or explicitly bootstrap H1")
                if self._signer is not None:
                    require(action == "unlock" and status["wallet"]["locked"] is True,
                            "Public wallet is already unlocked")
                    self._stop_signer()
                self._start_signer(params.get("password"), create=action == "setup")
                self._request("status")
                result = {"unlocked": True, "wallet_id": self.journal["checkpoint"]["wallet_id"]}
            elif action == "lock":
                self._stop_signer()
                result = {"locked": True}
            elif action == "backup":
                result = self._backup()
            elif action == "recover":
                result = self._recover(params.get("backup_id"), params.get("password"))
            elif action == "crash":
                self.manager.layout(self.manager.inspect())
                self.manager.run(["kill", "--signal", "KILL", self.manager.container])
                self._discard_handles()
                self.journal["signer_clean"] = False
                self._event("crash", "Owned public container killed; address floors retained independently")
                self._start()
                result = {"crashed": True, "restarted": True, "locked": True}
            elif action in ("upgrade", "rollback"):
                require(self._signer is None, "Lock the wallet before binary replacement")
                backup = self._backup() if self.journal["checkpoint"] else None
                self._stop_worker()
                result = self.manager.upgrade(params.get("descriptor"), rollback=action == "rollback")
                self.descriptor = self.manager.descriptor
                self._start()
                result["backup"] = backup
                self._event(action, "Compatible binary changed; encrypted wallet and public floors kept on the same volume")
            else:
                if action in ("receive", "send"):
                    require(self._signer is not None, "Unlock the public wallet first")
                    self._intent(0 if action == "receive" else 1)
                try:
                    result = self._request(action, params)
                except Exception:
                    if action in ("receive", "send"):
                        self._stop_signer()
                        self._event("interrupted", "Address operation refused or interrupted; unlock again to advance the retained floor")
                    raise
            return {"result": result, "status": self.status()}

    def close(self):
        with self._mutex:
            try:
                self._reconcile_handles()
                self._stop_signer()
                self._stop_worker()
            finally:
                if self._lock is not None:
                    os.close(self._lock)
                    self._lock = None
