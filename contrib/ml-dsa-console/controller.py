#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Host-only controller for the prepared, offline, valueless Linux fixture.

Only encrypted records and public metadata leave Linux. This does not provision
Docker or rebuild missing native binaries. The fixture phrase is deliberately
public and is never accepted from an HTTP request.
"""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import struct
import subprocess
import threading
import time
import uuid

HEAD = "9f4b20a938e67ef985df0780fb41b6035abef15e"
IMAGE = "sha256:767891744587d93faf96d0f9d8ce2c66ebe3a73695b2a7389f82b62735b8ad3a"
SERVER = "/tmp/demo-signer-bin/pilot-signer"
# Exact arm64 binaries from the independent fresh qualification retained in
# the evidence SUMMARY. Merely recording new hashes would trust an altered build.
QUALIFIED_NATIVE = {
    "pqbtcd": "bb55d172508ed47727334f37be374dd34c67ecb42b2cceabae4a7b1d1a575159",
    "pqbtc-mldsa-client": "727e654e4ba692c21c6e259eea0f11838f88ff866a08843907f272395f741317",
    "pilot-signer": "e0b0aea159a0e39704314df63298b9d21d85bfeed21e86e98cab7a41ea70846c",
}
SCHEMA = "PQBTC-MLDSA44-CONSOLE-BACKUP-1"
GENESIS = "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"
MAX_BUNDLE = 80 * 1024 * 1024
PUBLIC_PHRASE = b"public-two-node-demo-fixture"
DURABLE_LABELS = {"org.pqbtc.console.schema": "durable-1", "org.pqbtc.console.source": HEAD}
IPC_TMPFS = {"/run/pqbtc-ipc": "rw,noexec,nosuid,nodev,size=1048576,mode=1777"}


class ConsoleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConsoleError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf8")


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON member")
        result[key] = value
    return result


def number(value, maximum=2**31):
    require(type(value) is int and 0 <= value <= maximum, "Invalid public counter or amount")
    return value


def hex_value(value, size):
    return type(value) is str and len(value) == size * 2 and re.fullmatch("[0-9a-f]+", value) is not None


def checkpoint(value):
    require(type(value) is dict and set(value) == {"wallet_id", "generation", "next_receive", "next_change"},
            "Invalid public checkpoint")
    require(hex_value(value["wallet_id"], 16) and value["wallet_id"] != "00" * 16, "Invalid checkpoint wallet identity")
    number(value["generation"], 2**64 - 1)
    number(value["next_receive"])
    number(value["next_change"])
    return copy.deepcopy(value)


def parse_checkpoint(raw):
    try:
        fields = raw.decode("ascii").strip().split(" ")
        require(len(fields) == 5 and fields[0] == "MLDSA_WALLET_STATUS_V1", "Missing final signer checkpoint")
        require(all(re.fullmatch("[0-9]+", item) for item in fields[2:]), "Invalid checkpoint counters")
        return checkpoint(dict(zip(("wallet_id", "generation", "next_receive", "next_change"),
                                   [fields[1], *map(int, fields[2:])])))
    except (UnicodeError, TypeError) as error:
        raise ConsoleError("Invalid public checkpoint") from error


# Reuse the reviewed PUBLIC manifest validator. It executes no native process,
# opens no wallet and accepts no password on the host.
_public_spec = importlib.util.spec_from_file_location("console_public_wallet", Path(__file__).resolve().parents[1] / "ml-dsa-signer/node_wallet.py")
_public = importlib.util.module_from_spec(_public_spec)
_public_spec.loader.exec_module(_public)


def validate_manifest(value):
    try:
        return _public.validate_manifest(value)
    except (ValueError, KeyError, TypeError) as error:
        raise ConsoleError("Public manifest validation failed") from error


def merge_manifests(first, second):
    first, second = validate_manifest(first), validate_manifest(second)
    require(first["wallet_id"] == second["wallet_id"], "Cannot merge different wallet identities")
    entries = {(item["branch"], item["index"]): item for item in first["entries"]}
    for item in second["entries"]:
        key = (item["branch"], item["index"])
        require(key not in entries or entries[key] == item, "Conflicting retained public address")
        entries[key] = item
    first["entries"] = [entries[key] for key in sorted(entries)]
    for field in ("next_receive", "next_change"):
        first[field] = max(first[field], second[field])
    return validate_manifest(first)


def validate_chain(value):
    require(type(value) is dict and set(value) == {"genesis", "tip", "blocks"}, "Invalid backup chain")
    require(hex_value(value["genesis"], 32) and hex_value(value["tip"], 32), "Invalid chain identity")
    blocks = value["blocks"]
    require(type(blocks) is list and len(blocks) <= 5000, "Backup chain block bound exceeded")
    require(value["genesis"] == GENESIS, "Backup chain is not the fixture regtest genesis")
    total, previous = 0, GENESIS
    for block in blocks:
        require(type(block) is str and len(block) % 2 == 0 and 0 < len(block) <= 8 * 1024 * 1024 and
                re.fullmatch("[0-9a-f]+", block) is not None, "Invalid raw backup block")
        data = bytes.fromhex(block)
        require(len(data) >= 80 and data[4:36][::-1].hex() == previous, "Backup block header link mismatch")
        previous = hashlib.sha256(hashlib.sha256(data[:80]).digest()).digest()[::-1].hex()
        total += len(data)
        require(total <= 32 * 1024 * 1024, "Backup chain byte bound exceeded")
    require(value["tip"] == previous, "Backup chain tip/header mismatch")
    return value


def validate_bundle(value, identity):
    require(type(value) is dict and set(value) == {"schema", "created_at", "identity", "checkpoint", "manifest", "chain", "ciphertext", "sha256"},
            "Invalid backup bundle members")
    require(value["schema"] == SCHEMA and type(value["created_at"]) is str and len(value["created_at"]) <= 40,
            "Invalid backup schema")
    payload = {key: item for key, item in value.items() if key != "sha256"}
    require(hex_value(value["sha256"], 32) and hashlib.sha256(canonical(payload)).hexdigest() == value["sha256"],
            "Backup checksum does not match")
    require(value["identity"] == identity, "Backup source, specification or binary identity does not match prepared runtime")
    require(hex_value(value["ciphertext"], 167), "Encrypted wallet record must be exactly 167 bytes")
    manifest, point = validate_manifest(value["manifest"]), checkpoint(value["checkpoint"])
    require(manifest["wallet_id"] == point["wallet_id"], "Backup wallet identities do not match")
    require(all(point[field] >= manifest[field] for field in ("next_receive", "next_change")), "Backup checkpoint below public address floors")
    validate_chain(value["chain"])
    return copy.deepcopy(value)


class Controller:
    def __init__(self, container, source, build, state_dir, code_dir, runtime_descriptor=None):
        require(type(container) is str and re.fullmatch("[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", container), "Invalid prepared container name")
        for path in (source, build):
            require(type(path) is str and re.fullmatch(r"/tmp/mldsa-[a-zA-Z0-9_./-]+", path) and ".." not in path, "Invalid contained native path")
        self.container, self.source, self.build = container, source, build
        self.runtime_descriptor = None
        self._source_runtime = None
        if runtime_descriptor is not None:
            spec = importlib.util.spec_from_file_location("controller_source_runtime", Path(__file__).resolve().parent / "source_runtime.py")
            self._source_runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self._source_runtime)
            self.runtime_descriptor = self._source_runtime.validate_descriptor(runtime_descriptor)
        self.state_dir, self.code_dir = Path(state_dir), Path(code_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private_dir(self.state_dir)
        (self.state_dir / "backups").mkdir(mode=0o700, exist_ok=True)
        self._private_dir(self.state_dir / "backups")
        self._mutex = threading.RLock()
        self._worker = self._signer = None
        self._worker_tainted = False
        self._prepared_storage = None
        self._worker_info = self._signer_info = None
        self._log = None
        self._metadata = {"version": 1, "retained": {}, "backups": [], "activity": []}
        if (self.state_dir / "session.json").exists():
            value = self._read_json("session.json", 24 * 1024 * 1024)
            require(value.get("version") == 1, "Unsupported console session metadata")
            self._metadata.update(value)
        require(type(self._metadata["retained"]) is dict and len(self._metadata["retained"]) <= 64, "Invalid retained wallet metadata")
        for wallet_id, retained in self._metadata["retained"].items():
            require(hex_value(wallet_id, 16) and type(retained) is dict, "Invalid retained wallet identity")
            for field, validator in (("manifest", validate_manifest), ("checkpoint", checkpoint)):
                if field in retained:
                    require(validator(retained[field])["wallet_id"] == wallet_id, "Retained wallet identity mismatch")
        self._last = self._metadata.get("last_status", self._empty())
        self._last["phase"], self._last["ready"] = "stopped", False
        self._last.setdefault("wallet", {})["locked"] = True

    @staticmethod
    def _private_dir(path):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Console state directory must be owned by you with mode 0700")

    @staticmethod
    def _empty():
        return {"phase": "stopped", "ready": False, "nodes": [], "wallet": {"wallet_id": None, "locked": True,
                "balance_sats": 0, "spendable_sats": 0, "confirmed_sats": 0, "pending_sats": 0,
                "utxos": [], "next_receive": 0, "next_change": 0, "addresses": []}, "backups": [], "activity": []}

    def _read_json(self, relative, maximum=MAX_BUNDLE):
        try:
            fd = os.open(self.state_dir / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as error:
            raise ConsoleError("Console file could not be safely opened") from error
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= maximum, "Console file ownership, mode or size refused")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(maximum + 1)
            require(len(raw) <= maximum, "Console file exceeds size bound")
            return json.loads(raw, object_pairs_hook=strict_pairs)
        except (OSError, ValueError, RecursionError) as error:
            raise ConsoleError("Console JSON could not be read or validated") from error
        finally:
            os.close(fd)

    def _write_json(self, relative, value):
        path = self.state_dir / relative
        if path.exists() or path.is_symlink():
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == 0o600, "Refusing to overwrite uncertain console file")
        raw = canonical(value) + b"\n"
        require(len(raw) <= MAX_BUNDLE, "Console JSON exceeds size bound")
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
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _save(self):
        self._metadata["last_status"] = copy.deepcopy(self._last)
        self._write_json("session.json", self._metadata)

    def _event(self, kind, message, txid=None):
        item = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind, "message": message}
        if txid:
            item["txid"] = txid
        self._metadata["activity"] = (self._metadata["activity"] + [item])[-100:]

    def _command(self, user, *args):
        return ["docker", "exec", "-i", "--user", user, "--env", "PYTHONDONTWRITEBYTECODE=1", "--env",
                "OPENSSL_CONF=/dev/null", "--env", "OPENSSL_MODULES=/nonexistent", self.container, *map(str, args)]

    def _invoke(self, user, *args, data=None, timeout=120):
        try:
            result = subprocess.run(self._command(user, *args), input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConsoleError("Prepared Docker runtime is unavailable or timed out") from error
        require(result.returncode == 0, "Contained fixture helper failed: " + result.stderr[:512].decode("utf8", "replace"))
        return result.stdout

    def _prepare(self):
        template = '{"id":{{json .Id}},"running":{{json .State.Running}},"image":{{json .Image}},"ro":{{json .HostConfig.ReadonlyRootfs}},"network":{{json .HostConfig.NetworkMode}},"memory":{{json .HostConfig.Memory}},"cpus":{{json .HostConfig.NanoCpus}},"drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}},"privileged":{{json .HostConfig.Privileged}},"labels":{{json .Config.Labels}},"capadd":{{json .HostConfig.CapAdd}},"restart":{{json .HostConfig.RestartPolicy.Name}}}'
        try:
            result = subprocess.run(["docker", "inspect", "--format", template, self.container], capture_output=True, timeout=15)
            require(result.returncode == 0, "Prepared offline container is missing; encrypted host backups are retained")
            config = json.loads(result.stdout)
            descriptor = self.runtime_descriptor
            image = descriptor["image"] if descriptor else IMAGE
            head = descriptor["manifest"]["source_head"] if descriptor else HEAD
            require(config["running"] and config["image"] == image and config["ro"] is True and config["network"] == "none" and
                    config["memory"] == 4294967296 and config["cpus"] == 4000000000 and config["drop"] == ["ALL"] and
                    config["security"] == ["no-new-privileges"] and config["privileged"] is False and
                    config.get("capadd") in (None, []), "Prepared container isolation does not match approved fixture")
            if descriptor:
                self._verify_source_manifest()
            self._prepared_storage = self._storage_config(config)
            script = ('import hashlib,json,pathlib,subprocess,sys; source=pathlib.Path(sys.argv[1]);'
                      'git=["git","-c","safe.directory="+str(source),"-C",str(source)];'
                      'head=subprocess.check_output(git+["rev-parse","HEAD"],text=True,encoding="utf8").strip();'
                      'assert head==sys.argv[2] and not subprocess.check_output(git+["status","--porcelain"]);'
                      'paths=sys.argv[3:];report={"source_head":head,"worktree":"clean","sha256":{p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths}};')
            if descriptor:
                script += 'report["source_tree"]=subprocess.check_output(git+["rev-parse","HEAD^{tree}"],text=True,encoding="utf8").strip();'
                paths = list(descriptor["manifest"]["sha256"])
            else:
                paths = [self.build + "/bin/pqbtcd", self.build + "/bin/pqbtc-mldsa-client", SERVER,
                         self.source + "/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md", self.source + "/contrib/ml-dsa-signer/node_wallet.py"]
            script += 'print(json.dumps(report))'
            try:
                identity = json.loads(self._invoke("1001:1000", "python3", "-c", script, self.source, head, *paths))
            except ConsoleError as error:
                raise ConsoleError("Prepared native source/build is missing or invalid; encrypted host backups are retained. " + str(error)) from error
            require(identity["source_head"] == head and identity["worktree"] == "clean", "Contained source identity mismatch")
            if descriptor:
                require(identity.get("source_tree") == descriptor["manifest"]["source_tree"], "Contained source tree identity mismatch")
                expected = descriptor["manifest"]["sha256"]
            else:
                expected = {self.build + "/bin/" + name: digest for name, digest in QUALIFIED_NATIVE.items() if name != "pilot-signer"}
                expected[SERVER] = QUALIFIED_NATIVE["pilot-signer"]
            require(all(identity["sha256"].get(path) == digest for path, digest in expected.items()),
                    "Prepared native binary qualification hashes do not match the approved fixture")
            return config["id"], identity
        except ConsoleError:
            raise
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            raise ConsoleError("Prepared native source/build is missing or invalid; restore requires the approved offline native runtime") from error

    def _verify_source_manifest(self):
        script = ('import os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=4194304;'
                  'data=os.read(fd,4194305);os.close(fd);assert len(data)<=4194304;sys.stdout.buffer.write(data)')
        raw = self._invoke("1001:1000", "python3", "-c", script, self._source_runtime.MANIFEST)
        require(hashlib.sha256(raw).hexdigest() == self.runtime_descriptor["manifest_sha256"] and
                json.loads(raw, object_pairs_hook=strict_pairs) == self.runtime_descriptor["manifest"],
                "Immutable source build manifest does not match retained runtime descriptor")

    def _marker(self, path, maximum=4096):
        script = ('import os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);'
                  's=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and '
                  'stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=int(sys.argv[2]);'
                  'data=os.read(fd,int(sys.argv[2])+1);assert len(data)<=int(sys.argv[2]);'
                  'os.close(fd);sys.stdout.buffer.write(data)')
        raw = self._invoke("1001:1000", "python3", "-c", script, path, maximum)
        return json.loads(raw, object_pairs_hook=strict_pairs)

    def _storage_config(self, config):
        mounts = config["mounts"]
        if self.runtime_descriptor is None and config["tmpfs"] == {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"}:
            mapping = {item["Destination"]: item for item in mounts}
            require(len(mapping) == len(mounts) and "/source-git" in mapping and set(mapping) <= {"/source-git", "/work-source"} and
                    all(item["Type"] == "bind" and item["RW"] is False for item in mounts), "Legacy prepared container mounts refused")
            return {"kind": "legacy-tmpfs", "container_id": config["id"]}
        expected_labels = self._source_runtime.labels(self.runtime_descriptor) if self.runtime_descriptor else DURABLE_LABELS
        require(config["tmpfs"] == IPC_TMPFS and config.get("labels") == expected_labels and len(mounts) == 1 and
                config.get("restart", "no") == "no",
                "Managed durable container mounts, labels or IPC configuration refused")
        mount = mounts[0]
        expected_volume = self.container + "-data-v1"
        require(mount.get("Destination") == "/tmp" and mount.get("Type") == "volume" and mount.get("RW") is True and
                mount.get("Name") == expected_volume, "Only the managed named volume may be mounted")
        template = '{"name":{{json .Name}},"driver":{{json .Driver}},"options":{{json .Options}},"labels":{{json .Labels}}}'
        result = subprocess.run(["docker", "volume", "inspect", "--format", template, expected_volume], capture_output=True, timeout=15)
        require(result.returncode == 0, "Managed durable volume is unavailable")
        volume = json.loads(result.stdout, object_pairs_hook=strict_pairs)
        require(volume.get("name") == expected_volume and volume.get("driver") == "local" and volume.get("options") in (None, {}) and
                volume.get("labels") == expected_labels, "Managed volume driver, options or labels refused")
        if self.runtime_descriptor:
            marker = self._marker(self._source_runtime.MARKER)
            require(type(marker) is dict and set(marker) == {"schema", "source_head", "volume_id", "manifest_sha256"} and
                    marker["schema"] == self._source_runtime.VOLUME_SCHEMA and
                    marker["source_head"] == self.runtime_descriptor["manifest"]["source_head"] and
                    marker["manifest_sha256"] == self.runtime_descriptor["manifest_sha256"] and
                    hex_value(marker["volume_id"], 16), "Managed source runtime volume marker refused")
            return {"kind": "named-volume", "volume": expected_volume, "volume_id": marker["volume_id"],
                    "manifest_sha256": marker["manifest_sha256"]}
        marker = self._marker("/tmp/.pqbtc-runtime-v1.json")
        require(type(marker) is dict and set(marker) == {"schema", "source_head", "volume_id"} and
                marker["schema"] == "PQBTC-MLDSA44-DURABLE-RUNTIME-1" and marker["source_head"] == HEAD and
                hex_value(marker["volume_id"], 16), "Managed durable runtime marker refused")
        return {"kind": "named-volume", "volume": expected_volume, "volume_id": marker["volume_id"]}

    def _validate_selected_state(self):
        for role in ("signer", "node", "code"):
            self._path(self._metadata.get(role + "_dir"), role)
        script = ('import hashlib,json,os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);'
                  'checks=[(p,0o750),(p/"wallet",0o700)];'
                  'assert all(stat.S_ISDIR(x.lstat().st_mode) and x.lstat().st_uid==1000 and stat.S_IMODE(x.lstat().st_mode)==m for x,m in checks);'
                  'fd=os.open(p/"wallet/wallet.dat",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;'
                  'data=os.read(fd,168);os.close(fd);assert len(data)==167;print(json.dumps({"wallet_sha256":hashlib.sha256(data).hexdigest()}))')
        wallet = json.loads(self._invoke("1000:1000", "python3", "-c", script, self._metadata["signer_dir"]))
        return wallet["wallet_sha256"], self._read_selected_manifest()

    def _read_selected_manifest(self, required=True):
        for role in ("node", "code"):
            self._path(self._metadata.get(role + "_dir"), role)
        script = ('import os,pathlib,stat,sys;paths=[pathlib.Path(x) for x in sys.argv[1:]];'
                  'assert all(stat.S_ISDIR(p.lstat().st_mode) and p.lstat().st_uid==1001 and stat.S_IMODE(p.lstat().st_mode)==0o700 for p in paths);'
                  'p=paths[0]/"public/public-wallet.json";'
                  'fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK) if p.exists() else None;'
                  's=os.fstat(fd) if fd is not None else None;'
                  'assert s is None or (stat.S_ISREG(s.st_mode) and s.st_uid==1001 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=16777216);'
                  'data=os.read(fd,16777217) if fd is not None else b"null";'
                  'assert len(data)<=16777216;sys.stdout.buffer.write(data);'
                  'os.close(fd) if fd is not None else None')
        manifest = json.loads(self._invoke("1001:1000", "python3", "-c", script,
                                          self._metadata["node_dir"], self._metadata["code_dir"]), object_pairs_hook=strict_pairs)
        if manifest is not None:
            manifest = validate_manifest(manifest)
            require(manifest["wallet_id"] == self._metadata["checkpoint"]["wallet_id"], "Durable public wallet identity mismatch")
        elif required and self._metadata.get("manifest"):
            raise ConsoleError("Durable public wallet metadata is missing; retained files need recovery")
        return manifest

    def _verify_session_storage(self, container_id, identity, *, replacing=False):
        current, previous = self._prepared_storage, self._metadata.get("storage")
        require(current is not None, "Prepared storage was not validated")
        if previous and previous.get("kind") == "named-volume":
            require(current == previous, "Durable volume identity changed; retained wallet was not opened")
        if "checkpoint" in self._metadata:
            require(identity == self._metadata["identity"], "Prepared native source or binaries changed")
            if current["kind"] == "named-volume":
                already_bound = previous and previous.get("kind") == "named-volume"
                if replacing and already_bound:
                    # Replacement recovery cannot depend on the files it repairs.
                    # Secure public records can add floors, but unavailable or
                    # invalid current records never replace retained metadata.
                    try:
                        manifest = self._read_selected_manifest(required=False)
                    except (ConsoleError, OSError, ValueError, KeyError, TypeError):
                        manifest = None
                        self._event("recover", "Current public record unavailable; retained public floors will be used")
                else:
                    digest, manifest = self._validate_selected_state()
                if not already_bound:
                    marker = self._marker("/tmp/.pqbtc-migration-v1.json", 8192)
                    expected = {"schema": "PQBTC-MLDSA44-DURABLE-MIGRATION-1", "old_container_id": self._metadata["container_id"],
                                "wallet_id": self._metadata["checkpoint"]["wallet_id"], "wallet_sha256": digest,
                                **{role + "_dir": self._metadata[role + "_dir"] for role in ("signer", "node", "code")}}
                    require(marker == expected, "Durable migration marker does not match the selected retained wallet")
                if manifest is not None:
                    retained = self._metadata["retained"].get(manifest["wallet_id"], {}).get("manifest")
                    self._retain(manifest=merge_manifests(retained, manifest) if retained else manifest)
            else:
                require(self._metadata.get("container_id") == container_id, "Legacy container state changed or was lost; use a retained encrypted backup")
        self._metadata.update(container_id=container_id, storage=copy.deepcopy(current))
        self._save()

    def _socket(self):
        if self._prepared_storage and self._prepared_storage["kind"] == "named-volume":
            path = self._metadata.get("ipc_dir")
            require(type(path) is str and re.fullmatch(r"/run/pqbtc-ipc/mldsa-console-ipc-[a-zA-Z0-9_]+", path), "Invalid ephemeral signer IPC directory")
            return path + "/signer.sock"
        return self._metadata["signer_dir"] + "/ipc/signer.sock"

    def _new_dir(self, role):
        user = "1000:1000" if role == "signer" else "1001:1000"
        mode = "0o750" if role == "signer" else "0o700"
        script = 'import os,tempfile; p=tempfile.mkdtemp(prefix="mldsa-console-' + role + '-");os.chmod(p,' + mode + ');print(p)'
        path = self._invoke(user, "python3", "-c", script).decode().strip()
        require(re.fullmatch(r"/tmp/mldsa-console-" + role + r"-[a-zA-Z0-9_]+", path), "Unexpected contained directory")
        return path

    @staticmethod
    def _path(path, role):
        require(type(path) is str and re.fullmatch(r"/tmp/mldsa-console-" + role + r"-[a-zA-Z0-9_]+", path), "Invalid retained contained path")
        return path

    def _setup_paths(self, fresh=False):
        if fresh or "signer_dir" not in self._metadata:
            signer = self._new_dir("signer")
            self._invoke("1000:1000", "python3", "-c", 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/"wallet").mkdir(mode=0o700);(p/"ipc").mkdir(mode=0o750)', signer)
            node, code = self._new_dir("node"), self._new_dir("code")
            self._metadata.update(signer_dir=signer, node_dir=node, code_dir=code)
        for role in ("signer", "node", "code"):
            self._path(self._metadata[role + "_dir"], role)
        if self._prepared_storage and self._prepared_storage["kind"] == "named-volume":
            script = 'import os,tempfile;p=tempfile.mkdtemp(prefix="mldsa-console-ipc-",dir="/run/pqbtc-ipc");os.chmod(p,0o750);print(p)'
            self._metadata["ipc_dir"] = self._invoke("1000:1000", "python3", "-c", script).decode().strip()
            self._socket()
        if self.runtime_descriptor:
            script = ('import os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                      'assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=1048576;'
                      'data=os.read(fd,1048577);os.close(fd);assert len(data)<=1048576;sys.stdout.buffer.write(data)')
            raw = self._invoke("1001:1000", "python3", "-c", script, self.source + "/contrib/ml-dsa-console/runtime.py")
        else:
            raw = (self.code_dir / "runtime.py").read_bytes()
        require(len(raw) <= 1024 * 1024, "Runtime script exceeds bound")
        self._invoke("1001:1000", "python3", "-c", 'import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600);f=os.fdopen(fd,"wb");f.write(sys.stdin.buffer.read());f.close()',
                     self._metadata["code_dir"] + "/runtime.py", data=raw)
        self._save()

    @staticmethod
    def _line(process, timeout, maximum):
        buffer = getattr(process, "_console_buffer", b"")
        deadline = time.monotonic() + timeout
        while b"\n" not in buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and select.select([process.stdout], [], [], max(0, remaining))[0], "Contained process response timed out")
            part = os.read(process.stdout.fileno(), min(65536, maximum + 1 - len(buffer)))
            require(part, "Contained process exited before response")
            buffer += part
            require(len(buffer) <= maximum, "Contained process response exceeds bound")
        line, process._console_buffer = buffer.split(b"\n", 1)
        return line

    def _spawn(self, user, executable, *args, stderr=None):
        launcher = 'import json,os,sys;print(json.dumps({"pid":os.getpid(),"start":open("/proc/self/stat").read().rsplit(")",1)[1].split()[19]}),flush=True);os.execv(sys.argv[1],sys.argv[1:])'
        try:
            process = subprocess.Popen(self._command(user, "python3", "-c", launcher, executable, *args), stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=stderr or subprocess.PIPE, bufsize=0)
            info = json.loads(self._line(process, 15, 512))
            require(type(info["pid"]) is int and info["pid"] > 1 and str(info["start"]).isdigit(), "Invalid contained process identity")
            info.update(uid=int(user.split(":")[0]), executable=executable)
            return process, info
        except (OSError, ValueError, KeyError) as error:
            raise ConsoleError("Contained process could not start") from error

    def _signal(self, info):
        # Verify Linux UID, process start tick and exact argv token before signaling.
        script = ('import os,pathlib,signal,sys;p=pathlib.Path("/proc")/sys.argv[1];'
                  'assert p.stat().st_uid==int(sys.argv[3]);'
                  'assert (p/"stat").read_text().rsplit(")",1)[1].split()[19]==sys.argv[2];'
                  'assert sys.argv[4].encode() in (p/"cmdline").read_bytes().split(b"\\0");'
                  'os.kill(int(sys.argv[1]),signal.SIGTERM)')
        self._invoke(str(info["uid"]) + ":1000", "python3", "-c", script, info["pid"], info["start"], info["uid"], info["executable"])

    def _floors(self, point):
        point = checkpoint(point)
        retained = self._metadata["retained"].get(point["wallet_id"], {})
        for value in (retained.get("checkpoint"), retained.get("manifest"), self._metadata.get("manifest")):
            if value and value["wallet_id"] == point["wallet_id"]:
                for field in ("next_receive", "next_change"):
                    point[field] = max(point[field], number(value[field]))
        return point

    def _retain(self, manifest=None, point=None):
        if manifest is not None:
            manifest = validate_manifest(manifest)
            self._metadata["manifest"] = manifest
            retained = self._metadata["retained"].setdefault(manifest["wallet_id"], {})
            retained["manifest"] = merge_manifests(retained["manifest"], manifest) if retained.get("manifest") else manifest
        if point is not None:
            point = checkpoint(point)
            floors = self._floors(point)
            require(all(point[field] >= floors[field] for field in ("next_receive", "next_change")),
                    "Signer checkpoint below retained address floors")
            self._metadata["checkpoint"] = point
            retained = self._metadata["retained"].setdefault(point["wallet_id"], {})
            retained["checkpoint"] = copy.deepcopy(point)
        self._save()

    def _start_signer(self, create=False):
        require(self._signer is None, "Signer already active")
        signer = self._metadata["signer_dir"]
        flags = ["--valueless-pilot", "--socket", self._socket(), "--wallet-dir", signer + "/wallet",
                 "--node-uid", "1001", "--fee-cap", "20000", "--spec-file", self.source + "/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md",
                 "--operator-fd", "3", "--operator-out-fd", "4"]
        if create:
            flags += ["--create"]
        else:
            point = self._floors(self._metadata["checkpoint"])
            flags += ["--restore", "--expected-wallet-id", point["wallet_id"], "--min-receive", str(point["next_receive"]),
                      "--min-change", str(point["next_change"]), "--acknowledge-restore-scan-range"]
        launcher = 'import json,os,sys;print(json.dumps({"pid":os.getpid(),"start":open("/proc/self/stat").read().rsplit(")",1)[1].split()[19]}),flush=True);os.dup2(0,3);os.dup2(1,4);os.execv(sys.argv[1],sys.argv[1:])'
        process = subprocess.Popen(self._command("1000:1000", "python3", "-c", launcher, SERVER, *flags),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self._signer = process
        self._metadata["signer_clean"] = False
        self._save()
        process.stdin.write(struct.pack("<H", len(PUBLIC_PHRASE)) + PUBLIC_PHRASE)
        process.stdin.close()
        process.stdin = None
        info = json.loads(self._line(process, 15, 512))
        info.update(uid=1000, executable=SERVER)
        self._signer_info = info
        point = parse_checkpoint(self._line(process, 15, 512))
        if not create:
            require(point["wallet_id"] == self._metadata["checkpoint"]["wallet_id"], "Restored signer wallet identity mismatch")
        self._retain(point=point)
        deadline = time.monotonic() + 15
        while self._invoke("1000:1000", "python3", "-c", 'import pathlib,sys;print(int(pathlib.Path(sys.argv[1]).is_socket()))', self._socket()).strip() != b"1":
            require(process.poll() is None and time.monotonic() < deadline, "Signer socket startup failed")
            time.sleep(0.02)

    def _stop_signer(self):
        if self._signer is None:
            return
        process = self._signer
        if process.poll() is None:
            self._signal(self._signer_info)
        try:
            output, error = process.communicate(timeout=20)
        except subprocess.TimeoutExpired as error:
            raise ConsoleError("Signer did not exit cleanly; no backup was made") from error
        self._signer = None
        require(process.returncode == 0 and not error, "Signer did not exit cleanly; no backup was made")
        point = parse_checkpoint(getattr(process, "_console_buffer", b"") + output)
        require(point["wallet_id"] == self._metadata["checkpoint"]["wallet_id"], "Final signer wallet identity mismatch")
        self._metadata["signer_clean"] = True
        self._retain(point=point)

    def _start_worker(self):
        require(self._worker is None, "Previous node worker still needs cleanup")
        self._worker_tainted = False
        fd = os.open(self.state_dir / "runtime.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._log = os.fdopen(fd, "ab", buffering=0)
        self._worker, self._worker_info = self._spawn("1001:1000", "/usr/bin/python3", self._metadata["code_dir"] + "/runtime.py",
                    "--source", self.source, "--build", self.build, "--state", self._metadata["node_dir"],
                    "--socket", self._socket(), "--signer-uid", "1000", stderr=self._log)

    def _request(self, action, params=None):
        require(not self._worker_tainted, "Node worker transport is unusable; stop the console before restarting")
        require(self._worker is not None and self._worker.poll() is None, "Node worker is stopped or exited; inspect retained runtime.log")
        try:
            self._worker.stdin.write(canonical({"action": action, "params": params or {}}) + b"\n")
            self._worker.stdin.flush()
            response = json.loads(self._line(self._worker, 240, MAX_BUNDLE), object_pairs_hook=strict_pairs)
            require(type(response) is dict and type(response.get("ok")) is bool, "Malformed node worker response")
            require(set(response) == ({"ok", "result", "manifest"} if response["ok"] else {"ok", "error"}),
                    "Malformed node worker response members")
            if not response["ok"]:
                require(type(response["error"]) is str, "Malformed node worker error")
            elif response["manifest"] is not None:
                self._retain(manifest=response["manifest"])
        except (OSError, ValueError, KeyError, RecursionError) as error:
            # JSON lines have no request identifiers. After any failed exchange,
            # a late response can never safely be associated with a new request.
            self._worker_tainted = True
            self._last["phase"], self._last["ready"] = "error", False
            try:
                self._save()
            except OSError:
                pass
            raise ConsoleError("Node worker transport failed; stop the console before restarting") from error
        require(response["ok"], response.get("error", "Node worker operation failed")[:1000])
        return response.get("result")

    def _retain_chain(self):
        if self._worker is None or self._worker.poll() is not None or not self._metadata.get("manifest"):
            return None
        chain = validate_chain(self._request("export_chain"))
        wallet_id = self._metadata["manifest"]["wallet_id"]
        self._write_json("chain-" + wallet_id + ".json", {"identity": self._metadata["identity"], "chain": chain})
        return chain

    @staticmethod
    def _merge_chains(first, second):
        first, second = validate_chain(first), validate_chain(second)
        require(first["genesis"] == second["genesis"], "Retained chain genesis mismatch")
        common = min(len(first["blocks"]), len(second["blocks"]))
        require(first["blocks"][:common] == second["blocks"][:common], "Retained chain conflicts with backup prefix")
        return second if len(second["blocks"]) > len(first["blocks"]) else first

    def _stop_worker(self):
        if self._worker is None:
            return
        process, failure = self._worker, None
        if process.poll() is None:
            if not self._worker_tainted:
                try:
                    self._retain_chain()
                    self._request("stop")
                except ConsoleError as error:
                    failure = error
            # EOF runs runtime.close() even when its response stream is tainted.
            if process.stdin is not None:
                process.stdin.close()
                process.stdin = None
        try:
            process.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            # Runtime's SIGTERM handler also runs finally/close. Signal only the
            # verified guest PID; never kill a docker client and orphan nodes.
            self._signal(self._worker_info)
            try:
                process.communicate(timeout=40)
            except subprocess.TimeoutExpired as error:
                raise ConsoleError("Node worker cleanup timed out; retained processes need inspection") from error
        require(process.returncode == 0, "Node worker did not exit cleanly; retained state needs inspection")
        self._worker = None
        if self._log:
            self._log.close()
            self._log = None
        if failure:
            raise failure

    def _normal_status(self, value):
        require(type(value) is dict, "Invalid runtime status")
        status = self._empty()
        status.update({key: value[key] for key in ("phase", "ready", "nodes") if key in value})
        status["wallet"].update(value.get("wallet") or {})
        if self._signer is None:
            status["wallet"]["locked"] = True
        status["backups"] = copy.deepcopy(self._metadata["backups"])
        status["activity"] = copy.deepcopy(self._metadata["activity"])
        self._last = status
        return status

    def _reconcile_handles(self):
        dead = {role: process for role, process in (("worker", self._worker), ("signer", self._signer))
                if process is not None and process.poll() is not None}
        if not dead:
            return
        for role, process in dead.items():
            try:
                process.communicate(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ConsoleError("Exited Docker process handles could not be reaped") from error
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(process, name, None)
                if stream is not None:
                    stream.close()
            setattr(self, "_" + role, None)
            setattr(self, "_" + role + "_info", None)
        if self._worker is None and self._log:
            self._log.close()
            self._log = None
        self._worker_tainted = False
        self._metadata["signer_clean"] = False
        self._last["phase"], self._last["ready"] = "stopped", False
        self._last["wallet"]["locked"] = True
        self._event("stop", "Contained processes exited; retained durable state can be restarted")
        active = self._worker is not None or self._signer is not None
        if active:
            # Only cleanup owned handles, using the existing PID/start/UID checks.
            try:
                self._stop_worker()
                self._stop_signer()
            finally:
                self._metadata["signer_clean"] = False
                self._save()
            raise ConsoleError("A contained process exited unexpectedly; its owned companion was stopped. Start the console again")
        self._save()

    def status(self):
        with self._mutex:
            self._reconcile_handles()
            if self._worker is not None:
                try:
                    self._normal_status(self._request("status"))
                except ConsoleError:
                    self._last["phase"], self._last["ready"] = "error", False
                    raise
            else:
                self._last["phase"], self._last["ready"] = "stopped", False
            self._last["backups"] = copy.deepcopy(self._metadata["backups"])
            self._last["activity"] = copy.deepcopy(self._metadata["activity"])
            self._save()
            return copy.deepcopy(self._last)

    @staticmethod
    def _params(action, params):
        allowed = {"start": set(), "stop": set(), "receive": set(), "fund": {"address", "amount_sats"},
                   "send": {"address", "amount_sats", "fee_sats"}, "mine": {"blocks"}, "backup": set(),
                   "recover": {"backup_id"}, "lock": set(), "unlock": set(), "status": set()}
        require(type(action) is str and action in allowed and type(params) is dict and set(params) <= allowed[action], "Unknown action or unexpected parameters")
        if action in ("send", "fund"):
            if action == "send":
                require("address" in params and "amount_sats" in params, "Send requires address and integer test satoshis")
            if "address" in params:
                require(type(params["address"]) is str and 1 <= len(params["address"]) <= 150 and
                        re.fullmatch("[a-z0-9]+", params["address"]), "Invalid test address")
            for field in ("amount_sats", "fee_sats"):
                if field in params:
                    number(params[field], 2100000000000000 if field == "amount_sats" else 20000)
                    require(params[field] > 0 if field == "amount_sats" else True, "Amount must be positive")
        if action == "mine":
            number(params.get("blocks", 1), 101)
            require(params.get("blocks", 1) > 0, "Mine at least one block")
        if action == "recover":
            require(type(params.get("backup_id")) is str and re.fullmatch("[0-9a-f]{32}", params["backup_id"]), "Choose an existing backup")

    def _rollback_startup(self):
        # Cleanup only handles this controller actually created. Preserve the
        # triggering exception; retain cleanup failures as operator evidence.
        for stop in (self._stop_worker, self._stop_signer):
            try:
                stop()
            except Exception as error:
                self._event("error", "Startup cleanup requires inspection: " + str(error)[:300])
        self._last["phase"], self._last["ready"] = "error", False
        self._last["wallet"]["locked"] = True

    def _start(self):
        self._reconcile_handles()
        require(self._worker is None, "Console already running")
        container_id, identity = self._prepare()
        existing = "checkpoint" in self._metadata
        self._verify_session_storage(container_id, identity)
        self._metadata.update(identity=identity)
        try:
            self._setup_paths()
            self._start_signer(create=not existing)
            self._start_worker()
            return self._request("start")
        except Exception:
            self._rollback_startup()
            raise

    def _backup(self):
        require(self._worker is not None, "Start the console before creating a backup")
        was_unlocked = self._signer is not None
        require(was_unlocked or self._metadata.get("signer_clean") is True, "Backup requires a clean signer shutdown checkpoint")
        self._stop_signer()  # clean final checkpoint is mandatory before reading ciphertext
        try:
            manifest = self._request("manifest")
            manifest = validate_manifest(manifest)
            chain = self._retain_chain()
            require(chain is not None, "Public chain snapshot unavailable")
            script = 'import os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;data=os.read(fd,168);assert len(data)==167;sys.stdout.buffer.write(data);os.close(fd)'
            ciphertext = self._invoke("1000:1000", "python3", "-c", script, self._metadata["signer_dir"] + "/wallet/wallet.dat")
            require(len(ciphertext) == 167, "Encrypted wallet record must be exactly 167 bytes")
            value = {"schema": SCHEMA, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "identity": self._metadata["identity"], "checkpoint": self._metadata["checkpoint"],
                     "manifest": manifest, "chain": chain, "ciphertext": ciphertext.hex()}
            value["sha256"] = hashlib.sha256(canonical(value)).hexdigest()
            validate_bundle(value, self._metadata["identity"])
            backup_id = uuid.uuid4().hex
            self._write_json("backups/" + backup_id + ".json", value)
            item = {"id": backup_id, "created_at": value["created_at"], "height": len(chain["blocks"]), "wallet_id": manifest["wallet_id"]}
            self._metadata["backups"].append(item)
            self._save()
            return item
        finally:
            if was_unlocked:
                self._start_signer()

    def _recover(self, backup_id):
        value = self._read_json("backups/" + backup_id + ".json")
        container_id, identity = self._prepare()
        value = validate_bundle(value, identity)  # complete validation precedes any stop
        self._verify_session_storage(container_id, identity, replacing=True)
        retained = self._metadata["retained"].get(value["manifest"]["wallet_id"], {})
        manifest = merge_manifests(value["manifest"], retained["manifest"]) if retained.get("manifest") else value["manifest"]
        latest_chain = self._retain_chain()
        chain = value["chain"]
        retained_file = self.state_dir / ("chain-" + manifest["wallet_id"] + ".json")
        if retained_file.exists():
            retained_chain = self._read_json(retained_file.name)
            require(retained_chain.get("identity") == identity, "Retained chain native identity mismatch")
            chain = self._merge_chains(chain, retained_chain["chain"])
        if latest_chain is not None:
            chain = self._merge_chains(chain, latest_chain)
        point = self._floors(value["checkpoint"])
        for field in ("next_receive", "next_change"):
            manifest[field] = max(manifest[field], point[field])
        self._stop_worker()
        self._stop_signer()
        self._metadata.update(container_id=container_id, identity=identity, checkpoint=point, manifest=manifest)
        try:
            self._setup_paths(fresh=True)
            self._invoke("1000:1000", "python3", "-c", 'import os,sys;data=sys.stdin.buffer.read(168);assert len(data)==167;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,data);os.fsync(fd);os.close(fd)',
                         self._metadata["signer_dir"] + "/wallet/wallet.dat", data=bytes.fromhex(value["ciphertext"]))
            self._start_signer()
            self._start_worker()
            self._request("import_chain", chain)
            self._request("import_manifest", {"manifest": manifest})
            return {"id": backup_id, "wallet_id": manifest["wallet_id"], "restored_height": len(chain["blocks"])}
        except Exception:
            self._rollback_startup()
            raise

    def action(self, name, params=None):
        with self._mutex:
            params = {} if params is None else params
            self._params(name, params)
            try:
                if name == "start":
                    result = self._start()
                elif name == "stop":
                    self._stop_worker()
                    self._stop_signer()
                    result = {"stopped": True}
                    self._last["wallet"]["locked"] = True
                elif name == "backup":
                    result = self._backup()
                elif name == "recover":
                    result = self._recover(params["backup_id"])
                elif name == "lock":
                    result = self._request("lock")
                    self._stop_signer()
                elif name == "unlock":
                    require(self._worker is not None, "Start the console before unlocking")
                    require(self._signer is None, "Wallet is already unlocked")
                    self._start_signer()
                    result = {"unlocked": True}
                elif name == "status":
                    result = None
                else:
                    require(self._signer is not None and self._signer.poll() is None, "Unlock the fixture wallet first")
                    result = self._request(name, params)
                    if name in ("fund", "mine"):
                        self._retain_chain()
                if name != "status":
                    self._event(name, {"start": "Offline console started", "stop": "Console stopped", "receive": "New test receive address saved",
                                      "fund": "Test funding transaction created", "send": "Test transaction broadcast", "mine": "Test blocks mined",
                                      "backup": "Encrypted backup saved", "recover": "Encrypted backup restored with retained address floors",
                                      "lock": "Fixture wallet locked", "unlock": "Fixture wallet unlocked"}[name],
                                result.get("txid") if isinstance(result, dict) else None)
                return {"status": self.status(), "result": result}
            except ConsoleError:
                self._save()
                raise
            except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                self._last["phase"], self._last["ready"] = "error", False
                self._save()
                raise ConsoleError("Console operation failed; retained files and encrypted backups are preserved") from error

    def close(self):
        with self._mutex:
            failure = None
            try:
                self._stop_worker()
            except ConsoleError as error:
                failure = error
            try:
                self._stop_signer()
            except ConsoleError as error:
                failure = failure or error
            self._last["phase"], self._last["ready"] = "stopped", False
            self._last["wallet"]["locked"] = True
            self._save()
            if failure:
                raise failure
