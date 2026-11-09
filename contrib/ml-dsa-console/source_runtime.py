#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Provision an offline runtime exclusively from a freshly built source image."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import uuid

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("console_source_legacy", HERE / "durable.py")
_legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)
IPC_TMPFS = _legacy.IPC_TMPFS
MANIFEST = "/opt/pqbtc-runtime/manifest.json"
MARKER = "/tmp/.pqbtc-source-runtime-v1.json"
VOLUME_SCHEMA = "PQBTC-MLDSA44-SOURCE-VOLUME-1"
DESCRIPTOR_SCHEMA = "PQBTC-MLDSA44-SOURCE-RUNTIME-1"
REQUIRED_HASHES = (
    "/tmp/mldsa-demo-build/bin/pqbtcd", "/tmp/mldsa-demo-build/bin/pqbtc-cli",
    "/tmp/mldsa-demo-build/bin/pqbtc-mldsa-client", "/tmp/mldsa-demo-build/bin/test_pqbtc",
    "/tmp/demo-signer-bin/pilot-signer",
    "/tmp/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md",
    "/tmp/mldsa-demo-source/contrib/ml-dsa-signer/node_wallet.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def validate_descriptor(value):
    require(type(value) is dict and set(value) == {"schema", "image", "manifest", "manifest_sha256"},
            "Invalid source runtime descriptor members")
    require(value["schema"] == DESCRIPTOR_SCHEMA and type(value["image"]) is str and
            re.fullmatch(r"sha256:[0-9a-f]{64}", value["image"]), "Source runtime requires an exact image identity")
    manifest = value["manifest"]
    require(type(manifest) is dict and manifest.get("schema") == "PQBTC-MLDSA44-SOURCE-BUILD-1",
            "Invalid source build manifest")
    for field in ("source_head", "source_tree"):
        require(type(manifest.get(field)) is str and re.fullmatch("[0-9a-f]{40}", manifest[field]), "Invalid source Git identity")
    require(manifest.get("compiler") in ("gcc", "clang") and manifest.get("architecture") in ("aarch64", "x86_64", "arm64", "amd64"),
            "Unsupported source runtime compiler or architecture")
    hashes = manifest.get("sha256")
    require(type(hashes) is dict and set(REQUIRED_HASHES) <= set(hashes), "Required native source-build hashes are missing")
    require(all(type(path) is str and type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest)
                for path, digest in hashes.items()), "Invalid native source-build digest")
    require(type(value["manifest_sha256"]) is str and
            hashlib.sha256(canonical(manifest)).hexdigest() == value["manifest_sha256"], "Source build manifest checksum does not match")
    return copy.deepcopy(value)


def labels(descriptor):
    value = validate_descriptor(descriptor)
    return {"org.pqbtc.console.build": "source-1", "org.pqbtc.console.schema": "source-1", "org.pqbtc.console.source": value["manifest"]["source_head"],
            "org.pqbtc.console.manifest": value["manifest_sha256"]}


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "Console state directory must be owned by you with mode 0700")
    return path


def load_descriptor(path, *, private=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    info.st_size <= 4 * 1024 * 1024 and stat.S_IMODE(info.st_mode) & 0o022 == 0 and
                    (not private or stat.S_IMODE(info.st_mode) == 0o600), "Unsafe source runtime descriptor file")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                value = _legacy.parsed(handle.read(4 * 1024 * 1024 + 1))
        finally:
            os.close(fd)
        return validate_descriptor(value)
    except OSError as error:
        raise ValueError("Source runtime descriptor could not be safely opened") from error


def save_descriptor(path, value):
    value = validate_descriptor(value)
    path = Path(path)
    if path.exists() or path.is_symlink():
        require(load_descriptor(path, private=True) == value, "Saved source runtime descriptor changed; wallet was not replaced")
        return
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(canonical(value))
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


class SourceManager(_legacy.RuntimeManager):
    def __init__(self, container="pqbtc-mldsa-local", volume=None):
        super().__init__(container=container, volume=volume)
        self.descriptor = None

    def _image_manifest(self):
        script = ('import os,stat,sys;p=' + repr(MANIFEST) + ';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);'
                  's=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and '
                  'stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=4194304;'
                  'data=os.read(fd,4194305);assert len(data)<=4194304;os.close(fd);sys.stdout.buffer.write(data)')
        result = self._run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges", "--user", "1001:1000", self.descriptor["image"], "python3", "-c", script])
        require(hashlib.sha256(result.stdout).hexdigest() == self.descriptor["manifest_sha256"] and
                _legacy.parsed(result.stdout) == self.descriptor["manifest"], "Built image does not match its source descriptor")

    def _volume(self):
        result = self._run(["docker", "volume", "inspect", self.volume], check=False)
        if result.returncode:
            return None
        value = _legacy.parsed(result.stdout)
        require(value.get("Name") == self.volume and value.get("Driver") == "local" and
                value.get("Options") in (None, {}) and value.get("Labels") == labels(self.descriptor),
                "Existing volume is not this source runtime; it was preserved")
        return value

    def _read_marker(self):
        script = ('import os,stat,sys;p=' + repr(MARKER) + ';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);'
                  's=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and '
                  'stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=4096;'
                  'data=os.read(fd,4097);assert len(data)<=4096;os.close(fd);sys.stdout.buffer.write(data)')
        result = self._run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges", "--user", "1001:1000", "--mount",
                            "type=volume,source=" + self.volume + ",target=/tmp,readonly,volume-nocopy", self.descriptor["image"], "python3", "-c", script])
        marker = _legacy.parsed(result.stdout)
        require(set(marker) == {"schema", "volume_id", "source_head", "manifest_sha256"} and marker["schema"] == VOLUME_SCHEMA and
                marker["source_head"] == self.descriptor["manifest"]["source_head"] and
                marker["manifest_sha256"] == self.descriptor["manifest_sha256"] and type(marker["volume_id"]) is str and
                re.fullmatch("[0-9a-f]{32}", marker["volume_id"]), "Source runtime volume identity does not match")
        return marker

    def _require_seed_only_volume(self):
        # The native directories survive even if host metadata is lost. A new
        # random wallet must never silently replace the user's visible session.
        script = ('import json,os,re;custody_state=False;'
                  '\nwith os.scandir("/tmp") as entries:\n'
                  ' for count,entry in enumerate(entries):\n'
                  '  assert count<4096, "Runtime namespace needs inspection"\n'
                  '  if re.fullmatch(r"mldsa-console-(?:signer|node|code)-[a-zA-Z0-9_]+",entry.name):\n'
                  '   custody_state=True;break\n'
                  'print(json.dumps({"custody_state":custody_state}))')
        result = self._run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges", "--user", "1001:1000", "--mount",
                            "type=volume,source=" + self.volume + ",target=/tmp,readonly,volume-nocopy", self.descriptor["image"], "python3", "-c", script])
        value = _legacy.parsed(result.stdout)
        require(value == {"custody_state": False},
                "Host session metadata is missing while durable wallet state remains; restore the retained host metadata before launching")

    def _layout(self, config):
        host = config.get("HostConfig", {})
        require(config.get("Image") == self.descriptor["image"] and config.get("Config", {}).get("Labels") == labels(self.descriptor) and
                host.get("ReadonlyRootfs") is True and host.get("NetworkMode") == "none" and
                host.get("Memory") == 4294967296 and host.get("NanoCpus") == 4000000000 and
                host.get("CapDrop") == ["ALL"] and host.get("CapAdd") in (None, []) and
                host.get("SecurityOpt") == ["no-new-privileges"] and host.get("Privileged") is False and
                host.get("Tmpfs") == IPC_TMPFS and host.get("RestartPolicy", {}).get("Name") == "no",
                "Source runtime isolation or image identity does not match")
        mounts = config.get("Mounts", [])
        require(type(mounts) is list and len(mounts) == 1 and mounts[0].get("Type") == "volume" and
                mounts[0].get("Name") == self.volume and mounts[0].get("Destination") == "/tmp" and mounts[0].get("RW") is True,
                "Source runtime requires only its named data volume")

    def _bootstrap_source(self, progress):
        command = ["docker", "volume", "create"]
        for key, value in labels(self.descriptor).items():
            command += ["--label", key + "=" + value]
        self._run([*command, self.volume])
        self._volume()
        helper = self.container + "-source-init-" + uuid.uuid4().hex[:8]
        progress("Initializing a fresh durable volume from the source-built image…")
        command = ["docker", "run", "--detach", "--name", helper, "--network", "none", "--read-only", "--user", "0:0",
                   "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE",
                   "--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "4294967296", "--mount",
                   "type=volume,source=" + self.volume + ",target=/tmp,volume-nocopy", self.descriptor["image"], "sleep", "infinity"]
        created = False
        try:
            self._run(command)
            created = True
            self._run(["docker", "exec", helper, "python3", "-c",
                       'import pathlib,os;assert not any(pathlib.Path("/tmp").iterdir()), "Volume is not empty";os.chmod("/tmp",0o1777)'])
            self._run(["docker", "exec", helper, "cp", "-a", "/opt/pqbtc-runtime/seed/.", "/tmp/"], timeout=180)
            # cp -a also preserves seed/.'s directory mode on its destination.
            self._run(["docker", "exec", helper, "chmod", "1777", "/tmp"])
            self._run(["docker", "exec", helper, "sync", "-f", "/tmp"], timeout=120)
            marker = {"schema": VOLUME_SCHEMA, "volume_id": uuid.uuid4().hex,
                      "source_head": self.descriptor["manifest"]["source_head"], "manifest_sha256": self.descriptor["manifest_sha256"]}
            script = ('import hashlib,json,os,pathlib,subprocess,sys;manifest=json.loads(sys.argv[1]);marker=json.loads(sys.argv[2]);'
                      'assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in manifest["sha256"].items());'
                      'git=["git","-c","safe.directory=/tmp/mldsa-demo-source","-C","/tmp/mldsa-demo-source"];'
                      'assert subprocess.check_output(git+["rev-parse","HEAD"],text=True).strip()==manifest["source_head"];'
                      'assert subprocess.check_output(git+["rev-parse","HEAD^{tree}"],text=True).strip()==manifest["source_tree"];'
                      'assert not subprocess.check_output(git+["status","--porcelain"]);'
                      'fd=os.open(sys.argv[3],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644);os.fchmod(fd,0o644);'
                      'os.write(fd,(json.dumps(marker,sort_keys=True,separators=(",",":"))+"\\n").encode());os.fsync(fd);os.close(fd);'
                      'fd=os.open("/tmp",os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
            self._run(["docker", "exec", helper, "python3", "-c", script, json.dumps(self.descriptor["manifest"]), json.dumps(marker), MARKER], timeout=120)
        except Exception as error:
            raise ValueError("Source runtime initialization failed; the incomplete volume and existing wallets were preserved. " + str(error)) from error
        finally:
            if created:
                self._run(["docker", "rm", "--force", helper], check=False)

    def _create(self):
        command = ["docker", "create", "--name", self.container, "--network", "none", "--read-only", "--cpus", "4",
                   "--memory", "4294967296", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no"]
        for key, value in labels(self.descriptor).items():
            command += ["--label", key + "=" + value]
        command += ["--mount", "type=volume,source=" + self.volume + ",target=/tmp,volume-nocopy", "--tmpfs",
                    "/run/pqbtc-ipc:" + IPC_TMPFS["/run/pqbtc-ipc"], self.descriptor["image"], "sleep", "infinity"]
        self._run(command)

    def _build_image(self, repo, *, compiler, no_cache, progress):
        spec = importlib.util.spec_from_file_location("console_source_builder", HERE / "source_build.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        return builder.build_image(repo, compiler=compiler, no_cache=no_cache, progress=progress)

    def ensure(self, state_dir, *, repo=None, compiler="gcc", descriptor=None, no_cache=False, progress=print):
        state = private_directory(state_dir)
        fd = os.open(state / ".runtime-setup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, "Unsafe source runtime installation lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError("Another source runtime installation is running; wait and relaunch") from error
            return self._ensure(state, repo=repo, compiler=compiler, descriptor=descriptor, no_cache=no_cache, progress=progress)
        finally:
            os.close(fd)

    def _ensure(self, state, *, repo, compiler, descriptor, no_cache, progress):
        saved = state / "runtime.json"
        prior = load_descriptor(saved, private=True) if saved.exists() or saved.is_symlink() else None
        if descriptor is not None:
            descriptor = validate_descriptor(descriptor)
            require(prior is None or prior == descriptor, "Saved source runtime descriptor changed; wallet was not replaced")
        else:
            descriptor = prior
        if descriptor is None:
            require(not (state / "session.json").exists() and not (state / "session.json").is_symlink(),
                    "Existing wallet needs its retained source runtime descriptor for recovery")
        self._daemon(progress)
        if descriptor is None:
            descriptor = self._build_image(Path(repo or HERE.parents[1]), compiler=compiler, no_cache=no_cache, progress=progress)
        self.descriptor = validate_descriptor(descriptor)
        self._image_manifest()
        volume = self._volume()
        if volume is None:
            require(not (state / "session.json").exists() and not (state / "session.json").is_symlink(),
                    "Existing wallet volume is missing; recover retained state rather than replacing the wallet")
            self._bootstrap_source(progress)
        elif not (state / "session.json").exists() and not (state / "session.json").is_symlink():
            self._require_seed_only_volume()
        save_descriptor(saved, self.descriptor)
        marker = self._read_marker()
        config = self._inspect(self.container)
        if config is None:
            progress("Creating the isolated source-built runtime…")
            self._create()
            config = self._inspect(self.container)
            require(config is not None, "Source runtime container was not created")
        self._layout(config)
        if config.get("State", {}).get("Running") is not True:
            self._run(["docker", "start", self.container])
        return {"container": self.container, "volume": self.volume, "volume_id": marker["volume_id"],
                "runtime_descriptor": copy.deepcopy(self.descriptor)}
