#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Start the isolated durable fixture; copy only its qualified public/test state.

The migration streams encrypted fixture records directly between Linux
containers. No native prototype binary or plaintext key is opened on the host.
Existing unrecognized or incomplete volumes are preserved and refused.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

HEAD = "9f4b20a938e67ef985df0780fb41b6035abef15e"
IMAGE = "sha256:767891744587d93faf96d0f9d8ce2c66ebe3a73695b2a7389f82b62735b8ad3a"
SCHEMA = "PQBTC-MLDSA44-DURABLE-RUNTIME-1"
LABELS = {"org.pqbtc.console.schema": "durable-1", "org.pqbtc.console.source": HEAD}
IPC_TMPFS = {"/run/pqbtc-ipc": "rw,noexec,nosuid,nodev,size=1048576,mode=1777"}
MARKER = "/tmp/.pqbtc-runtime-v1.json"
MIGRATION = "/tmp/.pqbtc-migration-v1.json"
NATIVE = {
    "/tmp/mldsa-demo-build/bin/pqbtcd": "bb55d172508ed47727334f37be374dd34c67ecb42b2cceabae4a7b1d1a575159",
    "/tmp/mldsa-demo-build/bin/pqbtc-mldsa-client": "727e654e4ba692c21c6e259eea0f11838f88ff866a08843907f272395f741317",
    "/tmp/demo-signer-bin/pilot-signer": "e0b0aea159a0e39704314df63298b9d21d85bfeed21e86e98cab7a41ea70846c",
}
INSPECT = ('{"Id":{{json .Id}},"Image":{{json .Image}},"State":{"Running":{{json .State.Running}}},'
           '"Config":{"Labels":{{json .Config.Labels}}},"Mounts":{{json .Mounts}},"HostConfig":{'
           '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"NetworkMode":{{json .HostConfig.NetworkMode}},'
           '"Memory":{{json .HostConfig.Memory}},"NanoCpus":{{json .HostConfig.NanoCpus}},'
           '"CapDrop":{{json .HostConfig.CapDrop}},"CapAdd":{{json .HostConfig.CapAdd}},'
           '"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Privileged":{{json .HostConfig.Privileged}},'
           '"Tmpfs":{{json .HostConfig.Tmpfs}},"RestartPolicy":{{json .HostConfig.RestartPolicy}}}}')


class RuntimeError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate runtime JSON member")
        value[key] = item
    return value


def parsed(raw):
    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
        if type(value) is list and len(value) == 1:
            value = value[0]
        require(type(value) is dict, "Runtime metadata must be an object")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise RuntimeError("Runtime metadata could not be validated") from error


class RuntimeManager:
    def __init__(self, container="pqbtc-mldsa-local", volume=None, seed_container="pqbtc-mldsa-demo-20261109"):
        self.container, self.volume = container, volume or container + "-data-v1"
        self.seed_container = seed_container
        for name in (self.container, self.volume, self.seed_container):
            require(type(name) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}", name),
                    "Invalid managed Docker name")

    @staticmethod
    def _run(command, *, data=None, check=True, timeout=30):
        try:
            result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Docker runtime command is unavailable or timed out") from error
        require(not check or result.returncode == 0,
                "Docker runtime command failed: " + result.stderr[:600].decode("utf8", "replace"))
        return result

    def _daemon(self, progress):
        command = ["docker", "info", "--format", "{{json .ServerVersion}}"]
        if self._run(command, check=False, timeout=10).returncode == 0:
            return
        progress("Starting Docker Desktop; waiting for its Linux engine…")
        self._run(["docker", "desktop", "start", "--timeout", "120"], timeout=130)
        deadline = time.monotonic() + 120
        while self._run(command, check=False, timeout=10).returncode:
            require(time.monotonic() < deadline, "Docker Desktop did not become ready; host backups are preserved")
            time.sleep(1)

    def _inspect(self, name):
        result = self._run(["docker", "inspect", "--format", INSPECT, name], check=False)
        return parsed(result.stdout) if result.returncode == 0 else None

    def _volume(self):
        result = self._run(["docker", "volume", "inspect", self.volume], check=False)
        if result.returncode:
            return None
        value = parsed(result.stdout)
        require(value.get("Name") == self.volume and value.get("Driver") == "local" and
                value.get("Options") in (None, {}) and value.get("Labels") == LABELS,
                "Existing Docker volume is not the managed fixture; it was preserved")
        return value

    def _layout(self, config):
        host = config.get("HostConfig", {})
        require(config.get("Image") == IMAGE and config.get("Config", {}).get("Labels") == LABELS and
                host.get("ReadonlyRootfs") is True and host.get("NetworkMode") == "none" and
                host.get("Memory") == 4294967296 and host.get("NanoCpus") == 4000000000 and
                host.get("CapDrop") == ["ALL"] and host.get("CapAdd") in (None, []) and
                host.get("SecurityOpt") == ["no-new-privileges"] and host.get("Privileged") is False and
                host.get("Tmpfs") == IPC_TMPFS and host.get("RestartPolicy", {}).get("Name") == "no",
                "Managed container isolation does not match the durable fixture")
        mounts = config.get("Mounts", [])
        require(type(mounts) is list and len(mounts) == 1 and mounts[0].get("Type") == "volume" and
                mounts[0].get("Name") == self.volume and mounts[0].get("Destination") == "/tmp" and
                mounts[0].get("RW") is True, "Managed container volume layout was refused")

    def _read_marker(self):
        script = ('import json,os,stat; p=' + repr(MARKER) + ';s=os.lstat(p);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and '
                  'stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=4096;'
                  'fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);print(os.read(fd,4097).decode());os.close(fd)')
        command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", "1001:1000",
                   "--mount", "type=volume,source=" + self.volume + ",target=/tmp,readonly", IMAGE, "python3", "-c", script]
        result = self._run(command, check=False)
        require(result.returncode == 0, "Durable volume is incomplete or its marker is unsafe; it was preserved")
        value = parsed(result.stdout)
        require(set(value) == {"schema", "volume_id", "source_head"} and value["schema"] == SCHEMA and
                value["source_head"] == HEAD and type(value["volume_id"]) is str and
                re.fullmatch("[0-9a-f]{32}", value["volume_id"]), "Durable runtime marker does not match the qualified fixture")
        return value

    @staticmethod
    def _migration_state(state_dir):
        directory = Path(state_dir)
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise RuntimeError("Console migration directory could not be safely created") from error
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Console state directory must be owned by you with mode 0700")
        path = directory / "session.json"
        if not path.exists() and not path.is_symlink():
            return {}
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 24 * 1024 * 1024,
                        "Console migration metadata ownership/mode/size was refused")
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    metadata = parsed(handle.read(24 * 1024 * 1024 + 1))
            finally:
                os.close(fd)
        except OSError as error:
            raise RuntimeError("Console migration metadata could not be safely opened") from error
        if "checkpoint" not in metadata:
            require(not any(field in metadata for field in ("signer_dir", "node_dir", "code_dir")),
                    "Incomplete console session needs inspection before migration")
            return {}
        result = {}
        for role in ("signer", "node", "code"):
            value = metadata.get(role + "_dir")
            require(type(value) is str and re.fullmatch(r"/tmp/mldsa-console-" + role + r"-[a-zA-Z0-9_]+", value),
                    "Selected console " + role + " directory is invalid")
            result[role + "_dir"] = value
        point = metadata["checkpoint"]
        require(type(point) is dict and type(point.get("wallet_id")) is str and
                re.fullmatch("[0-9a-f]{32}", point["wallet_id"]), "Selected fixture wallet identity is invalid")
        require(type(metadata.get("container_id")) is str, "Selected fixture container identity is missing")
        require(metadata.get("signer_clean") is True, "Stop the local wallet cleanly before its first durable migration")
        result.update(wallet_id=point["wallet_id"], old_container_id=metadata["container_id"])
        return result

    def _copy_stream(self, helper, uid, paths):
        source = ["docker", "exec", "--user", str(uid) + ":1000", self.seed_container,
                  "tar", "--format=posix", "-C", "/tmp", "-cf", "-", "--", *paths]
        target = ["docker", "exec", "-i", "--user", "0:0", helper,
                  "tar", "-C", "/tmp", "--same-owner", "--same-permissions", "-xf", "-"]
        # The pipe never exposes archive bytes to host Python or its output.
        producer = subprocess.Popen(source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        consumer = None
        try:
            consumer = subprocess.Popen(target, stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            producer.stdout.close()
            _, output_error = consumer.communicate(timeout=180)
            _, input_error = producer.communicate(timeout=30)
            require(producer.returncode == 0 and consumer.returncode == 0,
                    "Contained migration stream failed: " + (input_error + output_error)[:600].decode("utf8", "replace"))
        except (OSError, subprocess.TimeoutExpired) as error:
            # These are short-lived archive helpers, never node/signer owners.
            if consumer is not None:
                consumer.kill()
                consumer.communicate()
            producer.kill()
            producer.communicate()
            raise RuntimeError("Contained migration archive timed out or failed") from error

    def _bootstrap(self, state_dir, seed, progress):
        selected = self._migration_state(state_dir)
        require(not selected or selected["old_container_id"] == seed.get("Id"),
                "Selected wallet does not belong to the prepared seed container")
        host = seed.get("HostConfig", {})
        require(seed.get("State", {}).get("Running") is True and seed.get("Image") == IMAGE and
                host.get("ReadonlyRootfs") is True and host.get("NetworkMode") == "none" and
                host.get("CapDrop") == ["ALL"] and host.get("SecurityOpt") == ["no-new-privileges"],
                "Prepared seed container is unavailable or its isolation does not match")
        binds = [item for item in seed.get("Mounts", []) if item.get("Destination") == "/source-git" and
                 item.get("Type") == "bind" and item.get("RW") is False]
        require(len(binds) == 1 and type(binds[0].get("Source")) is str and binds[0]["Source"].startswith("/"),
                "Prepared seed git object source is unavailable")
        idle = ('import pathlib; names=[p.read_text().strip() for p in pathlib.Path("/proc").glob("[0-9]*/comm")];'
                'assert not any(n in ("pqbtcd","pilot-signer") for n in names), "Stop the local wallet before migration"')
        self._run(["docker", "exec", "--user", "1001:1000", self.seed_container, "python3", "-c", idle])
        command = ["docker", "volume", "create"]
        for key, value in LABELS.items():
            command += ["--label", key + "=" + value]
        self._run([*command, self.volume])
        require(self._volume() is not None, "New volume ownership could not be verified")
        helper = self.container + "-bootstrap-" + uuid.uuid4().hex[:8]
        progress("Copying the qualified Linux runtime and selected wallet into durable storage…")
        helper_command = ["docker", "run", "--detach", "--name", helper, "--user", "0:0", "--network", "none", "--read-only", "--cap-drop", "ALL"]
        for capability in ("CHOWN", "FOWNER", "DAC_OVERRIDE"):
            helper_command += ["--cap-add", capability]
        helper_command += ["--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "4294967296",
                           "--mount", "type=volume,source=" + self.volume + ",target=/tmp",
                           "--mount", "type=bind,source=" + binds[0]["Source"] + ",target=/source-git,readonly",
                           IMAGE, "sleep", "infinity"]
        created = False
        try:
            self._run(helper_command)
            created = True
            empty = 'import os,pathlib;assert not any(pathlib.Path("/tmp").iterdir()), "Refusing to overwrite nonempty migration volume";os.chmod("/tmp",0o1777)'
            self._run(["docker", "exec", helper, "python3", "-c", empty])
            signer_paths = ["demo-signer-bin/pilot-signer"]
            public_paths = ["mldsa-demo-source", "mldsa-demo-build/bin"]
            if selected:
                signer_paths += [selected["signer_dir"].removeprefix("/tmp/")]
                public_paths += [selected[field].removeprefix("/tmp/") for field in ("node_dir", "code_dir")]
            self._copy_stream(helper, 1000, signer_paths)
            self._copy_stream(helper, 1001, public_paths)
            # Only the new copied .git is changed. Materialize shared objects
            # before removing its alternates dependency on the host checkout.
            git = ["docker", "exec", helper, "git", "-c", "safe.directory=/tmp/mldsa-demo-source", "-C", "/tmp/mldsa-demo-source"]
            self._run([*git, "repack", "-a", "-d"], timeout=120)
            detach = 'from pathlib import Path;p=Path("/tmp/mldsa-demo-source/.git/objects/info/alternates");p.unlink() if p.exists() else None'
            self._run(["docker", "exec", helper, "python3", "-c", detach])
            self._run([*git, "fsck", "--connectivity-only"], timeout=120)
            # Archive close is not a durability barrier. Flush the volume before
            # publishing the fsynced completion marker used by later launches.
            self._run(["docker", "exec", helper, "sync", "-f", "/tmp"], timeout=120)
            marker = {"schema": SCHEMA, "source_head": HEAD, "volume_id": uuid.uuid4().hex}
            script = ('import hashlib,json,os,pathlib,stat,subprocess,sys;'
                      'native=json.loads(sys.argv[1]); selected=json.loads(sys.argv[2]); marker=json.loads(sys.argv[3]);'
                      'git=["git","-c","safe.directory=/tmp/mldsa-demo-source","-C","/tmp/mldsa-demo-source"];'
                      'assert subprocess.check_output(git+["rev-parse","HEAD"],text=True,encoding="utf8").strip()==marker["source_head"];'
                      'assert not subprocess.check_output(git+["status","--porcelain"]);'
                      'assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==digest for p,digest in native.items());'
                      'migration=None;'
                      '\nif selected:\n'
                      ' for k,uid,mode in (("signer_dir",1000,0o750),("node_dir",1001,0o700),("code_dir",1001,0o700)):\n'
                      '  s=os.lstat(selected[k]);assert stat.S_ISDIR(s.st_mode) and s.st_uid==uid and stat.S_IMODE(s.st_mode)==mode\n'
                      ' p=pathlib.Path(selected["signer_dir"])/"wallet/wallet.dat";s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167\n'
                      ' migration={"schema":"PQBTC-MLDSA44-DURABLE-MIGRATION-1",**selected,"wallet_sha256":hashlib.sha256(p.read_bytes()).hexdigest()}\n'
                      'def publish(path,value):\n'
                      ' fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644);os.fchmod(fd,0o644);os.write(fd,(json.dumps(value,sort_keys=True)+"\\n").encode());os.fsync(fd);os.close(fd)\n'
                      'if migration: publish(sys.argv[4],migration)\n'
                      'publish(sys.argv[5],marker)\n'
                      'fd=os.open("/tmp",os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
            self._run(["docker", "exec", helper, "python3", "-c", script, json.dumps(NATIVE), json.dumps(selected),
                       json.dumps(marker), MIGRATION, MARKER], timeout=120)
        except Exception as error:
            raise RuntimeError("Durable migration did not complete; the seed and host backups are preserved. "
                               "The incomplete volume was retained for inspection. " + str(error)) from error
        finally:
            if created:
                self._run(["docker", "rm", "--force", helper], check=False)

    def _create(self):
        command = ["docker", "create", "--name", self.container, "--network", "none", "--read-only", "--cpus", "4",
                   "--memory", "4294967296", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no"]
        for key, value in LABELS.items():
            command += ["--label", key + "=" + value]
        command += ["--mount", "type=volume,source=" + self.volume + ",target=/tmp", "--tmpfs",
                    "/run/pqbtc-ipc:" + IPC_TMPFS["/run/pqbtc-ipc"], IMAGE, "sleep", "infinity"]
        self._run(command)

    def ensure(self, state_dir, progress=print):
        self._daemon(progress)
        if self._volume() is None:
            seed = self._inspect(self.seed_container)
            require(seed is not None, "Prepared seed runtime is missing; refusing to replace an existing wallet or invent a native build")
            self._bootstrap(state_dir, seed, progress)
            require(self._volume() is not None, "Durable volume was not created")
        marker = self._read_marker()
        config = self._inspect(self.container)
        if config is None:
            progress("Recreating the isolated container around its existing durable volume…")
            self._create()
            config = self._inspect(self.container)
            require(config is not None, "Managed container was not created")
        self._layout(config)
        if config.get("State", {}).get("Running") is not True:
            progress("Starting the isolated Bitcoin runtime…")
            self._run(["docker", "start", self.container])
        return {"container": self.container, "volume": self.volume, "volume_id": marker["volume_id"]}
