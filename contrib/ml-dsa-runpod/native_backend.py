#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Native TEST wallet backend inside one independently identified provider pod.

This deliberately supplies no Docker-shaped identities or isolation receipts.
The provider owns the outer container; this backend owns native process sessions,
immutable payload selection and the existing public wallet recovery journal.
"""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import uuid

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module("runpod_native_exec", HERE / "native_exec.py")
public = module("runpod_public_controller", HERE.parent / "ml-dsa-console/public_controller.py")
require = public.require
SCHEMA = "PQBTC-RUNPOD-PAYLOAD-1"
VERSIONS = {
    "a3": ("a4777f3beabc0f1d67e4c340dff1bca522446d3f", "270db235c95ccf367fae9add30aa48244a4ab6a0"),
    "c": ("872da133db255e2188f74ebc5164ecbca620ee6e", "09adc01686c11ad83ac275e881af02b77d12b963"),
}
REQUIRED = {
    "seed/mldsa-demo-build/bin/pqbtcd",
    "seed/mldsa-demo-build/bin/pqbtc-mldsa-client",
    "seed/demo-signer-bin/pilot-signer",
    "seed/mldsa-demo-source/contrib/ml-dsa-console/public_runtime.py",
    "seed/mldsa-demo-source/contrib/ml-dsa-signer/node_wallet.py",
    "seed/mldsa-demo-source/docs/ML_DSA_44_PUBLIC_TEST_PROFILE.md",
    "seed/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md",
}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def validate_descriptor(value):
    required = {"schema", "version", "source_head", "source_tree", "manifest_sha256", "files"}
    require(type(value) is dict and required <= set(value) <= required | {"build_descriptor"} and
            value["schema"] == SCHEMA and value["version"] in VERSIONS,
            "Native payload descriptor shape refused")
    require((value["source_head"], value["source_tree"]) == VERSIONS[value["version"]],
            "Native payload is not one of the frozen source versions")
    require(type(value["manifest_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]),
            "Native payload build-manifest digest refused")
    files = value["files"]
    require(type(files) is dict and REQUIRED <= set(files) and len(files) <= 30000,
            "Native payload file closure is incomplete or exceeds its bound")
    for name, digest in files.items():
        require(type(name) is str and name.startswith("seed/") and len(name) <= 512 and
                not any(part in ("", ".", "..") for part in name.split("/")) and "\\" not in name and
                type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "Native payload file path/digest refused")
    if "build_descriptor" in value:
        build = public.source.validate_descriptor(value["build_descriptor"])
        require(build["manifest"]["source_head"] == value["source_head"] and
                build["manifest"]["source_tree"] == value["source_tree"] and
                build["manifest_sha256"] == value["manifest_sha256"], "Native payload/build provenance mismatch")
    return copy.deepcopy(value)


def payload_identity(value):
    value = validate_descriptor(value)
    result = {key: value[key] for key in ("version", "source_head", "source_tree", "manifest_sha256")}
    result.update(payload_sha256=hashlib.sha256(canonical(value)).hexdigest(),
                  node_sha256=value["files"]["seed/mldsa-demo-build/bin/pqbtcd"],
                  signer_sha256=value["files"]["seed/demo-signer-bin/pilot-signer"])
    return result


def owned_directory(path, owner=0):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "Native path must be absolute")
    for part in (path, *path.parents):
        info = part.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) & 0o022 == 0,
                "Native directory ancestry is not root-owned and protected")
    return path


class NativeManager(public.Files):
    """Fresh persistent data identity and immutable native-payload selection."""
    def __init__(self, state_dir, *, versions_root=Path("/opt/pqbtc-runpod/versions"),
                 runtime_root=Path("/opt/pqbtc-runtime"), data_root=Path("/var/lib/pqbtc"),
                 namespace="pqbtc-runpod-public"):
        super().__init__(state_dir)
        require(type(namespace) is str and re.fullmatch(r"pqbtc-runpod-[a-zA-Z0-9_.-]{1,64}", namespace),
                "Unsafe Runpod application namespace")
        self.namespace = namespace
        self.versions_root, self.runtime_root, self.data_root = map(Path, (versions_root, runtime_root, data_root))
        self.descriptor = None
        self.registry_path = self.state_dir / "native-processes.json"
        self.socket = Path("/run/pqbtc-ipc") / self.namespace / "signer.sock"

    def verify_payload(self, descriptor):
        descriptor = validate_descriptor(descriptor)
        root = owned_directory(self.versions_root / descriptor["version"])
        stored = native.read_json(root / "descriptor.json", private=False)
        require(stored == descriptor, "Native payload differs from the packaged descriptor")
        manifest = root / "manifest.json"
        metadata = manifest.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1 and
                stat.S_IMODE(metadata.st_mode) & 0o022 == 0 and metadata.st_size <= 4 * 1024 * 1024,
                "Unsafe native build manifest")
        raw = manifest.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == descriptor["manifest_sha256"], "Native build-manifest digest mismatch")
        build = json.loads(raw)
        require((build.get("source_head"), build.get("source_tree")) ==
                (descriptor["source_head"], descriptor["source_tree"]), "Native build source identity mismatch")
        expected_arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
        observed_arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(build.get("architecture"), build.get("architecture"))
        require(observed_arch == expected_arch, "Native payload architecture mismatch")
        observed = set()
        for entry in (root / "seed").rglob("*"):
            info = entry.lstat()
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) & 0o022 == 0 and
                    (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), "Unsafe native payload member")
            if stat.S_ISREG(info.st_mode):
                name = entry.relative_to(root).as_posix()
                require(name in descriptor["files"], "Unlisted native payload member")
                with entry.open("rb") as handle:
                    require(hashlib.file_digest(handle, "sha256").hexdigest() == descriptor["files"][name],
                            "Native payload file digest mismatch")
                observed.add(name)
        require(observed == set(descriptor["files"]), "Native payload file is missing")
        require(descriptor["files"]["seed/mldsa-demo-source/docs/ML_DSA_44_PUBLIC_TEST_PROFILE.md"] == public.PROFILE,
                "Native public TEST profile changed")
        require(descriptor["files"]["seed/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md"] == public.wallet.SPEC,
                "Native sealed wallet contract changed")
        return descriptor

    def _selected(self):
        path = self.runtime_root / "seed"
        if not path.exists() and not path.is_symlink():
            return None
        info = path.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0, "Native active selection is not an owned symlink")
        target = Path(os.readlink(path))
        for name in VERSIONS:
            if target == self.versions_root / name / "seed":
                return name
        raise ValueError("Native active selection points outside the frozen payloads")

    def _select(self, descriptor):
        owned_directory(self.runtime_root)
        current = self._selected()
        require(current is None or current in VERSIONS, "Native active selection refused")
        temporary = self.runtime_root / (".seed-" + uuid.uuid4().hex)
        os.symlink(str(self.versions_root / descriptor["version"] / "seed"), temporary)
        os.replace(temporary, self.runtime_root / "seed")
        fd = os.open(self.runtime_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _marker(self):
        return native.read_json(self.data_root / ".runpod-volume.json")

    def _fresh_volume(self):
        if not self.data_root.exists() and not self.data_root.is_symlink():
            owned_directory(self.data_root.parent)
            self.data_root.mkdir(mode=0o755)
        info = self.data_root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, "Native persistent mount ownership refused")
        present = set(self.data_root.iterdir())
        require(not present or present == {self.state_dir} and self.state_dir.parent == self.data_root,
                "Native data namespace is not fresh; existing data was preserved")
        os.chmod(self.data_root, 0o755)
        owned_directory(self.data_root)
        identity = {"schema": "PQBTC-RUNPOD-NATIVE-VOLUME-1", "namespace": self.namespace,
                    "volume_id": uuid.uuid4().hex, "profile_sha256": public.PROFILE}
        for name, uid in (("signer", 1000), ("node", 1001)):
            path = self.data_root / name
            path.mkdir(mode=0o700)
            os.chown(path, uid, 1000)
        native.write_json(self.data_root / ".runpod-volume.json", identity)
        return identity

    def _ensure_ipc(self):
        parent = self.socket.parent.parent
        parent.mkdir(mode=0o755, exist_ok=True)
        owned_directory(parent)
        path = self.socket.parent
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o750)
            os.chown(path, 1000, 1000)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000 and info.st_gid == 1000 and
                stat.S_IMODE(info.st_mode) == 0o750, "Native IPC directory ownership changed")

    def _verify_volume(self, prior):
        owned_directory(self.data_root)
        marker = self._marker()
        require(marker == {"schema": "PQBTC-RUNPOD-NATIVE-VOLUME-1", "namespace": self.namespace,
                           "volume_id": prior["volume_id"], "profile_sha256": public.PROFILE},
                "Native persistent-volume identity mismatch")
        for name, uid in (("signer", 1000), ("node", 1001)):
            info = (self.data_root / name).lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == 1000 and
                    stat.S_IMODE(info.st_mode) == 0o700, "Native persistent data layout changed")

    def ensure(self, descriptor=None):
        path = self.state_dir / "native-runtime.json"
        prior = self._read_json(path.name) if path.exists() or path.is_symlink() else None
        if prior is not None:
            require(type(prior) is dict and set(prior) == {"schema", "namespace", "volume_id", "data_root", "descriptor", "history"} and
                    prior["schema"] == "PQBTC-RUNPOD-NATIVE-RUNTIME-1" and prior["namespace"] == self.namespace and
                    prior["data_root"] == str(self.data_root) and type(prior["history"]) is list and
                    len(prior["history"]) <= 2, "Native runtime ownership changed")
            prior = self._reconcile_transition(prior)
            self._verify_volume(prior)
        candidate = validate_descriptor(descriptor or (prior or {}).get("descriptor"))
        require(prior is None or candidate == prior["descriptor"], "Use explicit native upgrade to change binaries")
        self.descriptor = self.verify_payload(candidate)
        if prior is None:
            require(not (self.data_root / ".runpod-volume.json").exists(), "Retained native data needs its original control journal")
            marker = self._fresh_volume()
            prior = {"schema": "PQBTC-RUNPOD-NATIVE-RUNTIME-1", "namespace": self.namespace,
                     "volume_id": marker["volume_id"], "data_root": str(self.data_root),
                     "descriptor": self.descriptor, "history": []}
            self._write_json(path.name, prior)
        selected = self._selected()
        require(selected in (None, candidate["version"]), "Native active payload conflicts with the retained journal")
        self._select(candidate)
        self._ensure_ipc()
        return copy.deepcopy(prior)

    def _reconcile_transition(self, prior):
        path = self.state_dir / "native-replacement.json"
        if not path.exists() and not path.is_symlink():
            return prior
        plan = self._read_json(path.name)
        require(type(plan) is dict and set(plan) == {"schema", "volume_id", "previous", "candidate"} and
                plan["schema"] == "PQBTC-RUNPOD-NATIVE-REPLACEMENT-1" and plan["volume_id"] == prior["volume_id"] and
                prior["descriptor"] in (plan["previous"], plan["candidate"]), "Native pending replacement identity mismatch")
        old, candidate = self.verify_payload(plan["previous"]), self.verify_payload(plan["candidate"])
        selected = self._selected()
        require(selected in (None, old["version"], candidate["version"]), "Unexpected native pending replacement payload")
        if selected == candidate["version"]:
            prior["descriptor"] = candidate
            if old not in prior["history"]:
                prior["history"].append(old)
        else:
            prior["descriptor"] = old
            self._select(old)
        self._write_json("native-runtime.json", prior)
        self._finish_transition()
        return prior

    def _finish_transition(self):
        os.rename(self.state_dir / "native-replacement.json",
                  self.state_dir / ("native-replacement-completed-" + uuid.uuid4().hex + ".json"))
        fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def upgrade(self, descriptor, *, rollback=False):
        prior = self.ensure()
        candidate = self.verify_payload(descriptor)
        old = prior["descriptor"]
        require(candidate["source_head"] != old["source_head"] and candidate["version"] != old["version"] and
                payload_identity(candidate)["node_sha256"] != payload_identity(old)["node_sha256"],
                "Native transition requires genuinely different source and node binaries")
        require(not rollback or candidate in prior["history"], "Native rollback requires a previously retained payload")
        self.emergency_stop()
        self._write_json("native-replacement.json", {"schema": "PQBTC-RUNPOD-NATIVE-REPLACEMENT-1",
                         "volume_id": prior["volume_id"], "previous": old, "candidate": candidate})
        self._select(candidate)
        if old not in prior["history"]:
            prior["history"].append(old)
        prior["descriptor"] = candidate
        self._write_json("native-runtime.json", prior)
        self._finish_transition()
        self.descriptor = candidate
        return {"previous_payload": payload_identity(old), "native_payload": payload_identity(candidate),
                "volume_id": prior["volume_id"], "data_rollback": False, "outer_provider_image_changed": False}

    def emergency_stop(self, signum=signal.SIGKILL):
        def stop(value):
            count = 0
            for record in value["groups"]:
                count += native.signal_members(record, signum)
            value["groups"] = [record for record in value["groups"] if native.verified_members(record)]
            require(not value["groups"], "Native process cleanup incomplete")
            return count
        count = native.with_registry(self.registry_path, self.namespace, stop)
        socket = self.socket
        if socket.exists() or socket.is_symlink():
            info = socket.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 1000 and info.st_gid == 1000,
                    "Uncertain native signer IPC entry was preserved")
            socket.unlink()
        return {"stopped_native_processes": count, "kind": "OWNED_NATIVE_APPLICATION_PROCESS_SESSIONS",
                "provider_container_stopped": False}

    def identity(self):
        require(self.descriptor is not None, "Native payload has not been selected")
        prior = self._read_json("native-runtime.json")
        self._verify_volume(prior)
        require(self._selected() == self.descriptor["version"] and prior["descriptor"] == self.descriptor,
                "Native identity selection mismatch")
        processes = []
        registry = native.registry(self.registry_path, self.namespace)
        for record in registry["groups"]:
            for item in native.verified_members(record):
                value = dict(item, role=record["role"])
                if record["role"] != "signer":
                    observed = native.proc_identity(item["pid"], executable_hash=True)
                    require(observed is not None and all(observed[key] == item[key] for key in item),
                            "Native process changed during executable hashing")
                    value["executable_sha256"] = observed["executable_sha256"]
                processes.append(value)
        return {"schema": "PQBTC-RUNPOD-NATIVE-IDENTITY-1", "backend": "native", "namespace": self.namespace,
                "volume_id": prior["volume_id"], "payload": payload_identity(self.descriptor),
                "payload_root": str(self.versions_root / self.descriptor["version"]),
                "active_seed": str(self.runtime_root / "seed"), "processes": processes,
                "execution_context": registry["context"],
                "previous_empty_contexts": registry["previous_empty_contexts"],
                "signer_execution_proof": self.signer_execution_proof(),
                "isolation": "PROVIDER_CONTAINER_PLUS_UID_SEPARATION", "outer_provider_image_changed": False}

    def signer_execution_proof(self):
        """A live hardened child plus the exact immutable FD used to exec it."""
        proofs = []
        for record in native.registry(self.registry_path, self.namespace)["groups"]:
            if record["role"] != "signer":
                continue
            for member in native.verified_members(record):
                require(member["pid"] == record["pid"] and
                        member.get("proof_kind") == "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD" and
                        member.get("pidfd_live") is True and member.get("post_exec_executable_observable") is False,
                        "Hardened signer execution proof is unavailable")
                require(self.descriptor is not None and record["pre_exec"]["sha256"] ==
                        self.descriptor["files"]["seed/demo-signer-bin/pilot-signer"],
                        "Live signer differs from the selected immutable payload")
                proofs.append({"proof_kind": "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD", "pid": member["pid"],
                               "start": member["start"], "uid": member["uid"], "session": member["session"],
                               "pgid": member["pgid"], "sha256": record["pre_exec"]["sha256"], "live": True,
                               "pidfd_bound": True, "post_exec_executable_observable": False,
                               "no_new_privileges": member["no_new_privileges"], "capabilities": member["capabilities"],
                               "pre_exec_file": copy.deepcopy(record["pre_exec"])})
        require(len(proofs) <= 1, "More than one live signer session exists")
        return proofs[0] if proofs else None


class _NativeControllerMethods:
    """Existing durable TEST wallet controls executed as isolated native UIDs."""
    def __init__(self, state_dir, descriptor=None, *, versions_root=Path("/opt/pqbtc-runpod/versions"),
                 runtime_root=Path("/opt/pqbtc-runtime"), data_root=Path("/var/lib/pqbtc"),
                 bootstrap=False, namespace="pqbtc-runpod-public"):
        require(sys.platform.startswith("linux") and os.geteuid() == 0,
                "Native Runpod controls require contained Linux root")
        owned_directory(runtime_root)
        self._global_lock = os.open(Path(runtime_root) / ".native-backend.lock",
                                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self._global_lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, "Native backend lock ownership mismatch")
        fcntl.flock(self._global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            super().__init__(state_dir, bootstrap=bootstrap)
            self.manager = NativeManager(state_dir, versions_root=versions_root, runtime_root=runtime_root,
                                         data_root=data_root, namespace=namespace)
            self.descriptor = descriptor
        except BaseException:
            os.close(self._global_lock)
            self._global_lock = None
            raise

    def _command(self, user, *args):
        require(user in ("1000:1000", "1001:1000"), "Unsupported native process UID")
        command = ["/usr/bin/python3", str(HERE / "native_exec.py"), "--uid", user.split(":")[0]]
        tokens = tuple(map(str, args))
        bound = self._public_module
        role = None
        if bound.SERVER in tokens:
            role = "signer"
        elif bound.SOURCE + "/contrib/ml-dsa-console/public_runtime.py" in tokens:
            role = "worker"
        elif bound.SOURCE + "/contrib/ml-dsa-qualification/public_transport.py" in tokens:
            role = "bridge"
        if role:
            command += ["--role", role, "--registry", str(self.manager.registry_path), "--namespace", self.manager.namespace]
            executables = [bound.SERVER] if role == "signer" else ["/usr/bin/python3"]
            if role == "worker":
                executables.append(bound.BUILD + "/bin/pqbtcd")
            for executable in executables:
                command += ["--allowed-executable", executable]
        if role == "signer":
            require(len(tokens) >= 4 and tokens[:2] == ("python3", "-c") and tokens[3] == bound.SERVER,
                    "Unexpected inherited signer launcher shape")
            require(self.manager.descriptor is not None, "Select a verified native payload before signer launch")
            command += ["--signer-fd-exec", "--expected-sha256",
                        self.manager.descriptor["files"]["seed/demo-signer-bin/pilot-signer"]]
            # The existing Python trampoline would lose the immutable-FD
            # guarantee. The trusted root wrapper performs its FD3/FD4 mapping
            # directly and execs exactly the file descriptor it hashed.
            tokens = tokens[3:]
        return [*command, "--", *tokens]

    def _spawn(self, user, executable, *args, stderr=None):
        process, info = super()._spawn(user, executable, *args, stderr=stderr)
        current = native.proc_identity(info["pid"])
        require(info["pid"] == process.pid and current is not None and current["start"] == info["start"] and
                current["uid"] == int(user.split(":")[0]), "Native process handshake identity mismatch")
        return process, info

    def _start_signer(self, *args, **kwargs):
        # Python default arguments in the inherited method were bound when its
        # module was imported, before this instance's DATA path was selected.
        kwargs.setdefault("path", self._public_module.DATA + "/signer/current")
        observed = super()._start_signer(*args, **kwargs)
        proof = self.manager.signer_execution_proof()
        require(proof is not None and proof["pid"] == self._signer_info["pid"] == self._signer.pid and
                proof["start"] == self._signer_info["start"] and proof["uid"] == 1000 and
                self._signer_info.get("proof_kind") == proof["proof_kind"] and
                self._signer_info.get("pre_exec_sha256") == proof["sha256"], "Native signer process identity mismatch")
        return observed

    def _signal(self, info):
        require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "Native pidfd signalling is required")
        signer_record = None
        if info["uid"] == 1000:
            records = native.registry(self.manager.registry_path, self.manager.namespace)["groups"]
            matching = [record for record in records if record["role"] == "signer" and
                        record["pid"] == info["pid"] and record["start"] == info["start"]]
            require(len(matching) == 1 and matching[0]["pre_exec"]["sha256"] == info.get("pre_exec_sha256"),
                    "Native signer signal lacks an immutable owned FD launch proof")
            signer_record = matching[0]
        current = native.proc_identity(info["pid"], signer_record=signer_record)
        if current is None or current["zombie"]:
            return
        executable_verified = (current.get("executable") == str(Path(info["executable"]).resolve(strict=True)) or
                               signer_record is not None and current.get("proof_kind") == "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD")
        require(current is not None and current["start"] == info["start"] and current["uid"] == info["uid"] and executable_verified,
                "Native signal identity mismatch; process preserved")
        try:
            fd = os.pidfd_open(info["pid"])
        except ProcessLookupError:
            return
        try:
            require(native.proc_identity(info["pid"], signer_record=signer_record) == current,
                    "Native process changed during signal binding")
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)

    def _start(self):
        self._reconcile_handles()
        self.manager.ensure(self.descriptor)
        self.descriptor = self.manager.descriptor
        if self._restart_needed or self._worker is None:
            # This also catches native children left behind after a controller
            # crash. Only verified sessions in the root-owned registry are used.
            self.manager.emergency_stop()
            self._discard_handles()
            self._restart_needed = False
        if self._worker is None:
            self._start_worker()
        return self._request("start")

    def action(self, action, params=None):
        if action != "crash":
            return super().action(action, params)
        require(params in (None, {}), "Unsupported native crash parameters")
        with self._mutex:
            self.manager.identity()
            cleanup = self.manager.emergency_stop()
            self._discard_handles()
            self.journal["signer_clean"] = False
            self._event("crash", "Owned native application sessions killed; durable floors retained")
            self._start()
            result = {"crashed": True, "restarted": True, "locked": True,
                      "crash_kind": "OWNED_NATIVE_APPLICATION_PROCESS_GROUPS", "cleanup": cleanup,
                      "provider_container_restarted": False}
            return {"result": result, "status": self.status()}

    def close(self):
        try:
            super().close()
        finally:
            try:
                self.manager.emergency_stop()
            finally:
                if self._global_lock is not None:
                    os.close(self._global_lock)
                    self._global_lock = None


def NativeController(state_dir, descriptor=None, *, versions_root=Path("/opt/pqbtc-runpod/versions"),
                     runtime_root=Path("/opt/pqbtc-runtime"), data_root=Path("/var/lib/pqbtc"),
                     bootstrap=False, namespace="pqbtc-runpod-public"):
    """Bind existing wallet logic to one namespace without shared module globals."""
    bound = module("runpod_bound_public_" + uuid.uuid4().hex, HERE.parent / "ml-dsa-console/public_controller.py")
    bound.SEED = str(Path(runtime_root) / "seed")
    bound.SOURCE = bound.SEED + "/mldsa-demo-source"
    bound.BUILD = bound.SEED + "/mldsa-demo-build"
    bound.SERVER = bound.SEED + "/demo-signer-bin/pilot-signer"
    bound.DATA = str(data_root)
    bound.SOCKET = str(Path("/run/pqbtc-ipc") / namespace / "signer.sock")
    controller_type = type("NativePublicController", (_NativeControllerMethods, bound.PublicController),
                           {"_public_module": bound})
    return controller_type(state_dir, descriptor, versions_root=versions_root, runtime_root=runtime_root,
                           data_root=data_root, bootstrap=bootstrap, namespace=namespace)
