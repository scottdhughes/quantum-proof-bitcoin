#!/usr/bin/env python3
"""Reviewed-only TEST receiver clone. Importing performs no runtime operations."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

BASE = "/pqbtc.slice/pqbtc-public.slice/pqbtc-public-soak.slice/pqbtc-public-soak-20261114.slice"
SERVICE = "pqbtc-public-soak-20261114-l-receiver-forensic-20261117-01.service"
TASK = Path("/data/pqbtc-public-runtime-20261114")
ENDPOINT = "unix:///data/pqbtc-public-runtime-20261114/client/docker.sock"
ENGINE = "898eeae9-915d-499e-977a-9168abb73d17"
DEFAULT_ENGINE = "6f22cb63-5d49-484a-a8f2-9d0576ae320d"
IMAGE = "sha256:b3358bb35d60a5f42c9ce1fe65c26926250c26e99815c3446810a8eb6e730f0a"
SOURCE_CONTAINER = "pqbtc-mldsa-public-soak-r3-l-soak-20261116-01-research"
SOURCE_ID = "e6ffad0815e423a2f54088232d6b8940282dfc7be457f7599085925ad27a5666"
SOURCE_VOLUME = SOURCE_CONTAINER + "-data-v1"
SOURCE_VOLUME_ID = "ad7aff1489a84a8d8140010d5c27033b"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
CLONE_CONTAINER = "pqbtc-mldsa-public-l-receiver-forensic-20261117-01"
CLONE_VOLUME = CLONE_CONTAINER + "-data-v1"
RAW_INPUT = TASK / "client/diagnostics/relay-forensics-20261117-01-input/pending-signed-transaction.raw"
OUTPUT = TASK / "client/diagnostics/relay-receiver-20261117-01"
SELF = Path(__file__).absolute()
TARGET_TXID = "f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94"
TARGET_RAW_SHA = "d9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028"
EXPECTED_TIP = "54a78dadccd74a664b730f09d436f7272b3fda02081deb9915935b0a5a4ff8be"
EXPECTED_UTXO = "5e8dbc2dc2a2a945baf0cd994eaaba8e4f02d6d0701b8b4ac60a9ead44aaac0d"
MAX_FILES, MAX_DIRS = 10_000, 128
MAX_FILE_BYTES, MAX_TOTAL_BYTES = 128 * 1024 * 1024, 512 * 1024 * 1024
MAX_DEPTH, MAX_PATH_BYTES = 8, 256
CHUNK = 1024 * 1024
LABELS = {"org.pqbtc.console.build": "source-1", "org.pqbtc.forensics.schema": "receiver-clone-1",
          "org.pqbtc.forensics.source-id": SOURCE_ID, "org.pqbtc.forensics.txid": TARGET_TXID}


class Refusal(ValueError):
    pass


def require(value, label):
    if not value:
        raise Refusal(label)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def check_info(info, *, directory, uid, gid):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), "SOURCE_TYPE")
    require(info.st_uid == uid and info.st_gid == gid, "SOURCE_OWNER")
    require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), "SOURCE_MODE")
    if not directory:
        require(info.st_nlink == 1, "SOURCE_SINGLE_LINK")


def path_kind(parts, directory):
    """Only public DB datasets; numeric LevelDB WALs are data, LOG files omitted."""
    require(parts and len(parts) <= MAX_DEPTH and
            len("/".join(parts).encode()) <= MAX_PATH_BYTES and
            all(p not in ("", ".", "..") and "/" not in p for p in parts), "PUBLIC_PATH_BOUND")
    if directory:
        require(parts in [("blocks",), ("blocks", "index"), ("chainstate",)], "PUBLIC_PATH_DIRECTORY")
        return "directory"
    if parts == ("mempool.dat",):
        return "data"
    if len(parts) == 2 and parts[0] == "blocks":
        require(re.fullmatch(r"(?:blk|rev)[0-9]{5,}\.dat|xor\.dat", parts[1]), "PUBLIC_PATH_FILE")
        return "data"
    db_file = (len(parts) == 3 and parts[:2] == ("blocks", "index")) or (len(parts) == 2 and parts[0] == "chainstate")
    require(db_file, "PUBLIC_PATH_FILE")
    if parts[-1] in ("LOG", "LOG.old"):
        return "omit_leveldb_diagnostic_log"
    require(re.fullmatch(r"CURRENT|LOCK|MANIFEST-[0-9]+|[0-9]{6,}\.(?:ldb|sst|log|dbtmp)", parts[-1]), "PUBLIC_PATH_FILE")
    return "data"


def open_relative(root_fd, parts, flags=os.O_RDONLY, mode=0o600):
    require(path_kind(tuple(parts), False) == "data", "PUBLIC_PATH_FILE")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, mode, dir_fd=fd)
    finally:
        os.close(fd)


def scan_public_tree(root, *, uid=1001, gid=1000):
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directories, files, omitted = [], [], []
    total, encountered = 0, 0
    try:
        check_info(os.fstat(root_fd), directory=True, uid=uid, gid=gid)

        def visit(parent_fd, name, parts):
            nonlocal total, encountered
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode), "SOURCE_SYMLINK")
            is_directory = stat.S_ISDIR(info.st_mode)
            check_info(info, directory=is_directory, uid=uid, gid=gid)
            kind = path_kind(parts, is_directory)
            record = {"path": "/".join(parts), "identity": identity(info), "bytes": info.st_size}
            if is_directory:
                require(len(directories) < MAX_DIRS, "DIRECTORY_COUNT_BOUND")
                directories.append(record)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    require(identity(os.fstat(fd)) == record["identity"], "SOURCE_CHANGED")
                    with os.scandir(fd) as stream:
                        # No unbounded listdir/sort before the entry-count guard.
                        for entry in stream:
                            visit(fd, entry.name, parts + (entry.name,))
                finally:
                    os.close(fd)
            else:
                encountered += 1
                require(encountered <= MAX_FILES, "FILE_COUNT_BOUND")
                if kind == "omit_leveldb_diagnostic_log":
                    omitted.append(record["path"])
                    return
                require(info.st_size <= MAX_FILE_BYTES, "FILE_BYTES_BOUND")
                total += info.st_size
                require(total <= MAX_TOTAL_BYTES, "TOTAL_BYTES_BOUND")
                files.append(record)
        for name in ["blocks", "chainstate", "mempool.dat"]:
            visit(root_fd, name, (name,))
        return {"root_identity": identity(os.fstat(root_fd)), "directories": sorted(directories, key=lambda x: x["path"]),
                "files": sorted(files, key=lambda x: x["path"]), "omitted_diagnostic_logs": sorted(omitted),
                "selected_bytes": total}
    finally:
        os.close(root_fd)


def hash_fd(fd, expected_size):
    os.lseek(fd, 0, os.SEEK_SET)
    digest, count = hashlib.sha256(), 0
    while True:
        piece = os.read(fd, CHUNK)
        if not piece:
            break
        count += len(piece)
        require(count <= expected_size <= MAX_FILE_BYTES, "SOURCE_CHANGED")
        digest.update(piece)
    require(count == expected_size, "SOURCE_CHANGED")
    return digest.hexdigest()


def copy_one(source_fd, destination_fd, record):
    parts = PurePosixPath(record["path"]).parts
    src = open_relative(source_fd, parts)
    dst = None
    try:
        require(identity(os.fstat(src)) == record["identity"], "SOURCE_CHANGED")
        dst = open_relative(destination_fd, parts, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        os.fchmod(dst, 0o600)
        digest, count = hashlib.sha256(), 0
        while True:
            data = os.read(src, CHUNK)
            if not data:
                break
            count += len(data)
            require(count <= record["bytes"] <= MAX_FILE_BYTES, "SOURCE_CHANGED")
            digest.update(data)
            view = memoryview(data)
            while view:
                written = os.write(dst, view)
                require(written > 0, "COPY_WRITE_INTERRUPTED")
                view = view[written:]
        require(count == record["bytes"], "SOURCE_CHANGED")
        os.fsync(dst)
        sha = digest.hexdigest()
        require(hash_fd(src, count) == sha and identity(os.fstat(src)) == record["identity"], "SOURCE_CHANGED")
        require(hash_fd(dst, count) == sha, "DESTINATION_HASH_MISMATCH")
        return {"path": record["path"], "bytes": count, "sha256": sha}
    finally:
        os.close(src)
        if dst is not None:
            os.close(dst)


def copy_public_tree(source, destination, *, uid=1001, gid=1000):
    manifest = scan_public_tree(source, uid=uid, gid=gid)
    require(not os.path.lexists(destination), "NEW_DESTINATION_REQUIRED")
    Path(destination).mkdir(mode=0o700)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    dest_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(source_fd)) == manifest["root_identity"], "SOURCE_CHANGED")
        for record in manifest["directories"]:
            parts = PurePosixPath(record["path"]).parts
            parent_fd = os.dup(dest_fd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = child
                os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        copied = [copy_one(source_fd, dest_fd, record) for record in manifest["files"]]
        require(scan_public_tree(source, uid=uid, gid=gid) == manifest, "SOURCE_CHANGED")
        for record, result in zip(manifest["files"], copied):
            fd = open_relative(source_fd, PurePosixPath(record["path"]).parts)
            try:
                require(identity(os.fstat(fd)) == record["identity"] and
                        hash_fd(fd, record["bytes"]) == result["sha256"], "SOURCE_CHANGED")
            finally:
                os.close(fd)
        os.fsync(dest_fd)
        return {"file_count": len(copied), "selected_bytes": manifest["selected_bytes"], "files": copied,
                "source_all_selected_identity_metadata_and_hashes_rechecked": True,
                "omitted_diagnostic_logs": manifest["omitted_diagnostic_logs"],
                "WAL_scope": "Numeric LevelDB WALs only inside blocks/index or chainstate are public database data; node/debug/console logs and LevelDB diagnostic LOG/LOG.old are not copied."}
    finally:
        os.close(source_fd)
        os.close(dest_fd)


def read_raw_transaction(path, *, uid=1001, gid=1000):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_gid == gid and
                stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                1 <= before.st_size <= 4_000_000, "RAW_FILE_OWNERSHIP")
        raw = os.read(fd, before.st_size + 1)
        require(len(raw) == before.st_size == 3878 and hashlib.sha256(raw).hexdigest() == TARGET_RAW_SHA and
                identity(before) == identity(os.fstat(fd)) == identity(os.lstat(path)), "RAW_BINDING")
        return raw
    finally:
        os.close(fd)


def validate_context(value):
    require(type(value) is dict and type(value.get("height")) is int and value["height"] == 408 and
            value.get("tip") == EXPECTED_TIP and value.get("utxo_hash") == EXPECTED_UTXO and
            type(value.get("utxo_count")) is int and value["utxo_count"] == 547, "EXPECTED_CLONE_CHAIN_CONTEXT")
    require(value.get("network_active") is False and value.get("peer_count") == 0 and
            type(value.get("mempool_size")) is int and value["mempool_size"] >= 0, "CLONE_MUST_BE_OFFLINE")


def collect_context(node):
    rpc = node.rpc()
    info, inventory, network = rpc.getblockchaininfo(), rpc.gettxoutsetinfo(), rpc.getnetworkinfo()
    return {"height": info["blocks"], "tip": info["bestblockhash"],
            "utxo_hash": inventory["hash_serialized_3"], "utxo_count": inventory["txouts"],
            "network_active": network["networkactive"], "peer_count": len(rpc.getpeerinfo()),
            "mempool_size": rpc.getmempoolinfo()["size"]}


def select_verdict(value):
    require(type(value) is dict and value.get("txid") == TARGET_TXID and type(value.get("allowed")) is bool,
            "NATIVE_VERDICT_IDENTITY")
    result = {"txid": TARGET_TXID, "allowed": value["allowed"]}
    if "wtxid" in value:
        require(type(value["wtxid"]) is str and re.fullmatch("[0-9a-f]{64}", value["wtxid"]), "VERDICT_WTXID")
        result["wtxid"] = value["wtxid"]
    if "vsize" in value:
        require(type(value["vsize"]) is int and 0 < value["vsize"] <= 4_000_000, "VERDICT_VSIZE")
        result["vsize"] = value["vsize"]
    for key in ["reject-reason", "package-error"]:
        if key in value:
            text = value[key]
            require(type(text) is str and len(text) <= 256 and
                    re.fullmatch(r"[A-Za-z0-9 _.,:()/\[\]-]+", text) and
                    re.search(r"[0-9a-fA-F]{80,}", text) is None, "VERDICT_REASON_BOUND")
            result[key] = text
    return result


def admit_with_node(node, raw):
    result = {"result": "FAIL"}
    try:
        node.start(network_active=False)
        before = collect_context(node)
        validate_context(before)
        result["context_before"] = before
        verdicts = node.rpc().testmempoolaccept([raw.hex()])
        require(type(verdicts) is list and len(verdicts) == 1, "ONE_NATIVE_VERDICT_REQUIRED")
        result["native_verdict"] = select_verdict(verdicts[0])
        after = collect_context(node)
        validate_context(after)
        require(before == after, "TESTMEMPOOLACCEPT_CHANGED_STATE")
        result.update({"result": "PASS", "context_before": before, "context_after": after,
                       "transaction_broadcast_or_admission_not_performed": True})
    except BaseException as error:
        result["guard"] = str(error) if isinstance(error, Refusal) else "OPAQUE_NATIVE_DIAGNOSTIC_FAILURE"
    finally:
        try:
            node.stop()
            result["node_stop_clean"] = True
        except BaseException:
            result["node_stop_clean"] = False
            result["result"] = "FAIL"
    return result


def expected_clone_identity(container_id):
    return {"Id": container_id, "Name": "/" + CLONE_CONTAINER, "Image": IMAGE,
            "Config": {"Labels": dict(LABELS), "Cmd": ["sleep", "infinity"], "User": "1001:1000"},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Memory": 1073741824,
                           "NanoCpus": 2000000000, "PidsLimit": 256, "CapDrop": ["ALL"],
                           "CapAdd": None, "Privileged": False, "SecurityOpt": ["no-new-privileges"],
                           "CgroupnsMode": "host", "PidMode": ""},
            "Mounts": [{"Type": "volume", "Name": CLONE_VOLUME, "Destination": "/clone", "RW": True},
                       {"Type": "bind", "Source": str(SELF), "Destination": "/opt/receiver_forensic.py", "RW": False},
                       {"Type": "bind", "Source": str(RAW_INPUT), "Destination": "/public-input/pending.raw", "RW": False}]}


def validate_clone_for_stop(value):
    require(type(value) is dict and re.fullmatch("[0-9a-f]{64}", value.get("Id", "")) and
            value["Id"] != SOURCE_ID, "CLONE_STOP_IDENTITY")
    expected = expected_clone_identity(value["Id"])
    require(all(value.get(k) == expected[k] for k in ["Name", "Image", "Config"]), "CLONE_STOP_LAYOUT")
    host = value.get("HostConfig", {})
    require(all(host.get(k) == v for k, v in expected["HostConfig"].items() if k != "CapAdd") and
            host.get("CapAdd") in (None, []), "CLONE_STOP_LAYOUT")
    mounts = value.get("Mounts")
    require(type(mounts) is list and len(mounts) == 3, "CLONE_STOP_MOUNTS")
    by_destination = {m.get("Destination"): m for m in mounts}
    require(len(by_destination) == 3 and all(all(by_destination.get(m["Destination"], {}).get(k) == v
                for k, v in m.items()) for m in expected["Mounts"]), "CLONE_STOP_MOUNTS")
    return value["Id"]


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "RECEIPT_WRITE")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "DUPLICATE_PUBLIC_JSON_MEMBER")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def self_pin(expected):
    require(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected), "SELF_PIN_FORMAT")
    fd = os.open(SELF, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and
                info.st_size <= 256 * 1024, "SELF_FILE_OWNERSHIP")
        raw = os.read(fd, 256 * 1024 + 1)
        require(hashlib.sha256(raw).hexdigest() == expected, "SELF_PIN_CHANGED")
    finally:
        os.close(fd)


def contained_boundary(memory, pids):
    require(__debug__ and sys.platform.startswith("linux") and os.getuid() == os.geteuid() == 1001,
            "CONTAINED_LINUX_UID1001_REQUIRED")
    cg = Path("/proc/self/cgroup").read_text().strip()
    require(re.fullmatch(re.escape("0::" + BASE) + r"/docker-[0-9a-f]{64}\.scope", cg), "CONTAINER_OUTSIDE_AGGREGATE")
    parent = Path("/sys/fs/cgroup") / BASE.lstrip("/")
    require((parent / "cpu.max").read_text().strip() == "200000 100000" and
            (parent / "memory.max").read_text().strip() == "4294967296" and
            (parent / "pids.max").read_text().strip() == "2048" and
            (parent / "cgroup.freeze").read_text().strip() == "0", "AGGREGATE_LIMIT_CHANGED")
    leaf = Path("/sys/fs/cgroup") / cg.removeprefix("0::/")
    require({name: (leaf / name).read_text().strip() for name in
             ["cpu.max", "memory.max", "pids.max", "cgroup.freeze"]} == {
                "cpu.max": "200000 100000", "memory.max": str(memory), "pids.max": str(pids),
                "cgroup.freeze": "0"}, "CONTAINED_LEAF_LIMIT_CHANGED")
    return cg


def contained_copy():
    cg = contained_boundary(536870912, 128)
    root = Path("/original")
    for p in [root, root / "node", root / "node/chain", root / "node/chain/mldsa44-test-v1"]:
        info = p.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "PUBLIC_PARENT_TYPE")
        if p != root:
            check_info(info, directory=True, uid=1001, gid=1000)
    marker_fd = os.open(root / "identity.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(marker_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= 1024, "PUBLIC_SOURCE_MARKER")
        marker = strict_json(os.read(marker_fd, 1025))
        require(marker == {"volume_id": SOURCE_VOLUME_ID, "profile_sha256": PROFILE}, "SOURCE_MARKER_IDENTITY")
    finally:
        os.close(marker_fd)
    clone = Path("/clone")
    check_info(clone.lstat(), directory=True, uid=1001, gid=1000)
    require(not any(clone.iterdir()), "NEW_EMPTY_CLONE_VOLUME")
    (clone / "node").mkdir(mode=0o700)
    (clone / "node/chain").mkdir(mode=0o700)
    receipt = copy_public_tree(root / "node/chain/mldsa44-test-v1", clone / "node/chain/mldsa44-test-v1")
    return {"schema": "PQBTC-L-PUBLIC-RECEIVER-DATA-COPY-1", "result": "PASS",
            "source_volume_id": SOURCE_VOLUME_ID, "source_marker_verified": True,
            "actual_generic_copy_cgroup": cg, **receipt}


def contained_native():
    cg = contained_boundary(1073741824, 256)
    raw = read_raw_transaction(Path("/public-input/pending.raw"))
    source = Path("/opt/pqbtc-runtime/seed/mldsa-demo-source")
    sys.path.insert(0, str(source / "contrib/ml-dsa-console"))
    sys.path.insert(0, str(source / "test/functional"))
    spec = importlib.util.spec_from_file_location("qualified_H_public_runtime", source / "contrib/ml-dsa-console/public_runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from test_framework.authproxy import AuthServiceProxy
    from test_framework.messages import CTransaction
    import io
    tx = CTransaction()
    stream = io.BytesIO(raw)
    tx.deserialize(stream)
    require(stream.tell() == len(raw) and tx.serialize_with_witness() == raw and tx.txid_hex == TARGET_TXID,
            "EXACT_SIGNED_RAW_TRANSACTION")
    node = module.PublicNode("/opt/pqbtc-runtime/seed/mldsa-demo-build/bin/pqbtcd",
                             Path("/clone/node/chain"), AuthServiceProxy)
    return {"schema": "PQBTC-L-OFFLINE-RECEIVER-NATIVE-ADMISSION-1", "actual_cgroup": cg,
            "bound_raw_sha256": TARGET_RAW_SHA, "bound_txid": TARGET_TXID,
            "fresh_rpc_auth_stayed_inside_clone": True, **admit_with_node(node, raw)}


class Docker:
    def __init__(self, endpoint=ENDPOINT):
        self.prefix = ["/usr/bin/docker", "--config", str(TASK / "client/cli-config"), "-H", endpoint]
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

    def call(self, args, *, timeout=30, check=True):
        result = subprocess.run([*self.prefix, *args], stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, env=self.environment)
        require(len(result.stdout) <= 8 * 1024 * 1024, "DOCKER_OUTPUT_BOUND")
        require(not check or result.returncode == 0, "DOCKER_OPERATION_FAILED_OPAQUE")
        return result

    def value(self, args, **kwargs):
        response = self.call(args, check=False, **kwargs)
        try:
            value = strict_json(response.stdout)
        except (ValueError, UnicodeError):
            raise Refusal("BOUNDED_DOCKER_JSON_REQUIRED") from None
        require(response.returncode == 0 or (type(value) is dict and value.get("result") == "FAIL" and
                ("guard" not in value or (type(value["guard"]) is str and
                 re.fullmatch("[A-Z0-9_]{1,100}", value["guard"])))), "DOCKER_HELPER_FAILURE_NOT_PROJECTED")
        return value


def selected_inspect(docker, name):
    template = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
                '"Config":{"Labels":{{json .Config.Labels}},"Cmd":{{json .Config.Cmd}},"User":{{json .Config.User}}},'
                '"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
                '"Memory":{{json .HostConfig.Memory}},"NanoCpus":{{json .HostConfig.NanoCpus}},'
                '"PidsLimit":{{json .HostConfig.PidsLimit}},"CapDrop":{{json .HostConfig.CapDrop}},'
                '"CapAdd":{{json .HostConfig.CapAdd}},"Privileged":{{json .HostConfig.Privileged}},'
                '"SecurityOpt":{{json .HostConfig.SecurityOpt}},"CgroupnsMode":{{json .HostConfig.CgroupnsMode}},'
                '"PidMode":{{json .HostConfig.PidMode}}},"Mounts":{{json .Mounts}},'
                '"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}},"FinishedAt":{{json .State.FinishedAt}}}}')
    return docker.value(["container", "inspect", "--format", template, name])


def guard_original(docker):
    require(docker.value(["info", "--format", '{"id":{{json .ID}},"arch":{{json .Architecture}},"driver":{{json .CgroupDriver}}}']) ==
            {"id": ENGINE, "arch": "x86_64", "driver": "systemd"}, "EXACT_NATIVE_PRIVATE_ENGINE")
    value = selected_inspect(docker, SOURCE_CONTAINER)
    require(value["Id"] == SOURCE_ID and value["Image"] == IMAGE and value["State"]["Running"] is False and
            value["State"]["Pid"] == 0 and value["Config"]["Labels"] == {
                "org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": PROFILE,
                "org.pqbtc.console.build": "source-1",
                "org.pqbtc.console.manifest": "28b84900e98248961469340744081d3c1d49e8f76e5c16731418aee000e2e823"},
            "ORIGINAL_STOPPED_IDENTITY_REQUIRED")
    mounts = value["Mounts"]
    require(len(mounts) == 1 and mounts[0].get("Type") == "volume" and mounts[0].get("Name") == SOURCE_VOLUME and
            mounts[0].get("Destination") == "/var/lib/pqbtc", "ORIGINAL_VOLUME_IDENTITY")
    volume = docker.value(["volume", "inspect", "--format",
        '{"name":{{json .Name}},"driver":{{json .Driver}},"options":{{json .Options}},"labels":{{json .Labels}}}', SOURCE_VOLUME])
    require(volume["name"] == SOURCE_VOLUME and volume["driver"] == "local" and volume["options"] in (None, {}) and
            volume["labels"] == {"org.pqbtc.console.schema": "public-test-1", "org.pqbtc.console.profile": PROFILE},
            "ORIGINAL_VOLUME_OWNERSHIP")
    require(not docker.call(["ps", "--filter", "volume=" + SOURCE_VOLUME, "--format", "{{.ID}}"] ).stdout.strip(),
            "ORIGINAL_VOLUME_HAS_RUNNING_WRITER")
    return {"id": SOURCE_ID, "image": IMAGE, "state": value["State"], "volume": volume}


def cpu_readiness():
    def sample():
        return [int(v) for v in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    first, start = sample(), time.monotonic()
    time.sleep(15)
    elapsed, last = time.monotonic() - start, sample()
    delta = [b - a for a, b in zip(first, last)]
    require(sum(delta) > 0 and all(v >= 0 for v in delta), "CPU_SAMPLE_INVALID")
    busy = 100 * (sum(delta) - delta[3] - delta[4]) / sum(delta)
    require(busy < 10, "RESEARCH_NOT_IDLE")
    return {"seconds": elapsed, "host_busy_percent": busy, "host_cpu_count": os.cpu_count()}


def stop_clone(docker, expected_id):
    value = selected_inspect(docker, expected_id)
    require(validate_clone_for_stop(value) == expected_id, "CREATED_INSTANCE_CHANGED")
    if value["State"]["Running"]:
        docker.call(["stop", "--time", "5", expected_id], timeout=20)
    after = selected_inspect(docker, expected_id)
    require(validate_clone_for_stop(after) == expected_id and after["State"]["Running"] is False and
            after["State"]["Pid"] == 0, "CLONE_BACKEND_STOP_NOT_PROVED")
    return {"backend_stopped": True, "container_id": expected_id, "pid": 0,
            "fresh_clone_volume_and_data_retained": True}


def cleanup_native(docker, created_id):
    if created_id is None:
        # A lost create response is ambiguous. Look up only this fresh reserved
        # name's ID; bind it only after complete selected ownership/layout checks.
        lookup = docker.call(["container", "inspect", "--format", "{{json .Id}}", CLONE_CONTAINER], check=False)
        if lookup.returncode:
            require_missing(lookup, "container", CLONE_CONTAINER)
            return {"backend_stopped": True, "state": "ABSENT", "absence_proved": True,
                    "fresh_clone_volume_and_data_retained": True}
        candidate = strict_json(lookup.stdout)
        require(type(candidate) is str and re.fullmatch("[0-9a-f]{64}", candidate) and
                candidate != SOURCE_ID, "UNKNOWN_CREATE_ID_LOOKUP")
        selected = selected_inspect(docker, candidate)
        created_id = validate_clone_for_stop(selected)
        require(created_id == candidate, "UNKNOWN_CREATE_ID_CHANGED")
        result = stop_clone(docker, created_id)
        result["id_discovered_and_bound_after_lost_create_response"] = True
        return result
    return stop_clone(docker, created_id)


def stop_temporary(docker, role):
    require(role in ("init", "copy"), "TEMPORARY_ROLE")
    name = CLONE_CONTAINER + "-" + role
    lookup = docker.call(["container", "inspect", "--format", "{{json .Id}}", name], check=False)
    if lookup.returncode:
        require_missing(lookup, "container", name)
        return {"role": role, "state": "ABSENT"}
    container_id = json.loads(lookup.stdout)
    value = selected_inspect(docker, container_id)
    require(re.fullmatch("[0-9a-f]{64}", container_id) and container_id != SOURCE_ID and
            value["Id"] == container_id and value["Name"] == "/" + name and value["Image"] == IMAGE and
            value["Config"]["Labels"] == LABELS | {"org.pqbtc.forensics.role": role}, "TEMPORARY_IDENTITY")
    host = value["HostConfig"]
    require(host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True and
            host["Privileged"] is False and host["CapDrop"] == ["ALL"] and
            host["SecurityOpt"] == ["no-new-privileges"] and host["NanoCpus"] == 2000000000 and
            host["Memory"] == (134217728 if role == "init" else 536870912) and
            host["PidsLimit"] == (64 if role == "init" else 128) and
            host["CgroupnsMode"] == "host" and host["PidMode"] == "" and
            host["CapAdd"] in ((["CHOWN"], ["CAP_CHOWN"]) if role == "init" else (None, [])), "TEMPORARY_ISOLATION")
    require(value["Config"]["User"] == ("0:0" if role == "init" else "1001:1000"), "TEMPORARY_UID")
    mounts = value["Mounts"]
    require(len(mounts) == (1 if role == "init" else 3), "TEMPORARY_MOUNT_COUNT")
    clone = next((m for m in mounts if m.get("Destination") == "/clone"), {})
    require(clone.get("Type") == "volume" and clone.get("Name") == CLONE_VOLUME and clone.get("RW") is True,
            "TEMPORARY_CLONE_MOUNT")
    if role == "copy":
        original = next((m for m in mounts if m.get("Destination") == "/original"), {})
        code = next((m for m in mounts if m.get("Destination") == "/opt/receiver_forensic.py"), {})
        require(original.get("Type") == "volume" and original.get("Name") == SOURCE_VOLUME and
                original.get("RW") is False and code.get("Type") == "bind" and code.get("Source") == str(SELF) and
                code.get("RW") is False, "TEMPORARY_READONLY_SOURCE_MOUNTS")
    if value["State"]["Running"]:
        docker.call(["stop", "--time", "2", container_id], timeout=10)
    after = docker.call(["container", "inspect", "--format", '{{json .State}}', container_id], check=False)
    if after.returncode:
        require_missing(after, "container", container_id)
        return {"role": role, "state": "REMOVED", "id": container_id}
    state = json.loads(after.stdout)
    require(state.get("Running") is False and state.get("Pid") == 0, "TEMPORARY_STOP_UNCERTAIN")
    return {"role": role, "state": "STOPPED", "id": container_id}


def require_missing(result, kind, name):
    require(kind in ("container", "volume") and type(name) is str, "MISSING_PROBE_SCOPE")
    text = result.stderr.decode("utf8", "replace").strip().casefold()
    allowed = {"error: no such object: " + name,
               "error: no such " + kind + ": " + name,
               "error response from daemon: no such " + kind + ": " + name}
    if kind == "volume":
        allowed.add("error response from daemon: get " + name + ": no such volume")
    require(result.returncode != 0 and not result.stdout.strip() and text in allowed,
            "FRESH_NAMESPACE_OR_EXACT_MISSING_PROOF_REQUIRED")


def host_run(expected_sha, raw_file):
    global RAW_INPUT
    require(__debug__ and sys.platform.startswith("linux") and os.geteuid() == 0, "LINUX_ROOT_CONTROL_ONLY")
    self_pin(expected_sha)
    require(bool(SELF.stat().st_mode & stat.S_IROTH), "PUBLIC_HELPER_MUST_BE_READABLE_BY_CONTAINED_UID1001")
    cg = Path("/proc/self/cgroup").read_text().strip()
    require(cg == "0::" + BASE + "/" + SERVICE, "HOST_RESERVED_SERVICE_REQUIRED")
    require(os.getpriority(os.PRIO_PROCESS, 0) == 19, "HOST_NICE19_REQUIRED")
    parent = Path("/sys/fs/cgroup") / BASE.lstrip("/")
    require((parent / "cpu.max").read_text().strip() == "200000 100000" and
            (parent / "memory.max").read_text().strip() == "4294967296" and
            (parent / "pids.max").read_text().strip() == "2048" and
            (parent / "cgroup.freeze").read_text().strip() == "0", "HOST_SHARED_QUOTA")
    leaf = Path("/sys/fs/cgroup") / cg.removeprefix("0::/")
    require({name: (leaf / name).read_text().strip() for name in
             ["cpu.max", "memory.max", "pids.max", "cgroup.freeze"]} == {
                "cpu.max": "200000 100000", "memory.max": "268435456", "pids.max": "128",
                "cgroup.freeze": "0"}, "HOST_LEAF_QUOTA")
    config = TASK / "client/cli-config"
    info = config.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1001 and stat.S_IMODE(info.st_mode) == 0o700 and
            not any(config.iterdir()), "EXACT_EMPTY_DOCKER_CONFIG_REQUIRED")
    RAW_INPUT = Path(raw_file).absolute()
    require(RAW_INPUT.name == "pending-signed-transaction.raw" and
            str(RAW_INPUT).startswith(str(TASK / "client/diagnostics") + "/") and ".." not in RAW_INPUT.parts,
            "SCOPED_PUBLIC_RAW_INPUT_REQUIRED")
    public_parent = TASK / "client/diagnostics"
    require(RAW_INPUT.parent != public_parent, "NEW_PUBLIC_INPUT_SUBDIRECTORY_REQUIRED")
    current = public_parent
    for part in (".", *RAW_INPUT.parent.relative_to(public_parent).parts):
        current = current / part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1001 and
                stat.S_IMODE(info.st_mode) == 0o700, "PUBLIC_INPUT_PARENT_OWNERSHIP")
    read_raw_transaction(RAW_INPUT)
    require(not os.path.lexists(OUTPUT), "NEW_HOST_RECEIPT_DIRECTORY_REQUIRED")
    OUTPUT.mkdir(mode=0o700)
    docker = Docker()
    default = Docker("unix:///var/run/docker.sock")
    require(default.call(["info", "--format", "{{.ID}}"] ).stdout.decode().strip() == DEFAULT_ENGINE and
            not default.call(["ps", "--format", "{{.ID}}"] ).stdout.strip(), "DEFAULT_ENGINE_BASELINE")
    before = guard_original(docker)
    require(not docker.call(["ps", "--format", "{{.ID}}"] ).stdout.strip(), "PRIVATE_ENGINE_NOT_IDLE")
    idle = cpu_readiness()
    require(docker.value(["image", "inspect", "--format",
        '{"id":{{json .Id}},"arch":{{json .Architecture}},"os":{{json .Os}}}', IMAGE]) ==
        {"id": IMAGE, "arch": "amd64", "os": "linux"}, "QUALIFIED_NATIVE_IMAGE_REQUIRED")
    for kind, name in [("volume", CLONE_VOLUME), ("container", CLONE_CONTAINER),
                       ("container", CLONE_CONTAINER + "-init"), ("container", CLONE_CONTAINER + "-copy")]:
        projection = "{{json .Id}}" if kind == "container" else "{{json .Name}}"
        value = docker.call([kind, "inspect", "--format", projection, name], check=False)
        require_missing(value, kind, name)
    volume_command = ["volume", "create"]
    for key, item in LABELS.items():
        volume_command += ["--label", key + "=" + item]
    docker.call([*volume_command, CLONE_VOLUME])
    common = ["--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--cgroupns", "host", "--cpus", "2"]
    helper_mount = "type=bind,source=" + str(SELF) + ",target=/opt/receiver_forensic.py,readonly"
    clone_mount = "type=volume,source=" + CLONE_VOLUME + ",target=/clone,volume-nocopy"
    init = ('import json,os,pathlib,re;'
            'cg=pathlib.Path("/proc/self/cgroup").read_text().strip();'
            'base=' + repr(BASE) + ';'
            'assert re.fullmatch(re.escape("0::"+base)+r"/docker-[0-9a-f]{64}[.]scope",cg);'
            'parent=pathlib.Path("/sys/fs/cgroup")/base.lstrip("/");'
            'leaf=pathlib.Path("/sys/fs/cgroup")/cg.removeprefix("0::/");'
            'names=["cpu.max","memory.max","pids.max","cgroup.freeze"];'
            'a={n:(parent/n).read_text().strip() for n in names};'
            'b={n:(leaf/n).read_text().strip() for n in names};'
            'assert a=={"cpu.max":"200000 100000","memory.max":"4294967296","pids.max":"2048","cgroup.freeze":"0"};'
            'assert b=={"cpu.max":"200000 100000","memory.max":"134217728","pids.max":"64","cgroup.freeze":"0"};'
            'p=pathlib.Path("/clone");assert not any(p.iterdir());'
            'os.chown(p,1001,1000);os.chmod(p,0o700);'
            'print(json.dumps({"cgroup":cg,"parent_limits":a,"leaf_limits":b},sort_keys=True))')
    label_args = [item for key, value in LABELS.items() for item in ["--label", key + "=" + value]]
    result = {"schema": "PQBTC-L-RESEARCH-RECEIVER-CLONE-FORENSIC-1", "result": "FAIL", "helper_sha256": expected_sha,
              "source_image": IMAGE, "target_txid": TARGET_TXID, "raw_sha256": TARGET_RAW_SHA,
              "original_source_stopped_before": before, "host_cpu_readiness": idle, "public_soak_credit_seconds": 0}
    created_id = None
    try:
        # CHOWN exists only in this generic initializer; original is not mounted.
        result["initializer_boundary"] = docker.value(["run", "--rm", "--name", CLONE_CONTAINER + "-init", *common, "--cap-add", "CHOWN",
                     "--memory", "134217728", "--pids-limit", "64", "--user", "0:0", *label_args,
                     "--label", "org.pqbtc.forensics.role=init", "--mount", clone_mount,
                     IMAGE, "python3", "-I", "-B", "-c", init])
        require(guard_original(docker) == before, "ORIGINAL_CHANGED_BEFORE_COPY")
        copy = docker.value(["run", "--rm", "--name", CLONE_CONTAINER + "-copy", *common,
            "--memory", "536870912", "--pids-limit", "128", "--user", "1001:1000",
            *label_args, "--label", "org.pqbtc.forensics.role=copy",
            "--mount", "type=volume,source=" + SOURCE_VOLUME + ",target=/original,readonly,volume-nocopy",
            "--mount", clone_mount, "--mount", helper_mount, IMAGE, "python3", "-I", "-B",
            "/opt/receiver_forensic.py", "--contained-copy", "--expected-helper-sha256", expected_sha], timeout=360)
        write_json(OUTPUT / "copy-receipt.json", copy)
        require(copy.get("result") == "PASS" and copy.get("source_marker_verified") is True, "COPY_RECEIPT_REFUSED")
        require(guard_original(docker) == before, "ORIGINAL_CHANGED_BEFORE_NATIVE")
        args = ["create", "--name", CLONE_CONTAINER, *common, "--memory", "1073741824", "--pids-limit", "256", "--user", "1001:1000",
                "--mount", clone_mount, "--mount", helper_mount, "--mount",
                "type=bind,source=" + str(RAW_INPUT) + ",target=/public-input/pending.raw,readonly"]
        for key, item in LABELS.items():
            args += ["--label", key + "=" + item]
        created_id = docker.call([*args, IMAGE, "sleep", "infinity"]).stdout.decode().strip()
        require(re.fullmatch("[0-9a-f]{64}", created_id) and created_id != SOURCE_ID and
                validate_clone_for_stop(selected_inspect(docker, CLONE_CONTAINER)) == created_id, "NEW_NATIVE_CONTAINER_IDENTITY")
        docker.call(["start", created_id])
        native = docker.value(["exec", "--user", "1001:1000", created_id, "python3", "-I", "-B",
            "/opt/receiver_forensic.py", "--contained-native", "--expected-helper-sha256", expected_sha], timeout=300)
        write_json(OUTPUT / "native-admission-receipt.json", native)
        require(native.get("result") == "PASS" and native.get("node_stop_clean") is True, "NATIVE_DIAGNOSTIC_INCOMPLETE")
        result.update({"result": "PASS", "copy_files": copy["file_count"], "copy_selected_bytes": copy["selected_bytes"],
                       "native_verdict": native["native_verdict"], "context": native["context_before"]})
    except BaseException as error:
        result["guard"] = str(error) if isinstance(error, Refusal) else "OPAQUE_HOST_DIAGNOSTIC_FAILURE"
    finally:
        try:
            result["cleanup"] = cleanup_native(docker, created_id)
        except BaseException:
            result["result"] = "FAIL"
            result["cleanup"] = {"backend_stopped": False, "guard": "OWNED_CLONE_STOP_UNCERTAIN"}
        try:
            result["temporary_helpers"] = [stop_temporary(docker, role) for role in ["copy", "init"]]
        except BaseException:
            result["result"] = "FAIL"
            result["temporary_helpers"] = {"stopped": False, "guard": "TEMPORARY_CLEANUP_UNCERTAIN"}
        try:
            result["original_source_stopped_after"] = guard_original(docker)
            require(result["original_source_stopped_after"] == before, "ORIGINAL_METADATA_CHANGED")
            result["original_source_metadata_unchanged"] = True
            require(default.call(["info", "--format", "{{.ID}}"] ).stdout.decode().strip() == DEFAULT_ENGINE and
                    not default.call(["ps", "--format", "{{.ID}}"] ).stdout.strip(), "DEFAULT_ENGINE_CHANGED")
            result["default_engine_unchanged_idle"] = True
        except BaseException:
            result["result"] = "FAIL"
            result["original_source_metadata_unchanged"] = False
        write_json(OUTPUT / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-receiver-diagnostic", action="store_true")
    mode.add_argument("--contained-copy", action="store_true")
    mode.add_argument("--contained-native", action="store_true")
    parser.add_argument("--expected-helper-sha256", required=True)
    parser.add_argument("--raw-file")
    args = parser.parse_args()
    try:
        self_pin(args.expected_helper_sha256)
        if args.contained_copy:
            result = contained_copy()
        elif args.contained_native:
            result = contained_native()
        else:
            require(args.raw_file is not None, "RAW_FILE_ARGUMENT_REQUIRED")
            result = host_run(args.expected_helper_sha256, args.raw_file)
    except BaseException as error:
        result = {"result": "FAIL", "guard": str(error) if isinstance(error, Refusal) else "OPAQUE_ENTRY_FAILURE"}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result.get("result") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
