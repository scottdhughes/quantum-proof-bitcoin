#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Declared two-host public TEST soak; only 86,400 actual seconds can pass.

The operator supplies existing hosts, public TLS ingress and prequalified source
images. No hosting is rented. Disposable test-wallet operator material travels
only through agent stdin, is never persisted, and cannot be recovered on resume.
An interrupted attempt is FAIL; a new attempt starts from zero elapsed time.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONFIG_SCHEMA = "PQBTC-MLDSA44-PUBLIC-SOAK-CONFIG-1"
DECLARATION_SCHEMA = "PQBTC-MLDSA44-PUBLIC-SOAK-DECLARATION-1"
RESULT_SCHEMA = "PQBTC-MLDSA44-PUBLIC-SOAK-RESULT-1"
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
NODE = "/tmp/mldsa-demo-build/bin/pqbtcd"
SIGNER = "/tmp/demo-signer-bin/pilot-signer"
SOURCE_PREFIX = "/tmp/mldsa-demo-source/"
CONTROL_FILES = ("contrib/ml-dsa-qualification/public_soak_agent.py",
                 "contrib/ml-dsa-console/public_controller.py", "contrib/ml-dsa-qualification/public_transport.py")
CLAIM_SCHEMA = "PQBTC-MLDSA44-SOAK-ATTEMPT-CLAIM-1"
CLAIM_FILE = ".public-soak-attempt.json"
FAULTS = (("crash", 2 * 3600), ("partition", 4 * 3600), ("hostile", 6 * 3600),
          ("old_backup_missing_record", 8 * 3600), ("reindex", 12 * 3600),
          ("upgrade", 16 * 3600), ("rollback", 18 * 3600))
REQUIRED_CHECKS = {"integration-normal", "integration-asan-ubsan", "signer-normal", "signer-asan-ubsan",
                   "key-lifecycle-normal-and-sanitized", "node-profile-and-resource-units",
                   "actual-node-spend-old-record-restore", "actual-public-accepted-set-and-both-reindex-paths",
                   "actual-node-30-full-blocks-and-mempool-pressure"}
PRIVATE_FIELDS = {"password", "passphrase", "secret", "ciphertext", "operator_input", "private_key", "seed"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON member")
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def hex64(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def public_value(value, operator_values=()):
    if type(value) is dict:
        require(not PRIVATE_FIELDS.intersection(value), "Private material cannot enter public soak evidence")
        for item in value.values():
            public_value(item, operator_values)
    elif type(value) is list:
        for item in value:
            public_value(item, operator_values)
    elif type(value) is str:
        require(not any(secret and secret in value for secret in operator_values), "Operator material detected in public output")
    else:
        require(value is None or type(value) in (bool, int) or type(value) is float and math.isfinite(value),
                "Public evidence accepts only finite JSON values")
    return value


def duration_for(mode):
    require(mode in ("soak", "preflight"), "Choose soak or preflight")
    return 86400 if mode == "soak" else 900


def require_elapsed(mode, monotonic_seconds, wall_seconds):
    duration = duration_for(mode)
    require(finite(monotonic_seconds) and finite(wall_seconds) and
            monotonic_seconds >= duration and wall_seconds >= duration,
            "Full actual monotonic and UTC elapsed duration is required")
    return "PASS" if mode == "soak" else "PREFLIGHT_PASS"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def load_public_json(path, maximum=4 * 1024 * 1024):
    path = Path(path)
    require(not any(part.lower() in {".env", ".ssh", "credentials", "credentials.json", "id_rsa", "id_ed25519"}
                    or part.lower().startswith(".env.") for part in path.parts), "Sensitive named input refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                info.st_mode & 0o022 == 0 and info.st_size <= maximum, "Owned, bounded, non-writable-by-others JSON input required")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
        require(len(raw) <= maximum, "JSON input size bound")
        return parsed(raw), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def write_immutable(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = canonical(value) + b"\n"
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(data).hexdigest()


class EventLog:
    def __init__(self, path, *, secrets=()):
        self.path = Path(path)
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.last, self.count, self.secrets = "00" * 32, 0, tuple(secrets)
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    def append(self, kind, data):
        require(type(kind) is str and re.fullmatch(r"[a-z0-9_]{1,64}", kind), "Invalid evidence event kind")
        public_value(data, self.secrets)
        value = {"sequence": self.count, "utc": utc(), "monotonic_ns": time.monotonic_ns(),
                 "kind": kind, "data": data, "previous_sha256": self.last}
        value["sha256"] = hashlib.sha256(canonical(value)).hexdigest()
        raw = canonical(value) + b"\n"
        require(len(raw) <= 2 * 1024 * 1024, "Soak evidence event bound")
        offset = 0
        while offset < len(raw):
            offset += os.write(self.fd, raw[offset:])
        os.fsync(self.fd)
        self.last, self.count = value["sha256"], self.count + 1
        return value["sha256"]

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def verify_events(path):
    prior, count, last_time = "00" * 32, 0, -1
    clocks = {}
    with Path(path).open("rb") as handle:
        for raw in handle:
            require(len(raw) <= 2 * 1024 * 1024 and raw.endswith(b"\n"), "Truncated or oversized evidence event")
            value = parsed(raw)
            digest = value.pop("sha256")
            require(value.get("sequence") == count and value.get("previous_sha256") == prior and
                    type(value.get("monotonic_ns")) is int and value["monotonic_ns"] >= last_time and
                    hex64(digest) and hashlib.sha256(canonical(value)).hexdigest() == digest,
                    "Soak evidence sequence, clock or hash chain changed")
            public_value(value)
            if value.get("kind") in ("public_clock_started", "public_clock_completed"):
                key = value["kind"]
                require(key not in clocks, "Duplicate public clock boundary")
                clocks[key] = {"utc": value["utc"], "monotonic_ns": value["monotonic_ns"], "data": value["data"]}
            prior, count, last_time = digest, count + 1, value["monotonic_ns"]
    return {"count": count, "last_sha256": prior, "clock_boundaries": clocks}


def require_event_duration(chain, mode):
    bounds = chain.get("clock_boundaries", {})
    require(set(bounds) == {"public_clock_started", "public_clock_completed"}, "Actual public event clock boundaries are missing")
    start, end = bounds["public_clock_started"], bounds["public_clock_completed"]
    monotonic = (end["monotonic_ns"] - start["monotonic_ns"]) / 1_000_000_000
    first, last = datetime.fromisoformat(start["utc"]), datetime.fromisoformat(end["utc"])
    require(first.tzinfo is not None and last.tzinfo is not None and first.utcoffset().total_seconds() == 0 and
            last.utcoffset().total_seconds() == 0 and start["data"].get("duration_seconds") == duration_for(mode),
            "Declared UTC event clock duration differs")
    wall = (last - first).total_seconds()
    require_elapsed(mode, monotonic, wall)
    return {"monotonic_seconds": monotonic, "wall_seconds": wall}


def begin_workload(run, log, report, mode, public_probe):
    # The fsynced event precedes the duration origin. Even a slow append/fsync
    # cannot make the independently observed event span shorter than the run.
    log.append("public_clock_started", {"duration_seconds": duration_for(mode), "public_probe": public_probe})
    run.started_mono, run.started_wall = time.monotonic(), time.time()
    report["started_utc"] = utc()


class FloorGuard:
    def __init__(self):
        self.floors, self.addresses, self.paths = {}, set(), set()

    def observe(self, host, status):
        wallet = status.get("wallet", {})
        identity = wallet.get("wallet_id")
        require(type(identity) is str and re.fullmatch(r"[0-9a-f]{32}", identity), "Public wallet identity missing")
        point = {key: wallet.get(key) for key in ("next_receive", "next_change")}
        require(all(type(value) is int and 0 <= value < 2**31 for value in point.values()), "Public address floors invalid")
        prior = self.floors.get(host)
        if prior:
            require(prior["wallet_id"] == identity and all(point[key] >= prior[key] for key in point),
                    "Terminal wallet identity change or address floor rollback")
        require(not any(other != host and value["wallet_id"] == identity for other, value in self.floors.items()),
                "The two hosts must not share cloned signer custody")
        self.floors[host] = {"wallet_id": identity, **point}

    def snapshot(self, host):
        return dict(self.floors[host])

    def issued(self, host, entry, before):
        require(type(entry) is dict and entry.get("branch") == 0 and type(entry.get("index")) is int and
                entry["index"] >= before["next_receive"] and entry["index"] < self.floors[host]["next_receive"] and
                type(entry.get("address")) is str and entry["address"].startswith("tq1"), "Receive operation reused or understated a path")
        key = (host, entry["branch"], entry["index"])
        require(key not in self.paths and entry["address"] not in self.addresses, "Address or derivation path was reused")
        self.paths.add(key)
        self.addresses.add(entry["address"])


class SlotLedger:
    def __init__(self, mode):
        self.mode, self.rows = mode, []
        self.interval = 60 if mode == "soak" else 5

    def success(self, index, settle_seconds, *, started_elapsed=None):
        require(index == len(self.rows) and finite(settle_seconds) and 0 <= settle_seconds <= 60,
                "Out-of-order payment slot or settlement exceeded sixty seconds")
        require(finite(started_elapsed) and index * self.interval <= started_elapsed < (index + 1) * self.interval,
                "Normal payment did not actually start within its declared slot")
        self.rows.append({"slot": index, "success": True, "settle_seconds": settle_seconds,
                          "payment_started_elapsed": started_elapsed})

    def missed(self, index, phases):
        require(index == len(self.rows), "Out-of-order missing payment slot")
        start, end = index * self.interval, (index + 1) * self.interval
        matches = [phase for phase in phases if phase.get("name") in dict(FAULTS) and
                   finite(phase.get("started_elapsed")) and finite(phase.get("finished_elapsed")) and
                   start < phase["finished_elapsed"] and end > phase["started_elapsed"]]
        require(matches, "Unexplained missed workload slot is terminal")
        self.rows.append({"slot": index, "success": False, "fault": matches[0]["name"]})


def validate_qualified_version(descriptor, receipt):
    source = load_module(ROOT / "contrib/ml-dsa-console/source_runtime.py", "soak_source_runtime")
    descriptor = source.validate_descriptor(descriptor)
    manifest = descriptor["manifest"]
    require(type(receipt) is dict and receipt.get("schema") == "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1" and
            receipt.get("result") == "PASS" and receipt.get("public_soak") is False and receipt.get("emulated") is False and
            receipt.get("image") == descriptor["image"] and receipt.get("manifest_sha256") == descriptor["manifest_sha256"] and
            receipt.get("source") == {"head": manifest["source_head"], "tree": manifest["source_tree"]},
            "Each version needs a matching exact-source native qualification PASS receipt")
    qualify = load_module(HERE / "run_native_qualification.py", "soak_native_qualification")
    arch = qualify.normalize_architecture(manifest["architecture"])
    require(qualify.normalize_architecture(receipt.get("architecture")) == arch and
            receipt.get("compiler") == manifest["compiler"] and
            all(receipt.get("checks", {}).get(name) == "PASS" for name in REQUIRED_CHECKS),
            "Native architecture/compiler or required qualification checks are missing")
    for field in ("identity_before", "identity_after"):
        value = receipt.get(field, {})
        require(value.get("head") == manifest["source_head"] and value.get("tree") == manifest["source_tree"] and
                all(value.get("sha256", {}).get(path) == manifest["sha256"].get(path) for path in (NODE, SIGNER)),
                "Qualified node/signer binary receipt does not match the source image")
    require(receipt.get("cleanup") in ("REMOVED", "STOPPED_RETAINED"), "Native qualification cleanup did not complete")
    return {"descriptor": descriptor, "architecture": arch, "source_head": manifest["source_head"],
            "source_tree": manifest["source_tree"], "image": descriptor["image"],
            "node_sha256": manifest["sha256"][NODE], "signer_sha256": manifest["sha256"][SIGNER]}


def validate_version_pair(first, second):
    require(first["architecture"] == second["architecture"] and first["source_head"] != second["source_head"] and
            first["source_tree"] != second["source_tree"] and first["image"] != second["image"] and
            first["node_sha256"] != second["node_sha256"],
            "Upgrade/rollback requires two genuinely distinct qualified source and node binary versions")


def validate_adverse(value):
    require(value.get("baseline_accepted") is True and value.get("invalid_signature_allowed") is False and
            value.get("wrong_network_refused") is True and value.get("broadcast") is False and
            type(value.get("reject_reason")) is str and "script-verify" in value["reject_reason"],
            "Actual adverse signature verification rejection or wrong-network HELLO control failed")


def host_exec(host, arguments):
    arguments = list(map(str, arguments))
    if host["transport"]["kind"] == "local":
        return arguments
    return [*host["transport"]["argv"], shlex.join(arguments)]


def host_json(host, arguments, *, timeout=45):
    completed = subprocess.run(host_exec(host, arguments), capture_output=True, timeout=timeout)
    require(completed.returncode == 0 and len(completed.stdout) <= 4 * 1024 * 1024,
            "Independent owned-host helper failed or exceeded its response bound")
    value = parsed(completed.stdout)
    require(type(value) is dict, "Independent owned-host helper did not return an object")
    return public_value(value)


PRELAUNCH_SCRIPT = r'''import hashlib,json,os,pathlib,stat,subprocess,sys
p=json.loads(sys.argv[1]); root=pathlib.Path(p['repo'])
def git(*args):
 return subprocess.check_output(['git','-C',str(root),*args],timeout=20).decode().strip()
head,tree=git('rev-parse','HEAD'),git('rev-parse','HEAD^{tree}')
assert [head,tree] in p['approved_revisions'] and not git('status','--porcelain=v1','--untracked-files=all'),'unapproved or dirty agent checkout'
def hashed(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd); assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=4194304
  raw=os.read(fd,4194305); assert len(raw)<=4194304; return hashlib.sha256(raw).hexdigest()
 finally: os.close(fd)
identity={'source_head':head,'source_tree':tree,'clean':True,
 'control_sha256':{name:hashed(name) for name in p['control_files']}}
raw=subprocess.check_output(p['docker']+['info','--format','{"architecture":{{json .Architecture}},"daemon_id":{{json .ID}}}'],timeout=20)
d=json.loads(raw); identity.update(docker_architecture=d['architecture'],docker_daemon_id=d['daemon_id'])
print(json.dumps(identity,sort_keys=True))
'''


def validate_prelaunch(host, value):
    qualify = load_module(HERE / "run_native_qualification.py", "soak_live_architecture")
    require(value.get("clean") is True and type(value.get("docker_daemon_id")) is str and
            8 <= len(value["docker_daemon_id"]) <= 256, "Agent checkout must be clean and actual Docker daemon identity must be known")
    for label in ("a", "b"):
        version = host["versions"][label]["qualified"]
        if (value.get("source_head"), value.get("source_tree")) == (version["source_head"], version["source_tree"]):
            require(qualify.normalize_architecture(value.get("docker_architecture")) == version["architecture"],
                    "Actual Docker architecture would emulate the declared qualified image")
            expected = version["descriptor"]["manifest"]["sha256"]
            require(all(hex64(expected.get(SOURCE_PREFIX + path)) and value.get("control_sha256", {}).get(path) ==
                        expected[SOURCE_PREFIX + path] for path in CONTROL_FILES),
                    "Actual host control code differs from the approved source image")
            return {**value, "approved_control_version": label}
    raise ValueError("Host agent checkout HEAD/tree is neither qualified source version")


def prelaunch_host(host):
    payload = {"repo": host["repo"], "control_files": list(CONTROL_FILES),
               "approved_revisions": [[version["qualified"]["source_head"], version["qualified"]["source_tree"]]
                                      for version in host["versions"].values()],
               "docker": ["sudo", "-n", "docker"] if host["sudo_docker"] else ["docker"]}
    return validate_prelaunch(host, host_json(host, ["python3", "-I", "-c", PRELAUNCH_SCRIPT, canonical(payload).decode()]))


def require_distinct_daemons(hosts):
    require(len(hosts) == 2 and len({value["docker_daemon_id"] for value in hosts.values()}) == 2,
            "Both host controls target the same Docker daemon")


NAMESPACE_SCRIPT = r'''import json,os,pathlib,stat,subprocess,sys
p=json.loads(sys.argv[1]); state=pathlib.Path(p['state_dir'])
def absent(kind,name):
 r=subprocess.run(p['docker']+[kind,'inspect','--format','{{json .}}',name],capture_output=True,timeout=15)
 if r.returncode==0: return False
 message=r.stderr.lower()
 assert b'no such object' in message or ('no such '+kind).encode() in message,'cannot establish namespace absence'
 return True
proof={'container_absent':absent('container',p['container']),'volume_absent':absent('volume',p['volume']),
 'state_dir_absent':not os.path.lexists(state)}
if p['operation']=='probe': print(json.dumps(proof,sort_keys=True))
else:
 assert p['operation']=='claim' and all(proof.values()),'public soak requires entirely fresh namespaces'
 claim=p['claim']; assert claim['container']==p['container'] and claim['volume']==p['volume']
 os.mkdir(state,0o700)
 directory=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  s=os.fstat(directory); assert s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
  fd=os.open('.public-soak-attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   raw=json.dumps(claim,sort_keys=True,separators=(',',':')).encode()+b'\n'; offset=0
   while offset<len(raw): offset+=os.write(fd,raw[offset:])
   os.fsync(fd)
  finally: os.close(fd)
  os.fsync(directory)
 finally: os.close(directory)
 parent=os.open(state.parent,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(parent)
 finally: os.close(parent)
 print(json.dumps({'claim':claim,'freshness':proof},sort_keys=True))
'''


def namespace_payload(host, operation):
    return {"state_dir": host["state_dir"], "container": host["container"], "volume": host["container"] + "-data-v1",
            "operation": operation, "docker": ["sudo", "-n", "docker"] if host["sudo_docker"] else ["docker"]}


def namespace_probe(host):
    value = host_json(host, ["python3", "-I", "-c", NAMESPACE_SCRIPT, canonical(namespace_payload(host, "probe")).decode()])
    require(set(value) == {"container_absent", "volume_absent", "state_dir_absent"} and
            all(type(flag) is bool for flag in value.values()), "Invalid public namespace absence proof")
    return value


def namespace_claim(host, attempt_id):
    require(type(attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", attempt_id), "Invalid soak attempt identity")
    claim = {"schema": CLAIM_SCHEMA, "attempt_id": attempt_id, "container": host["container"],
             "volume": host["container"] + "-data-v1", "port": host["p2p_port"], "profile_sha256": PROFILE}
    payload = {**namespace_payload(host, "claim"), "claim": claim}
    value = host_json(host, ["python3", "-I", "-c", NAMESPACE_SCRIPT, canonical(payload).decode()])
    require(value.get("claim") == claim and value.get("freshness") ==
            {"container_absent": True, "volume_absent": True, "state_dir_absent": True},
            "Public attempt claim did not establish fresh owned state")
    return claim


def funnel_snapshot(config, host, endpoint):
    port, hostport = str(endpoint["port"]), endpoint["hostname"] + ":" + str(endpoint["port"])
    require(type(config) is dict, "Funnel configuration object required")
    handler = config.get("TCP", {}).get(port)
    require(type(handler) is dict and handler.get("TCPForward") == "127.0.0.1:" + str(host["p2p_port"]) and
            handler.get("TerminateTLS") == endpoint["hostname"] and not handler.get("HTTPS") and not handler.get("HTTP") and
            not handler.get("ProxyProtocol") and config.get("AllowFunnel", {}).get(hostport) is True,
            "Declared public TLS port is not the exact owned loopback P2P handler")
    require(not any(key != hostport and key.endswith(":" + port) and enabled
                    for key, enabled in config.get("AllowFunnel", {}).items()), "Public TLS port is shared with an unrelated host route")
    require(not any(key.endswith(":" + port) for key in config.get("Web", {})),
            "Public TLS port also contains unrelated web handlers")
    require(not any(port in item.get("TCP", {}) or item.get("AllowFunnel", {}).get(hostport)
                    for item in config.get("Foreground", {}).values()), "Foreground route makes public port ownership ambiguous")
    return {"port": port, "host_port": hostport, "handler": copy.deepcopy(handler), "allow_funnel": True,
            "configuration_sha256": hashlib.sha256(canonical(config)).hexdigest()}


def same_funnel_handler(config, point):
    return (type(config) is dict and config.get("TCP", {}).get(point["port"]) == point["handler"] and
            config.get("AllowFunnel", {}).get(point["host_port"]) is True and
            not any(key != point["host_port"] and key.endswith(":" + point["port"]) and enabled
                    for key, enabled in config.get("AllowFunnel", {}).items()) and
            not any(key.endswith(":" + point["port"]) for key in config.get("Web", {})) and
            not any(point["port"] in item.get("TCP", {}) or item.get("AllowFunnel", {}).get(point["host_port"])
                    for item in config.get("Foreground", {}).values()))


def unrelated_funnel(config, point):
    result = copy.deepcopy(config)
    for group, key in (("TCP", point["port"]), ("AllowFunnel", point["host_port"])):
        if group in result:
            result[group].pop(key, None)
            if not result[group]:
                result.pop(group)
    return result


def read_funnel(host):
    return host_json(host, ["tailscale", "funnel", "status", "--json"])


VOLUME_SCRIPT = r'''import json,os,pathlib,stat,sys
p=json.loads(sys.argv[1]); path=pathlib.Path(p['state_dir'])/'public-runtime.json'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 s=os.fstat(fd); assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4194304
 data=os.read(fd,4194305); assert len(data)<=4194304; v=json.loads(data)
finally: os.close(fd)
print(json.dumps({'schema':v['schema'],'container':v['container'],'volume':v['volume'],'volume_id':v['volume_id'],
 'port':v['port'],'profile_sha256':v['compatibility']['profile_sha256'],'image':v['descriptor']['image'],
 'manifest_sha256':v['descriptor']['manifest_sha256']},sort_keys=True))
'''


def initial_volume(host):
    value = host_json(host, ["python3", "-I", "-c", VOLUME_SCRIPT, canonical({"state_dir": host["state_dir"]}).decode()])
    version = host["versions"]["a"]["qualified"]
    require(value.get("schema") == "PQBTC-MLDSA44-PUBLIC-RUNTIME-1" and value.get("container") == host["container"] and
            value.get("volume") == host["container"] + "-data-v1" and value.get("port") == host["p2p_port"] and
            value.get("profile_sha256") == PROFILE and value.get("image") == version["image"] and
            value.get("manifest_sha256") == version["descriptor"]["manifest_sha256"] and
            type(value.get("volume_id")) is str and re.fullmatch(r"[0-9a-f]{32}", value["volume_id"]),
            "Initial public volume journal does not match the ensured live qualified runtime")
    return value


def require_original_volume(volumes, host, observed):
    require(host in volumes and observed == volumes[host], "Binary transition replaced the original persistent public volume identity")


EMERGENCY_STOP_SCRIPT = r'''import json,os,pathlib,re,stat,subprocess,sys
p=json.loads(sys.argv[1]); stopped=[]
def check(value,message):
 if not value: raise ValueError(message)
def inspect(selector):
 r=subprocess.run(p['docker']+['inspect','--format','{{json .}}',selector],capture_output=True,timeout=10)
 if r.returncode:
  check(b'No such object:' in r.stderr or b'No such container:' in r.stderr,'cannot determine owned container liveness')
  return None
 check(len(r.stdout)<=1048576,'container inspection response bound')
 return json.loads(r.stdout)
def private_json(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd); check(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=limit,'unsafe retained ownership metadata')
  raw=os.read(fd,limit+1); check(len(raw)<=limit,'retained ownership metadata bound'); return json.loads(raw)
 finally: os.close(fd)
claim=p.get('attempt_claim')
check(type(claim) is dict and claim.get('schema')=='PQBTC-MLDSA44-SOAK-ATTEMPT-CLAIM-1' and
 type(claim.get('attempt_id')) is str and re.fullmatch('[0-9a-f]{32}',claim['attempt_id']) and
 claim.get('container')==p['container'] and claim.get('volume')==p['container']+'-data-v1' and
 claim.get('port')==p['p2p_port'] and claim.get('profile_sha256')==p['profile'],'no ownership claim for this attempt')
root=pathlib.Path(p['state_dir']); check(private_json(root/'.public-soak-attempt.json',4096)==claim,'attempt ownership token changed')
journal=root/'public-runtime.json'
if not os.path.lexists(journal):
 check(inspect(p['container']) is None,'matching older container lacks this attempt retained volume identity; preserved')
 print(json.dumps({'backend_stopped':True,'state':'NO_BACKEND_CREATED','stopped_ids':[]})); raise SystemExit(0)
retained=private_json(journal,4194304)
check(retained.get('schema')=='PQBTC-MLDSA44-PUBLIC-RUNTIME-1' and retained.get('container')==p['container'] and
 retained.get('volume')==claim['volume'] and retained.get('port')==p['p2p_port'] and
 retained.get('compatibility',{}).get('profile_sha256')==p['profile'] and
 type(retained.get('volume_id')) is str and re.fullmatch('[0-9a-f]{32}',retained['volume_id']),'retained runtime does not belong to this attempt')
if p.get('expected_volume_id') is not None: check(retained['volume_id']==p['expected_volume_id'],'original attempt volume identity changed')
rd=retained.get('descriptor',{}); check(rd.get('image') in p['images'] and rd.get('manifest_sha256')==p['images'][rd['image']],'retained source image is not qualified')
def owned(v):
 labels=v.get('Config',{}).get('Labels',{}) or {}; image=v.get('Image')
 check(v.get('Name')=='/'+p['container'] and image in p['images'],'container name/image ownership changed')
 check(labels.get('org.pqbtc.console.schema')=='public-test-1' and
  labels.get('org.pqbtc.console.profile')==p['profile'] and labels.get('org.pqbtc.console.build')=='source-1' and
  labels.get('org.pqbtc.console.manifest')==p['images'][image],'container source/profile/manifest ownership changed')
 check(v.get('HostConfig',{}).get('PortBindings')=={'23833/tcp':[{'HostIp':'127.0.0.1','HostPort':str(p['p2p_port'])}]},'container P2P port ownership changed')
 mounts=v.get('Mounts',[])
 check(len(mounts)==1 and mounts[0].get('Type')=='volume' and mounts[0].get('Name')==claim['volume'] and mounts[0].get('Destination')=='/var/lib/pqbtc' and mounts[0].get('RW') is True,'container retained volume mount changed')
 check(type(v.get('Id')) is str and re.fullmatch('[0-9a-f]{64}',v['Id']) and type(v.get('State',{}).get('Running')) is bool,'immutable container identity/liveness missing')
 return v['Id']
def marker(image):
 r=subprocess.run(p['docker']+['volume','inspect','--format','{{json .}}',claim['volume']],capture_output=True,timeout=10)
 check(r.returncode==0 and len(r.stdout)<=1048576,'retained named volume unavailable'); v=json.loads(r.stdout)
 check(v.get('Name')==claim['volume'] and v.get('Driver')=='local' and v.get('Options') in (None,{}) and
  v.get('Labels')=={'org.pqbtc.console.schema':'public-test-1','org.pqbtc.console.profile':p['profile']},'retained named volume ownership changed')
 script="import json,os,stat;fd=os.open('/owned/identity.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_size<1024;print(json.dumps(json.loads(os.read(fd,1024))));os.close(fd)"
 r=subprocess.run(p['docker']+['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','268435456','--pids-limit','32','--mount','type=volume,source='+claim['volume']+',target=/owned,readonly,volume-nocopy',image,'python3','-I','-c',script],capture_output=True,timeout=20)
 check(r.returncode==0 and len(r.stdout)<=1024,'retained volume marker unavailable')
 m=json.loads(r.stdout); check(m.get('volume_id')==retained['volume_id'] and m.get('profile_sha256')==p['profile'],'actual volume marker does not match this attempt')
for attempt in range(4):
 v=inspect(p['container'])
 if v is None:
  print(json.dumps({'backend_stopped':True,'state':'ABSENT','stopped_ids':stopped})); break
 identity=owned(v)
 marker(v['Image'])
 if v['State']['Running']:
  r=subprocess.run(p['docker']+['stop','--time','1',identity],capture_output=True,timeout=15)
  check(r.returncode==0,'owned immutable container stop failed'); stopped.append(identity)
 after=inspect(identity)
 if after is not None:
  check(owned(after)==identity and after['State']['Running'] is False,'owned immutable container remains running')
 named=inspect(p['container'])
 if named is None or owned(named)==identity and named['State']['Running'] is False:
  print(json.dumps({'backend_stopped':True,'state':'STOPPED' if named else 'ABSENT','stopped_ids':stopped,'last_id':identity})); break
else: raise ValueError('owned agent kept replacing stopped containers')
'''


def emergency_stop_owned(host):
    images = {version["qualified"]["image"]: version["qualified"]["descriptor"]["manifest_sha256"]
              for version in host["versions"].values()}
    require(type(host.get("_attempt_claim")) is dict, "Cleanup refuses a container without this run's attempt claim")
    payload = {"container": host["container"], "p2p_port": host["p2p_port"], "profile": PROFILE, "images": images,
               "state_dir": host["state_dir"], "attempt_claim": host["_attempt_claim"], "expected_volume_id": host.get("_attempt_volume_id"),
               "docker": ["sudo", "-n", "docker"] if host["sudo_docker"] else ["docker"]}
    value = host_json(host, ["python3", "-I", "-c", EMERGENCY_STOP_SCRIPT, canonical(payload).decode()], timeout=100)
    require(value.get("backend_stopped") is True, "Independent owned backend shutdown was not established")
    return value


def agent_command(host, until_utc):
    command = ["python3", host["repo"] + "/contrib/ml-dsa-qualification/public_soak_agent.py", "--state-dir", host["state_dir"],
               "--descriptor", host["versions"]["a"]["remote_descriptor"], "--container", host["container"],
               "--p2p-port", str(host["p2p_port"]), "--until-utc", until_utc]
    if host["sudo_docker"]:
        command.append("--sudo-docker")
    if host["role"] == "bootstrap":
        command.append("--bootstrap")
    return host_exec(host, command)


def prepare_config(value):
    require(type(value) is dict and set(value) == {"schema", "hosts", "public_endpoint", "cleanup_public_route"} and
            value["schema"] == CONFIG_SCHEMA and type(value["cleanup_public_route"]) is bool,
            "Public soak configuration members invalid")
    sys.path.insert(0, str(HERE))
    from public_transport import PublicEndpoint
    endpoint = value["public_endpoint"]
    require(type(endpoint) is dict and set(endpoint) == {"hostname", "port", "public_ips"}, "Public endpoint configuration members")
    PublicEndpoint(endpoint["hostname"], endpoint["port"], tuple(endpoint["public_ips"]))
    hosts = value["hosts"]
    require(type(hosts) is list and len(hosts) == 2 and
            {host.get("role") for host in hosts} == {"bootstrap", "follower"}, "Exactly one bootstrap and one follower host are required")
    require(len({host.get("name") for host in hosts}) == 2, "Distinct public host names required")
    result = copy.deepcopy(value)
    for host in result["hosts"]:
        require(set(host) == {"name", "role", "transport", "repo", "state_dir", "container", "p2p_port", "sudo_docker", "versions"} and
                type(host["name"]) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", host["name"]) and
                type(host["container"]) is str and re.fullmatch(r"pqbtc-mldsa-public-soak-[a-z0-9][a-z0-9_.-]{0,60}", host["container"]),
                "Only new dedicated public soak host/container namespaces are accepted")
        require(type(host["p2p_port"]) is int and 1024 <= host["p2p_port"] <= 65535 and type(host["sudo_docker"]) is bool and
                all(type(host[key]) is str and host[key].startswith("/") and "\n" not in host[key] and "\0" not in host[key]
                    for key in ("repo", "state_dir")), "Host paths and published P2P port are invalid")
        transport = host["transport"]
        require(type(transport) is dict and transport.get("kind") in ("local", "ssh"), "Choose local or SSH transport")
        if transport["kind"] == "local":
            require(set(transport) == {"kind"}, "Local transport takes no SSH arguments")
        else:
            require(set(transport) == {"kind", "argv"} and type(transport["argv"]) is list and
                    len(transport["argv"]) >= 2 and transport["argv"][0] == "ssh" and
                    all(type(part) is str and part and "\n" not in part and "\0" not in part for part in transport["argv"]),
                    "Explicit SSH argv is required for the existing remote host")
            require(not any(part in ("-F", "-i", "-L", "-R", "-D") or
                            part.lower().startswith(("proxycommand=", "localcommand=", "remotecommand=")) for part in transport["argv"]),
                    "Agent SSH configuration cannot add forwarding, credential paths or shell hooks")
        require(type(host["versions"]) is dict and set(host["versions"]) == {"a", "b"}, "Both qualified versions are required")
        for label, version in host["versions"].items():
            require(type(version) is dict and set(version) == {"descriptor", "native_receipt", "remote_descriptor"} and
                    type(version["remote_descriptor"]) is str and version["remote_descriptor"].startswith("/") and
                    "\0" not in version["remote_descriptor"] and "\n" not in version["remote_descriptor"], "Qualified version paths invalid")
            descriptor, descriptor_hash = load_public_json(version["descriptor"])
            receipt, receipt_hash = load_public_json(version["native_receipt"], maximum=8 * 1024 * 1024)
            version["qualified"] = {**validate_qualified_version(descriptor, receipt),
                                    "descriptor_file_sha256": descriptor_hash, "native_receipt_sha256": receipt_hash}
        validate_version_pair(host["versions"]["a"]["qualified"], host["versions"]["b"]["qualified"])
    require({host["transport"]["kind"] for host in result["hosts"]} == {"ssh", "local"}, "Both existing hosts must participate")
    for label in ("a", "b"):
        require(len({(host["versions"][label]["qualified"]["source_head"], host["versions"][label]["qualified"]["source_tree"])
                     for host in result["hosts"]}) == 1, "Each declared version must use the same source revision on both platforms")
    return result


class AgentClient:
    """One sequential agent pipe; ambiguous operations are never resubmitted."""
    def __init__(self, host, until, operator_values):
        self.host, self.operator_values = host, tuple(operator_values)
        self.sequence, self.pending, self.stderr_tail = 0, bytearray(), b""
        self.stderr_hash, self.stderr_bytes = hashlib.sha256(), 0
        self.stderr_closed = False
        self.process = subprocess.Popen(agent_command(host, until), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0, close_fds=True)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(pipe.fileno(), False)
        try:
            ready = parsed(self._line(time.monotonic() + 60))
            require(ready.get("event") == "agent_ready" and ready.get("scope") == SCOPE and ready.get("until_utc") == until,
                    "Owned agent did not acknowledge its independent shutdown deadline")
        except BaseException:
            self.close()
            raise

    def _stderr(self):
        try:
            raw = os.read(self.process.stderr.fileno(), 65536)
        except BlockingIOError:
            return
        if raw:
            self.stderr_hash.update(raw)
            self.stderr_bytes += len(raw)
            combined = self.stderr_tail + raw
            require(not any(secret.encode() in combined for secret in self.operator_values),
                    "Terminal operator material leak in agent diagnostics")
            self.stderr_tail = combined[-4096:]
            require(self.stderr_bytes <= 4 * 1024 * 1024, "Agent diagnostic output bound exceeded")
        else:
            self.stderr_closed = True

    def _line(self, deadline):
        while time.monotonic() < deadline:
            split = self.pending.find(b"\n")
            if split >= 0:
                raw = bytes(self.pending[:split + 1])
                del self.pending[:split + 1]
                require(not any(secret.encode() in raw for secret in self.operator_values), "Terminal operator material leak in agent response")
                return raw
            require(len(self.pending) <= 1024 * 1024, "Compact agent response bound exceeded")
            remaining = min(1, max(0, deadline - time.monotonic()))
            inputs = [self.process.stdout] + ([] if self.stderr_closed else [self.process.stderr])
            readable = select.select(inputs, [], [], remaining)[0]
            if self.process.stderr in readable:
                self._stderr()
            if self.process.stdout in readable:
                raw = os.read(self.process.stdout.fileno(), 65536)
                require(raw, "Owned agent closed its response pipe")
                self.pending.extend(raw)
            require(self.process.poll() is None, "Owned agent exited unexpectedly")
        raise ValueError("Owned agent response deadline; ambiguous operations are not retried")

    def call(self, action, params=None, *, timeout=90):
        raw = canonical({"id": self.sequence, "action": action, "params": params or {}}) + b"\n"
        require(len(raw) <= 1024 * 1024, "Agent request size bound")
        deadline, offset = time.monotonic() + timeout, 0
        while offset < len(raw):
            remaining = min(1, max(0, deadline - time.monotonic()))
            require(remaining > 0, "Owned agent request deadline")
            if select.select([], [self.process.stdin], [], remaining)[1]:
                try:
                    offset += os.write(self.process.stdin.fileno(), raw[offset:])
                except BlockingIOError:
                    continue
        del raw
        value = parsed(self._line(deadline))
        require(type(value) is dict and value.get("id") == self.sequence and type(value.get("ok")) is bool,
                "Owned agent response sequence or framing mismatch")
        self.sequence += 1
        require(value["ok"], "Owned public action failed: " + action + " (" + str(value.get("error_class", "unknown")) + ")")
        result = value.get("data")
        require(type(result) is dict, "Public agent action result must be an object")
        return public_value(result, self.operator_values)

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        deadline = time.monotonic() + 90
        primary, proofs = None, {}
        try:
            while self.process.poll() is None and time.monotonic() < deadline:
                if self.stderr_closed:
                    try:
                        self.process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                elif select.select([self.process.stderr], [], [], 0.2)[0]:
                    self._stderr()
            require(self.process.poll() == 0, "Owned agent cleanup did not finish cleanly")
            self._stderr()
        except BaseException as error:
            primary = error
        try:
            if self.process.poll() is None:
                # Preserve a still-live independent watchdog if an unreachable
                # host prevents proof that its backend has first been stopped.
                proofs["before_termination"] = emergency_stop_owned(self.host)
                try:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=10)
                finally:
                    proofs["after_termination"] = emergency_stop_owned(self.host)
            else:
                # Clean EOF normally stops native children but leaves the
                # Docker supervisor sleeping. Stop that owned container too.
                proofs["after_exit"] = emergency_stop_owned(self.host)
        finally:
            # If the pre-termination stop could not be proved, retain the agent
            # and its watchdog rather than killing the only remaining guard.
            if self.process.poll() is None:
                raise ValueError("Backend shutdown unconfirmed; independent agent/watchdog was preserved")
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                if pipe and not pipe.closed:
                    pipe.close()
        if primary is not None:
            raise primary
        return {"exit_code": self.process.returncode, "stderr_bytes": self.stderr_bytes,
                "stderr_sha256": self.stderr_hash.hexdigest(), "backend_stop_proofs": proofs}


def validate_identity(value, version):
    require(value.get("image") == version["image"] and value.get("source_head") == version["source_head"] and
            value.get("source_tree") == version["source_tree"] and
            value.get("architecture") in (version["architecture"], "arm64" if version["architecture"] == "aarch64" else "amd64") and
            all(value.get("sha256", {}).get(path) == version["descriptor"]["manifest"]["sha256"][path] for path in (NODE, SIGNER)),
            "The live host does not match its declared qualified source/image/binaries")


def validate_phases(mode, phases):
    duration = duration_for(mode)
    require(type(phases) is list and len(phases) == len(FAULTS) and
            [row.get("name") for row in phases] == [name for name, _ in FAULTS], "Every declared fault phase must complete once")
    for row, (name, scheduled) in zip(phases, FAULTS):
        expected = scheduled * duration / 86400
        require(row.get("result") == "PASS" and finite(row.get("started_elapsed")) and finite(row.get("finished_elapsed")) and
                expected <= row["started_elapsed"] <= expected + 60 and
                0 <= row["finished_elapsed"] - row["started_elapsed"] <= 300,
                "Declared fault phase timing or recovery limit failed: " + name)
        payment = row.get("recovery_payment", {})
        require(type(payment) is dict and hex64(payment.get("txid")) and hex64(payment.get("block_hash")) and
                payment.get("sender") != payment.get("receiver") and payment.get("recipient_in_mempool") is True and
                finite(payment.get("settle_seconds")) and 0 <= payment["settle_seconds"] <= 60 and
                finite(payment.get("started_elapsed")) and finite(payment.get("completed_elapsed")) and
                row["started_elapsed"] <= payment["started_elapsed"] <= payment["completed_elapsed"] <= row["finished_elapsed"],
                "Fault phase lacks a fresh relayed/confirmed recovery payment inside its shared recovery budget")
    require(len({row["recovery_payment"]["txid"] for row in phases}) == len(phases), "Fault phases reused an earlier payment proof")


def validate_outcome(mode, elapsed_monotonic, elapsed_wall, ledger, phases, *, final_recovered_spend, cleanup_ok, public_start, public_end):
    result = require_elapsed(mode, elapsed_monotonic, elapsed_wall)
    validate_phases(mode, phases)
    expected = duration_for(mode) // ledger.interval
    require(len(ledger.rows) == expected and all(row["slot"] == index for index, row in enumerate(ledger.rows)),
            "Every declared normal workload slot needs an outcome")
    successful = [row for row in ledger.rows if row.get("success") is True]
    missed = [row for row in ledger.rows if row.get("success") is False]
    require(len(successful) + len(missed) == expected and successful, "Workload slot result missing")
    require(all(finite(row.get("payment_started_elapsed")) and row["slot"] * ledger.interval <=
                row["payment_started_elapsed"] < (row["slot"] + 1) * ledger.interval for row in successful),
            "Actual normal payment start times do not match their declared slots")
    if mode == "soak":
        require(len(successful) >= 1410 and len(missed) <= 30, "Declared normal payment/missed-slot budget failed")
    for row in missed:
        test = SlotLedger(mode)
        test.rows = [{}] * row["slot"]
        test.missed(row["slot"], phases)
        require(test.rows[-1]["fault"] == row.get("fault"), "Missing-slot fault attribution differs")
    latencies = sorted(row.get("settle_seconds") for row in successful)
    require(all(finite(value) and 0 <= value <= 60 for value in latencies), "Invalid normal payment settlement observations")
    p95 = latencies[math.ceil(len(latencies) * 0.95) - 1]
    require(final_recovered_spend is True and cleanup_ok is True and
            public_start.get("result") == public_end.get("result") == "PASS" and
            public_start.get("scope") == public_end.get("scope") == "ANONYMOUS_PUBLIC_TLS_NATIVE_P2P_HANDSHAKE_ONLY",
            "Final recovered spend, actual public route or owned cleanup did not complete")
    return {"result": result, "successful_normal_slots": len(successful), "missed_slots": len(missed),
            "p95_settle_seconds": p95, "elapsed_monotonic_seconds": elapsed_monotonic, "elapsed_wall_seconds": elapsed_wall}


class Soak:
    def __init__(self, config, mode, log, operator_values, until):
        self.config, self.mode, self.log, self.operator_values, self.until = config, mode, log, operator_values, until
        self.hosts = {host["name"]: host for host in config["hosts"]}
        self.bootstrap = next(host["name"] for host in config["hosts"] if host["role"] == "bootstrap")
        self.follower = next(host["name"] for host in config["hosts"] if host["role"] == "follower")
        self.agents, self.statuses, self.old_backups, self.old_backup_points, self.volumes = {}, {}, {}, {}, {}
        self.prelaunch, self.initial_volumes, self.funnel = {}, {}, None
        self.attempt_id, self.namespace_proofs, self.claims = secrets.token_hex(16), {}, {}
        self.guard, self.ledger, self.phases = FloorGuard(), SlotLedger(mode), []
        self.started_mono = self.started_wall = None
        self.last_sample = self.last_clock = None
        self.action_deadline = None

    def action(self, host, action, params=None, *, timeout=90):
        if self.action_deadline is not None:
            timeout = min(timeout, self.action_deadline - time.monotonic())
            require(timeout > 0, "Declared operation/fault recovery deadline passed")
        value = self.agents[host].call(action, params, timeout=timeout)
        if "status" in value:
            self.statuses[host] = value["status"]
            if value["status"].get("wallet", {}).get("wallet_id"):
                self.guard.observe(host, value["status"])
        elif action == "status":
            self.statuses[host] = value
            if value.get("wallet", {}).get("wallet_id"):
                self.guard.observe(host, value)
        self.log.append("action", {"host": host, "action": action, "result": value})
        return value["result"] if "status" in value and type(value.get("result")) is dict else value

    def statuses_now(self):
        for host in self.hosts:
            self.action(host, "status")
        return self.statuses

    def agree(self, *, peers=True, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            statuses = list(self.statuses_now().values())
            nodes = [value.get("nodes", []) for value in statuses]
            if all(len(value) == 1 for value in nodes):
                entries = [value[0] for value in nodes]
                if all(entries[0].get(field) is not None and entries[0].get(field) == entries[1].get(field)
                       for field in ("height", "tip", "utxo_hash", "utxo_count")) and (not peers or all(entry.get("peers", 0) >= 1 for entry in entries)):
                    require(hex64(entries[0]["tip"]) and hex64(entries[0]["utxo_hash"]), "Full UTXO/tip hashes missing")
                    return entries[0]
            time.sleep(0.1)
        raise ValueError("Two-host tip/full-UTXO/peer agreement deadline")

    def bridge(self):
        self.action(self.follower, "bridge_start", {**self.config["public_endpoint"], "until_utc": self.until})
        self.action(self.follower, "peer", {"endpoint": "127.0.0.1:23834"})
        return self.agree()

    def probe(self):
        sys.path.insert(0, str(HERE))
        from public_transport import PublicEndpoint, probe
        value = self.config["public_endpoint"]
        require(self.funnel is not None and same_funnel_handler(read_funnel(self.hosts[self.bootstrap]), self.funnel),
                "Declared public handler changed during the attempt")
        result = probe(PublicEndpoint(value["hostname"], value["port"], tuple(value["public_ips"])))
        self.log.append("anonymous_public_probe", result)
        return result

    def identity(self, host, label):
        value = self.action(host, "identity")
        validate_identity(value, self.hosts[host]["versions"][label]["qualified"])

    def receive(self, host):
        before = self.guard.snapshot(host)
        entry = self.action(host, "receive")
        self.guard.issued(host, entry, before)
        return entry["address"]

    def sample(self):
        now_mono, now_wall = time.monotonic(), time.time()
        if self.last_sample is not None:
            require(now_mono - self.last_sample <= 90, "Unexplained resource/workload monitoring gap")
        if self.last_clock is not None:
            require(abs((now_wall - self.last_clock[1]) - (now_mono - self.last_clock[0])) <= 5,
                    "Host sleep or clock discontinuity cannot count as uninterrupted soak time")
        self.last_sample, self.last_clock = now_mono, (now_mono, now_wall)
        for host in self.hosts:
            value = self.action(host, "sample")
            require(type(value.get("rss_bytes")) is int and 0 < value["rss_bytes"] <= 1024**3 and
                    type(value.get("peak_rss_bytes")) is int and value["rss_bytes"] <= value["peak_rss_bytes"] <= 1024**3 and
                    value.get("maxmempool_bytes") == 32_000_000 and type(value.get("mempool_usage_bytes")) is int and
                    0 <= value["mempool_usage_bytes"] <= 32_000_000, "Owned node memory/mempool resource bound failed")
            if self.hosts[host].get("transport", {}).get("kind") == "ssh":
                require(finite(value.get("whole_host_cpu_percent")) and 0 <= value["whole_host_cpu_percent"] < 90,
                        "Research host CPU budget exceeded")
            if host == self.follower:
                require(value.get("bridge_alive") is True, "Declared public bridge is not alive")

    def payment(self, sender, receiver):
        started = time.monotonic()
        outer_deadline = self.action_deadline
        self.action_deadline = min(started + 60, outer_deadline if outer_deadline is not None else float("inf"))
        try:
            address = self.receive(receiver)
            sent = self.action(sender, "send", {"address": address, "amount_sats": 100_000, "fee_sats": 5000}, timeout=60)
            require(sent.get("broadcast") is True and hex64(sent.get("txid")), "Actual test payment was not broadcast")
            while time.monotonic() < self.action_deadline:
                tx = self.action(receiver, "transaction", {"txid": sent["txid"]})
                require(tx.get("txid") == sent["txid"], "Receiver relay observation returned another transaction")
                if tx.get("in_mempool") is True:
                    break
                time.sleep(min(0.1, max(0, self.action_deadline - time.monotonic())))
            else:
                raise ValueError("Receiver did not observe actual transaction relay before mining")
            relay_seconds = time.monotonic() - started
            mined = self.action(sender, "mine", {"blocks": 1}, timeout=60)
            require(type(mined.get("blocks")) is list and len(mined["blocks"]) == 1 and hex64(mined["blocks"][0]), "Actual confirmation block missing")
            self.agree(timeout=max(0.1, self.action_deadline - time.monotonic()))
            for host in self.hosts:
                tx = self.action(host, "transaction", {"txid": sent["txid"], "block_hash": mined["blocks"][0]})
                require(tx.get("txid") == sent["txid"] and tx.get("confirmed") is True and
                        type(tx.get("confirmations")) is int and tx["confirmations"] >= 1 and
                        tx.get("block_hash") == mined["blocks"][0], "The specific public payment was not confirmed on both hosts")
            elapsed = time.monotonic() - started
            require(elapsed <= 60, "Payment settlement exceeded sixty seconds")
            origin = self.started_mono if self.started_mono is not None else started
            receipt = {"sender": sender, "receiver": receiver, "txid": sent["txid"], "block_hash": mined["blocks"][0],
                       "settle_seconds": elapsed, "recipient_in_mempool": True, "recipient_relay_seconds": relay_seconds,
                       "started_elapsed": started - origin, "completed_elapsed": time.monotonic() - origin}
            self.log.append("confirmed_payment", receipt)
            return receipt
        finally:
            self.action_deadline = outer_deadline

    def setup(self):
        for host, config in self.hosts.items():
            self.prelaunch[host] = prelaunch_host(config)
        require_distinct_daemons(self.prelaunch)
        for host, config in self.hosts.items():
            self.namespace_proofs[host] = namespace_probe(config)
        require(all(all(proof.values()) for proof in self.namespace_proofs.values()),
                "Public soak requires fresh container, volume and state-directory namespaces on BOTH hosts")
        candidate_funnel = funnel_snapshot(read_funnel(self.hosts[self.bootstrap]), self.hosts[self.bootstrap], self.config["public_endpoint"])
        for host, config in self.hosts.items():
            self.claims[host] = namespace_claim(config, self.attempt_id)
            config["_attempt_claim"] = self.claims[host]
        self.funnel = candidate_funnel
        self.log.append("prelaunch_bound", {"hosts": self.prelaunch, "public_route": self.funnel})
        for host, config in self.hosts.items():
            self.agents[host] = AgentClient(config, self.until, self.operator_values.values())
            self.action(host, "start", timeout=240)
            self.identity(host, "a")
            self.initial_volumes[host] = initial_volume(config)
            self.volumes[host] = self.initial_volumes[host]["volume_id"]
            config["_attempt_volume_id"] = self.volumes[host]
            self.log.append("initial_volume_bound", {"host": host, "identity": self.initial_volumes[host]})
            require(self.statuses[host].get("wallet", {}).get("wallet_id") is None,
                    "Only fresh disposable public test custody can enter a new soak attempt")
        self.probe()
        self.bridge()
        for host in self.hosts:
            self.action(host, "setup", {"password": self.operator_values[host]}, timeout=90)
            self.old_backup_points[host] = self.guard.snapshot(host)
            self.old_backups[host] = self.action(host, "backup")["id"]
            self.action(host, "unlock", {"password": self.operator_values[host]}, timeout=90)
            address = self.receive(host)
            self.action(host, "fund", {"address": address}, timeout=240)
            self.agree()
            require(self.statuses[host]["wallet"].get("spendable_sats", 0) > 100_000 + 5000,
                    "Both disposable wallets need actual mature native test coins")
        self.payment(self.bootstrap, self.follower)
        self.payment(self.follower, self.bootstrap)
        self.sample()

    def recover(self, host):
        before = self.guard.snapshot(host)
        require(all(before[key] > self.old_backup_points[host][key] for key in ("next_receive", "next_change")),
                "Recovery must use a genuinely old backup from before later issuance and sends")
        result = self.action(host, "quarantine_record", timeout=120)
        require(result.get("selected_record_missing") is True and result.get("independent_journal_preserved") is True,
                "Missing-record recovery did not preserve the independent public floor journal")
        recovered = self.action(host, "recover", {"backup_id": self.old_backups[host], "password": self.operator_values[host]}, timeout=240)
        require(recovered.get("wallet_id") == before["wallet_id"] and recovered.get("chain_snapshot_restored") is False and
                all(recovered.get(key, -1) >= before[key] for key in ("next_receive", "next_change")),
                "Old backup restore lowered identity/floors or restored a chain snapshot")
        self.bridge()

    def fault(self, name):
        started = time.monotonic()
        self.action_deadline = started + 300
        row = {"name": name, "started_elapsed": started - self.started_mono, "result": "FAIL"}
        self.log.append("fault_started", row)
        if name == "crash":
            result = self.action(self.follower, "crash", timeout=120)
            require(result.get("crashed") is True and result.get("restarted") is True, "Actual crash/restart did not run")
            self.action(self.follower, "unlock", {"password": self.operator_values[self.follower]})
            self.bridge()
            self.identity(self.follower, "a")
        elif name == "partition":
            for host in self.hosts:
                self.action(host, "network", {"active": False})
            left = self.action(self.bootstrap, "mine", {"blocks": 1})
            right = self.action(self.follower, "mine", {"blocks": 2})
            require(left.get("blocks") and right.get("blocks"), "Both partition branches must mine actual competing blocks")
            self.statuses_now()
            require(self.statuses[self.bootstrap]["nodes"][0]["tip"] != self.statuses[self.follower]["nodes"][0]["tip"],
                    "Partition did not create distinct competing tips")
            row["competing_tips"] = {host: self.statuses[host]["nodes"][0]["tip"] for host in self.hosts}
            hold = 60 if self.mode == "soak" else 5
            until = time.monotonic() + hold
            while time.monotonic() < until:
                self.sample()
                time.sleep(min(5, max(0, until - time.monotonic())))
            for host in self.hosts:
                self.action(host, "network", {"active": True})
            winning = self.bridge()
            require(winning["tip"] == right["blocks"][-1], "Rejoin did not select the longer-work partition branch")
            row["rejoined_tip"] = winning["tip"]
        elif name == "hostile":
            require(self.funnel is not None and same_funnel_handler(read_funnel(self.hosts[self.bootstrap]), self.funnel),
                    "Hostile control refused because the owned public handler changed")
            result = self.action(self.follower, "hostile", self.config["public_endpoint"], timeout=60)
            require(result.get("scope") == "BOUNDED_PUBLIC_P2P_OVERSIZED_HEADER_CONTROL" and
                    result.get("disconnect_observed") is True and result.get("invalid_accepted") is False,
                    "Bounded public hostile P2P control did not reject and disconnect")
            self.action(self.bootstrap, "clear_bans")
            self.bridge()
        elif name == "old_backup_missing_record":
            self.recover(self.bootstrap)
        elif name == "reindex":
            self.action(self.follower, "reindex", timeout=180)
            self.bridge()
        elif name in ("upgrade", "rollback"):
            label = "b" if name == "upgrade" else "a"
            for host in self.hosts:
                self.action(host, "lock")
                result = self.action(host, name, {"descriptor": self.hosts[host]["versions"][label]["qualified"]["descriptor"]}, timeout=240)
                previous = "a" if label == "b" else "b"
                require(result.get("data_rollback") is False and result.get("image") == self.hosts[host]["versions"][label]["qualified"]["image"] and
                        result.get("previous_image") == self.hosts[host]["versions"][previous]["qualified"]["image"] and
                        type(result.get("volume_id")) is str and result["volume_id"], "Binary transition image or retained volume receipt failed")
                require_original_volume(self.volumes, host, result["volume_id"])
                self.action(host, "unlock", {"password": self.operator_values[host]})
                self.identity(host, label)
                self.bridge()
        else:
            raise ValueError("Undeclared fault phase")
        require(time.monotonic() - started <= 300, "Declared fault recovery exceeded five minutes")
        self.agree()
        sender = self.bootstrap if name in ("old_backup_missing_record", "upgrade") else self.follower
        receiver = self.follower if sender == self.bootstrap else self.bootstrap
        row["recovery_payment"] = self.payment(sender, receiver)
        # Fault periods are explicit monitoring windows. The next normal sample
        # starts a new gap interval; clock discontinuity checks remain active.
        self.last_sample = time.monotonic()
        self.sample()
        row.update({"finished_elapsed": time.monotonic() - self.started_mono, "result": "PASS"})
        require(row["finished_elapsed"] - row["started_elapsed"] <= 300, "Declared fault recovery exceeded five minutes")
        self.phases.append(row)
        self.log.append("fault_completed", row)
        self.action_deadline = None

    def workload(self):
        duration = duration_for(self.mode)
        next_adverse, next_sample = 0, 0
        total = duration // self.ledger.interval
        while len(self.ledger.rows) < total:
            elapsed = time.monotonic() - self.started_mono
            for name, offset in FAULTS[len(self.phases):]:
                if elapsed >= offset * duration / 86400:
                    self.fault(name)
                    elapsed = time.monotonic() - self.started_mono
                else:
                    break
            index = len(self.ledger.rows)
            due, end = index * self.ledger.interval, (index + 1) * self.ledger.interval
            if elapsed >= end:
                self.ledger.missed(index, self.phases)
                self.log.append("normal_slot", self.ledger.rows[-1])
                continue
            if elapsed >= next_sample:
                self.sample()
                next_sample = time.monotonic() - self.started_mono + 30
            if elapsed >= next_adverse:
                for host in self.hosts:
                    result = self.action(host, "adverse")
                    validate_adverse(result)
                self.probe()
                next_adverse = elapsed + (600 if self.mode == "soak" else 60)
            # Maintenance performs real I/O. Its earlier time observation
            # cannot authorize a payment after this slot has already expired.
            elapsed = time.monotonic() - self.started_mono
            if elapsed >= end:
                self.ledger.missed(index, self.phases)
                self.log.append("normal_slot", self.ledger.rows[-1])
                continue
            if elapsed >= due:
                order = (self.bootstrap, self.follower) if index % 2 == 0 else (self.follower, self.bootstrap)
                payment_started = time.monotonic() - self.started_mono
                payment = self.payment(*order)
                self.ledger.success(index, payment["settle_seconds"], started_elapsed=payment_started)
                self.log.append("normal_slot", self.ledger.rows[-1])
            else:
                time.sleep(min(1, due - elapsed))
        while time.monotonic() - self.started_mono < duration or time.time() - self.started_wall < duration:
            if time.monotonic() - self.last_sample >= 30:
                self.sample()
            time.sleep(0.2)
        return {"monotonic_seconds": time.monotonic() - self.started_mono,
                "wall_seconds": time.time() - self.started_wall}

    def cleanup(self):
        result, errors = {}, []
        for host, agent in self.agents.items():
            try:
                result[host] = agent.close()
            except Exception as error:
                errors.append({"host": host, "error_class": type(error).__name__})
        if self.config["cleanup_public_route"]:
            host = self.hosts[self.bootstrap]
            try:
                if self.funnel is None:
                    result["task_public_route"] = "NO_ROUTE_CLAIMED_OR_MODIFIED"
                else:
                    before = read_funnel(host)
                    require(same_funnel_handler(before, self.funnel), "Public handler changed; preserved without a cleanup mutation")
                    others = unrelated_funnel(before, self.funnel)
                    privilege = (["sudo", "-n"] if host["transport"]["kind"] == "ssh" and host.get("sudo_docker") else [])
                    values = host_exec(host, [*privilege, "tailscale", "funnel", "--tls-terminated-tcp=" + self.funnel["port"], "off"])
                    completed = subprocess.run(values, capture_output=True, timeout=30)
                    require(completed.returncode == 0, "Task-only public TLS route cleanup failed")
                    after = read_funnel(host)
                    require(after.get("AllowFunnel", {}).get(self.funnel["host_port"]) is not True and
                            after.get("TCP", {}).get(self.funnel["port"]) in (None, self.funnel["handler"]) and
                            unrelated_funnel(after, self.funnel) == others, "Scoped Funnel cleanup changed an unrelated handler or left public access active")
                    result["task_public_route"] = {"state": "SCOPED_PUBLIC_PORT_DISABLED", "bound_handler": self.funnel,
                                                  "final_configuration_sha256": hashlib.sha256(canonical(after)).hexdigest()}
            except Exception as error:
                errors.append({"route_cleanup_error_class": type(error).__name__})
        else:
            result["task_public_route"] = ("BACKEND_AND_BRIDGE_STOPPED_ROUTE_CONFIG_RETAINED_FOR_OWNER" if self.agents
                                           else "NO_ATTEMPT_AGENTS_STARTED_ROUTE_UNTOUCHED")
        result["attempt_claims"] = {"attempt_id": self.attempt_id, "claimed_hosts": sorted(self.claims),
                                    "state_directories_preserved": True}
        self.log.append("cleanup", {"results": result, "errors": errors})
        require(not errors, "Owned public agent or task-route cleanup failed; inspect independent deadlines")
        return result


def checkout_identity():
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=30).decode().strip()
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "A clean committed host runner checkout is required")
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def declaration(config, mode, source, config_sha256, initial, *, prelaunch, volumes, funnel, attempt_id, namespace_proofs, claims):
    duration = duration_for(mode)
    hosts = []
    for host in config["hosts"]:
        versions = {}
        for label, value in host["versions"].items():
            versions[label] = {key: item for key, item in value["qualified"].items() if key != "descriptor"}
        hosts.append({"name": host["name"], "role": host["role"], "container": host["container"],
                      "transport": host["transport"]["kind"], "p2p_port": host["p2p_port"], "versions": versions})
    return {"schema": DECLARATION_SCHEMA, "scope": SCOPE, "profile_sha256": PROFILE, "mode": mode,
            "duration_seconds": duration, "normal_slot_seconds": 60 if mode == "soak" else 5,
            "amount_sats": 100_000, "fee_sats": 5000, "configuration_sha256": config_sha256,
            "host_runner_source": source, "hosts": hosts, "public_endpoint": config["public_endpoint"],
            "initial_status": initial, "host_execution_audit": prelaunch, "original_volume_identities": volumes,
            "owned_public_route": funnel, "attempt_id": attempt_id, "initial_namespace_absence": namespace_proofs,
            "atomic_attempt_claims": claims, "declared_at_utc": utc(),
            "faults": [{"name": name, "scheduled_elapsed_seconds": offset * duration / 86400,
                        "maximum_recovery_seconds": 300} for name, offset in FAULTS],
            "partition_hold_seconds": 60 if mode == "soak" else 5,
            "adverse_period_seconds": 600 if mode == "soak" else 60,
            "acceptance": {"successful_normal_slots_minimum": 1410 if mode == "soak" else 1,
                           "missed_slots_maximum": 30 if mode == "soak" else None,
                           "missed_slots_only_within_declared_fault_windows": True,
                           "settlement_p95_seconds_maximum": 60, "node_peak_rss_bytes_maximum": 1024**3,
                           "maxmempool_bytes": 32_000_000, "research_host_cpu_percent_below": 90,
                           "unexpected_monitoring_gap_seconds_maximum": 90,
                           "final_missing_record_recovery_and_confirmed_spend": True},
            "operator_material": "DISPOSABLE_TEST_ONLY_MEMORY_AND_AGENT_STDIN",
            "failure_policy": "terminal FAIL, owned cleanup, no resume or accumulated partial elapsed time",
            "scoped_funnel_port_cleanup": config["cleanup_public_route"], "production_admitted": False}


def main(argv=None):
    require(__debug__, "Optimized Python cannot produce soak evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("preflight", "soak"), default="preflight")
    args = parser.parse_args(argv)
    source = checkout_identity()
    value, config_hash = load_public_json(args.config)
    config = prepare_config(value)
    output = args.output_dir.resolve()
    require(output != ROOT and ROOT not in output.parents and not output.exists() and not args.output_dir.is_symlink(),
            "Choose a new soak evidence directory outside the checkout; attempts cannot resume")
    output.mkdir(mode=0o700, parents=True)
    operator_values = {host["name"]: secrets.token_urlsafe(32) for host in config["hosts"]}
    log = EventLog(output / "events.jsonl", secrets=operator_values.values())
    until = datetime.fromtimestamp(time.time() + duration_for(args.mode) + 3600, timezone.utc).isoformat(timespec="seconds")
    run = Soak(config, args.mode, log, operator_values, until)
    report = {"schema": RESULT_SCHEMA, "result": "FAIL", "scope": SCOPE, "mode": args.mode,
              "production_admitted": False, "host_runner_source": source, "configuration_sha256": config_hash,
              "agent_independent_shutdown_utc": until}
    candidate = False
    try:
        run.setup()
        public_start = run.probe()
        declared = declaration(config, args.mode, source, config_hash, run.statuses_now(),
                               prelaunch=run.prelaunch, volumes=run.initial_volumes, funnel=run.funnel,
                               attempt_id=run.attempt_id, namespace_proofs=run.namespace_proofs, claims=run.claims)
        report["declaration_sha256"] = write_immutable(output / "declaration.json", declared)
        log.append("declaration_bound", {"sha256": report["declaration_sha256"], "mode": args.mode})
        begin_workload(run, log, report, args.mode, public_start)
        elapsed = run.workload()
        require_elapsed(args.mode, elapsed["monotonic_seconds"], elapsed["wall_seconds"])
        log.append("public_clock_completed", elapsed)
        recovery_started = time.monotonic()
        run.action_deadline = recovery_started + 300
        run.recover(run.follower)
        run.payment(run.follower, run.bootstrap)
        require(time.monotonic() - recovery_started <= 300, "Final recovered spend exceeded five minutes")
        run.action_deadline = None
        public_end = run.probe()
        run.last_sample = time.monotonic()
        run.sample()
        run.agree()
        require(checkout_identity() == source, "Host runner source changed during the public attempt")
        report.update({"finished_utc": utc(), "elapsed": elapsed, "public_start": public_start, "public_end": public_end,
                       "slots": run.ledger.rows, "phases": run.phases, "final_status": run.statuses,
                       "final_recovered_spend": True})
        candidate = True
    except BaseException as error:
        report["error_class"] = type(error).__name__
        report["error"] = str(error)
        public_value(report, operator_values.values())
        log.append("attempt_failed", {"error_class": type(error).__name__, "detail": str(error)})
    finally:
        try:
            report["cleanup"] = run.cleanup()
            report["cleanup_ok"] = True
        except BaseException as error:
            report["cleanup_ok"] = False
            report["cleanup_error_class"] = type(error).__name__
            candidate = False
        try:
            if candidate:
                report.update(validate_outcome(args.mode, elapsed["monotonic_seconds"], elapsed["wall_seconds"],
                              run.ledger, run.phases, final_recovered_spend=True, cleanup_ok=report["cleanup_ok"],
                              public_start=public_start, public_end=public_end))
            else:
                report["result"] = "FAIL"
            log.append("attempt_completed", {"result": report["result"], "cleanup_ok": report["cleanup_ok"]})
        except BaseException as error:
            report["result"] = "FAIL"
            report["closure_error_class"] = type(error).__name__
        finally:
            log.close()
            try:
                report["event_chain"] = verify_events(output / "events.jsonl")
                if report["result"] in ("PASS", "PREFLIGHT_PASS"):
                    report["event_clock_elapsed"] = require_event_duration(report["event_chain"], args.mode)
            except BaseException as error:
                report["result"] = "FAIL"
                report["event_chain_error_class"] = type(error).__name__
            public_value(report, operator_values.values())
            write_immutable(output / "report.json", report)
            write_immutable(output / "evidence-sha256.json", {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in sorted(output.rglob("*")) if path.is_file()})
    print(report["result"] + ": " + str(output / "report.json"), flush=True)
    return 0 if report["result"] in ("PASS", "PREFLIGHT_PASS") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Public soak refused: " + str(error)) from error
