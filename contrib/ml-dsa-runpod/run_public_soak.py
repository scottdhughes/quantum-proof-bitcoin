#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Mac Docker + Runpod native public TEST soak, with explicit backend proofs.

The unchanged logical workload validates payments, floors, all seven fault
phases, and 86,400 actual wall and monotonic seconds. Provider lifecycle and
native payload replacement have different receipts from Docker operations.
This program does not acquire resources or read provider credentials.
"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("runpod_soak_common", ROOT / "contrib/ml-dsa-qualification/run_public_soak.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, canonical, hex64 = base.require, base.canonical, base.hex64
CONFIG_SCHEMA = "PQBTC-RUNPOD-PUBLIC-SOAK-CONFIG-1"
CONTROL_FILES = (
    "contrib/ml-dsa-runpod/run_public_soak.py", "contrib/ml-dsa-runpod/runpod_agent.py",
    "contrib/ml-dsa-runpod/native_backend.py", "contrib/ml-dsa-runpod/native_exec.py",
    "contrib/ml-dsa-qualification/run_public_soak.py", "contrib/ml-dsa-qualification/public_soak_agent.py",
    "contrib/ml-dsa-console/public_controller.py", "contrib/ml-dsa-qualification/public_transport.py",
)
_prepare_config = base.prepare_config
_docker_namespace_probe, _docker_namespace_claim = base.namespace_probe, base.namespace_claim
_docker_volume, _docker_emergency = base.initial_volume, base.emergency_stop_owned
_docker_validate_identity, _declaration = base.validate_identity, base.declaration
_host_json = base.host_json


def native(host):
    return host["backend"] == "native"


def host_json(host, arguments, **kwargs):
    # The legacy helpers also use this entry point. -I ignores Python ENV
    # switches, so the bytecode flag must be an explicit interpreter argument.
    arguments = list(arguments)
    if arguments and Path(str(arguments[0])).name.startswith("python") and "-B" not in arguments[1:]:
        arguments.insert(1, "-B")
    return _host_json(host, arguments, **kwargs)


def safe_path(value):
    return type(value) is str and value.startswith("/") and "\0" not in value and "\n" not in value and ".." not in Path(value).parts


def validate_native_paths(settings, state_dir):
    mount = Path("/var/lib/pqbtc")
    require(all(safe_path(value) for value in (state_dir, settings["data_root"], settings["runtime_root"], settings["versions_root"])) and
            settings["runtime_root"] == "/opt/pqbtc-runtime" and settings["versions_root"] == "/opt/pqbtc-runpod/versions",
            "Public native runtime paths must match the provider/export contract")
    state, data = Path(state_dir), Path(settings["data_root"])
    require(state != mount and data != mount and state.is_relative_to(mount) and data.is_relative_to(mount) and
            state != data and state.parent == data.parent and state.parent != mount,
            "Native controller/data must be fresh siblings inside one scoped provider-mounted namespace")


def validate_resource_identity(value, settings):
    version = value.get("cgroup_version")
    paths = value.get("controller_paths", {})
    require(value.get("schema") == "PQBTC-RUNPOD-CGROUP-SNAPSHOT-1" and type(version) is int and version in (1, 2) and
            value.get("scope") == "PROVIDER_CONTAINER_CGROUP_V" + str(version) and type(paths) is dict and paths and
            all(safe_path(path) for path in paths.values()), "Actual versioned provider cgroup proof required")
    require((set(paths) == {"unified"}) if version == 2 else {"cpu", "cpuacct", "memory", "pids"} <= set(paths),
            "Current process cgroup controller paths missing")
    require(value.get("cpu_cores") == settings["cpu_cores"] and value.get("memory_max_bytes") == settings["memory_bytes"],
            "Provider cgroup hard allocation differs from the declared binding")


def validate_ssh(transport):
    require(type(transport) is dict and {"kind", "argv"} <= set(transport) <=
            {"kind", "argv", "pod_id", "generation", "hostkey_source", "known_hosts_sha256"} and transport["kind"] == "ssh" and
            type(transport["argv"]) is list and len(transport["argv"]) >= 2 and transport["argv"][0] == "ssh" and
            all(type(part) is str and part and "\n" not in part and "\0" not in part for part in transport["argv"]),
            "Public provider SSH transport shape invalid")
    arguments = transport["argv"]
    require(re.fullmatch(r"[A-Za-z0-9_@.:[\]-]{1,256}", arguments[-1]) and not arguments[-1].startswith("-"),
            "Single provider SSH destination must be last")
    allowed = {"batchmode", "connecttimeout", "stricthostkeychecking", "clearallforwardings", "forwardagent", "forwardx11",
               "identitiesonly", "serveraliveinterval", "serveralivecountmax", "loglevel", "connectionattempts",
               "userknownhostsfile", "globalknownhostsfile", "hostkeyalias"}
    options = {}
    index = 1
    while index < len(arguments) - 1:
        token = arguments[index]
        if token in ("-T", "-4", "-6", "-q"):
            index += 1
            continue
        if token == "-p":
            require(index + 1 < len(arguments) - 1 and arguments[index + 1].isdigit() and
                    1 <= int(arguments[index + 1]) <= 65535, "Provider SSH TCP port invalid")
            index += 2
            continue
        require(token == "-o" or token.startswith("-o"), "Provider SSH flags cannot add forwarding, hooks, commands, or credential paths")
        if token == "-o":
            index += 1
            require(index < len(arguments) - 1, "Incomplete SSH option")
            option = arguments[index]
        else:
            option = token[2:]
        name, split, value = option.partition("=")
        require(split and name.lower() in allowed and value, "Unapproved provider SSH option")
        require(name.lower() not in options, "Duplicate SSH option refused")
        options[name.lower()] = value
        require(name.lower() != "stricthostkeychecking" or value == "yes", "Provider host key must be independently pinned")
        require(name.lower() != "globalknownhostsfile" or value == "/dev/null", "Only task-specific host-key trust may authenticate the provider")
        index += 1
    require(all(options.get(name) == value for name, value in
                {"batchmode": "yes", "stricthostkeychecking": "yes", "clearallforwardings": "yes",
                 "forwardagent": "no", "forwardx11": "no"}.items()), "Strict noninteractive SSH isolation options required")
    return {"kind": "ssh", "argv": list(arguments)}


def validate_control_identity(value):
    require(type(value) is dict and set(value) == {"source_head", "source_tree", "sha256"} and
            re.fullmatch(r"[0-9a-f]{40}", value["source_head"]) and re.fullmatch(r"[0-9a-f]{40}", value["source_tree"]) and
            type(value["sha256"]) is dict and set(value["sha256"]) == set(CONTROL_FILES) and
            all(hex64(item) for item in value["sha256"].values()), "Pinned exact launcher control identity required")
    return value


def validate_payload(payload, qualified, label):
    require(type(payload) is dict and set(payload) in (
        {"schema", "version", "source_head", "source_tree", "manifest_sha256", "files"},
        {"schema", "version", "source_head", "source_tree", "manifest_sha256", "files", "build_descriptor"}),
        "Native payload descriptor members")
    require(payload["schema"] == "PQBTC-RUNPOD-PAYLOAD-1" and payload["version"] == ("a3" if label == "a" else "c") and
            payload["source_head"] == qualified["source_head"] and payload["source_tree"] == qualified["source_tree"] and
            payload["manifest_sha256"] == qualified["descriptor"]["manifest_sha256"], "Native payload source/build provenance mismatch")
    files = payload["files"]
    require(type(files) is dict and 1 <= len(files) <= 30000 and all(
        type(path) is str and not Path(path).is_absolute() and ".." not in Path(path).parts and
        "\0" not in path and "\n" not in path and hex64(digest) for path, digest in files.items()), "Native payload file hashes invalid")
    for path in (base.NODE, base.SIGNER, base.SOURCE_PREFIX + "docs/ML_DSA_44_PUBLIC_TEST_PROFILE.md",
                 base.SOURCE_PREFIX + "docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md"):
        require(files.get("seed/" + path.removeprefix("/tmp/")) == qualified["descriptor"]["manifest"]["sha256"].get(path),
                "Native payload changed a qualified binary or sealed profile/contract")
    return payload


def prepare_config(value):
    require(type(value) is dict and set(value) == {"schema", "hosts", "public_endpoint", "cleanup_public_route", "provider_restart"}
            and value["schema"] == CONFIG_SCHEMA, "Runpod soak configuration members")
    original = copy.deepcopy(value)
    legacy = copy.deepcopy(value)
    legacy["schema"] = base.CONFIG_SCHEMA
    del legacy["provider_restart"]
    for host in legacy["hosts"]:
        require(host.get("backend") in ("docker", "native"), "Declare actual Docker/native backend")
        backend = host.pop("backend")
        if host["transport"].get("kind") == "ssh":
            host["transport"] = validate_ssh(host["transport"])
        validate_control_identity(host.pop("control_identity"))
        if backend == "native":
            settings = host.pop("native")
            require(type(settings) is dict and set(settings) == {"pod_id", "namespace", "data_root", "versions_root", "runtime_root",
                                                                "cpu_cores", "memory_bytes", "outer_image"}, "Native settings members")
            require(type(settings["pod_id"]) is str and re.fullmatch(r"[a-zA-Z0-9_-]{4,80}", settings["pod_id"]) and
                    type(settings["namespace"]) is str and re.fullmatch(r"pqbtc-runpod-[a-z0-9_.-]{1,70}", settings["namespace"]) and
                    all(safe_path(settings[key]) for key in ("data_root", "versions_root", "runtime_root")) and
                    type(settings["cpu_cores"]) is int and 1 <= settings["cpu_cores"] <= 4 and
                    type(settings["memory_bytes"]) is int and 1024**3 <= settings["memory_bytes"] <= 8 * 1024**3 and
                    type(settings["outer_image"]) is str and 1 <= len(settings["outer_image"]) <= 512 and
                    not host["sudo_docker"] and host["p2p_port"] == 23833 and host["role"] == "follower" and host["transport"]["kind"] == "ssh",
                    "Native follower provider binding/resources invalid")
            require(Path(settings["data_root"]) != Path(host["state_dir"]) and
                    Path(host["state_dir"]) not in Path(settings["data_root"]).parents,
                    "Native data and controller directories must be independent fresh paths")
            validate_native_paths(settings, host["state_dir"])
            for version in host["versions"].values():
                require("payload" in version, "Native version requires its payload descriptor")
                del version["payload"]
        else:
            require(host["role"] == "bootstrap" and host["transport"]["kind"] == "local", "Mac Docker bootstrap required")
    prepared = _prepare_config(legacy)
    require({host["backend"] for host in original["hosts"]} == {"docker", "native"}, "Exactly one Docker and one native backend required")
    for host, source in zip(prepared["hosts"], original["hosts"]):
        host["backend"], host["control_identity"] = source["backend"], source["control_identity"]
        if native(host):
            host["native"] = source["native"]
            for label, version in host["versions"].items():
                payload, digest = base.load_public_json(source["versions"][label]["payload"], maximum=16 * 1024 * 1024)
                version["qualified"]["payload"] = validate_payload(payload, version["qualified"], label)
                version["qualified"]["payload_file_sha256"] = digest
    require(len({host["control_identity"]["source_head"] for host in prepared["hosts"]}) == 1 and
            len({host["control_identity"]["source_tree"] for host in prepared["hosts"]}) == 1,
            "Both hosts must use the same reviewed launcher source")
    restart = original["provider_restart"]
    if restart is not None:
        require(type(restart) is dict and set(restart) == {"argv", "script_sha256"} and
                type(restart["argv"]) is list and len(restart["argv"]) >= 2 and
                all(type(part) is str and part and "\n" not in part and "\0" not in part for part in restart["argv"]) and
                safe_path(restart["argv"][0]) and safe_path(restart["argv"][1]) and restart["argv"][1].endswith(".py") and
                hex64(restart["script_sha256"]), "Pinned provider lifecycle helper configuration invalid")
    prepared["provider_restart"] = restart
    return prepared


PRELAUNCH_SCRIPT = r'''import hashlib,json,os,pathlib,platform,stat,subprocess,sys
p=json.loads(sys.argv[1]);root=pathlib.Path(p['repo']);expected=p['control_identity']
observed={}
for name in expected['sha256']:
 path=root/name;assert root.resolve() in path.resolve().parents
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=4194304
  raw=os.read(fd,4194305);assert len(raw)<=4194304;observed[name]=hashlib.sha256(raw).hexdigest()
 finally:os.close(fd)
assert observed==expected['sha256'],'control file identity changed'
value={'backend':p['backend'],'control_identity':expected,'actual_control_sha256':observed,'architecture':platform.machine()}
assert (root/'.git').exists(),'complete frozen control checkout is required'
def git(*args):return subprocess.check_output(['git','-C',str(root),*args],timeout=20).decode().strip()
assert git('rev-parse','HEAD')==expected['source_head'] and git('rev-parse','HEAD^{tree}')==expected['source_tree']
assert not git('status','--porcelain=v1','--untracked-files=all')
value['source_git_observed']=True
if p['backend']=='docker':
 raw=subprocess.check_output(p['docker']+['info','--format','{"architecture":{{json .Architecture}},"daemon_id":{{json .ID}}}'],timeout=20)
 d=json.loads(raw);value.update(docker_architecture=d['architecture'],docker_daemon_id=d['daemon_id'])
else:
 assert os.geteuid()==0 and os.environ.get('RUNPOD_POD_ID')==p['native']['pod_id']
 mounted=pathlib.Path('/var/lib/pqbtc');s=mounted.lstat()
 assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o001,'provider state mount ownership/traversal differs'
 for destination in (p['state_dir'],p['native']['data_root']):
  assert pathlib.Path(destination)!=mounted and pathlib.Path(destination).is_relative_to(mounted),'native state path is outside provider mount'
  ancestor=pathlib.Path(destination).parent
  while ancestor!=mounted:
   if os.path.lexists(ancestor):
    s=ancestor.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o001,'native state parent ownership/traversal differs'
   ancestor=ancestor.parent
 sys.path.insert(0,str(root/'contrib/ml-dsa-runpod'));from runpod_agent import cgroup_snapshot
 value.update(pod_id=p['native']['pod_id'],provider_container=cgroup_snapshot(),outer_image_provider_binding=p['native']['outer_image'])
print(json.dumps(value,sort_keys=True))
'''


def prelaunch_host(host):
    payload = {key: host[key] for key in ("repo", "backend", "control_identity", "state_dir")}
    payload["docker"] = ["sudo", "-n", "docker"] if host["sudo_docker"] else ["docker"]
    if native(host):
        payload["native"] = host["native"]
    value = base.host_json(host, ["python3", "-B", "-I", "-c", PRELAUNCH_SCRIPT, canonical(payload).decode()])
    require(value.get("backend") == host["backend"] and value.get("control_identity") == host["control_identity"] and
            value.get("actual_control_sha256") == host["control_identity"]["sha256"] and
            value.get("source_git_observed") is True, "Actual complete launcher checkout identity differs")
    arch = base.load_module(ROOT / "contrib/ml-dsa-qualification/run_native_qualification.py", "runpod_architecture").normalize_architecture
    actual = value.get("architecture") if native(host) else value.get("docker_architecture")
    require(all(arch(actual) == version["qualified"]["architecture"] for version in host["versions"].values()),
            "Actual execution architecture would emulate a qualified payload")
    if native(host):
        limits = value.get("provider_container", {})
        require(value.get("pod_id") == host["native"]["pod_id"], "Actual provider pod identity differs")
        validate_resource_identity(limits, host["native"])
    else:
        require(type(value.get("docker_daemon_id")) is str and len(value["docker_daemon_id"]) >= 8, "Actual Docker daemon identity missing")
    return value


def require_distinct_backends(hosts):
    require(len(hosts) == 2 and {value.get("backend") for value in hosts.values()} == {"docker", "native"},
            "Two independently controlled Docker/native hosts required")
    require(sum(bool(value.get("pod_id")) for value in hosts.values()) == 1 and
            sum(bool(value.get("docker_daemon_id")) for value in hosts.values()) == 1,
            "Native pod identity cannot be substituted with a Docker identity")


NAMESPACE_SCRIPT = r'''import json,os,pathlib,socket,stat,sys
p=json.loads(sys.argv[1]);state=pathlib.Path(p['state_dir']);data=pathlib.Path(p['data_root'])
def ports_free():
 sockets=[]
 try:
  for port in (23832,23833,23834):
   s=socket.socket();s.bind(('127.0.0.1',port));sockets.append(s)
  return True
 except OSError:return False
 finally:
  for s in sockets:s.close()
proof={'state_dir_absent':not os.path.lexists(state),'data_root_absent':not os.path.lexists(data),'native_ports_absent':ports_free()}
if p['operation']=='probe':print(json.dumps(proof,sort_keys=True))
else:
 assert p['operation']=='claim' and all(proof.values())
 missing=[];parent=state.parent
 while not parent.exists():missing.append(parent);parent=parent.parent
 assert not parent.is_symlink()
 for parent in reversed(missing):os.mkdir(parent,0o755);os.chmod(parent,0o755)
 assert not state.parent.is_symlink()
 os.mkdir(state,0o700);directory=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  s=os.fstat(directory);assert s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700
  fd=os.open('.public-soak-attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   raw=json.dumps(p['claim'],sort_keys=True,separators=(',',':')).encode()+b'\n';offset=0
   while offset<len(raw):offset+=os.write(fd,raw[offset:])
   os.fsync(fd)
  finally:os.close(fd)
  os.fsync(directory)
 finally:os.close(directory)
 fd=os.open(state.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 print(json.dumps({'claim':p['claim'],'freshness':proof},sort_keys=True))
'''


def namespace_probe(host):
    if not native(host):
        return _docker_namespace_probe(host)
    payload = {"state_dir": host["state_dir"], "data_root": host["native"]["data_root"], "operation": "probe"}
    result = base.host_json(host, ["python3", "-B", "-I", "-c", NAMESPACE_SCRIPT, canonical(payload).decode()])
    require(set(result) == {"state_dir_absent", "data_root_absent", "native_ports_absent"} and
            all(type(value) is bool for value in result.values()), "Native namespace absence proof invalid")
    return result


def namespace_claim(host, attempt_id):
    if not native(host):
        return _docker_namespace_claim(host, attempt_id)
    require(type(attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", attempt_id), "Native attempt identity invalid")
    claim = {"schema": "PQBTC-RUNPOD-SOAK-ATTEMPT-1", "attempt_id": attempt_id, "pod_id": host["native"]["pod_id"],
             "namespace": host["native"]["namespace"], "data_root": host["native"]["data_root"], "profile_sha256": base.PROFILE}
    payload = {"state_dir": host["state_dir"], "data_root": host["native"]["data_root"], "operation": "claim", "claim": claim}
    value = base.host_json(host, ["python3", "-B", "-I", "-c", NAMESPACE_SCRIPT, canonical(payload).decode()])
    require(value.get("claim") == claim and value.get("freshness") ==
            {"state_dir_absent": True, "data_root_absent": True, "native_ports_absent": True}, "Native claim was not fresh")
    return claim


def initial_volume(host):
    if not native(host):
        return _docker_volume(host)
    value = host.get("_live_identity", {})
    require(value.get("namespace") == host["native"]["namespace"] and value.get("pod_id") == host["native"]["pod_id"] and
            type(value.get("volume_id")) is str and re.fullmatch(r"[0-9a-f]{32}", value["volume_id"]),
            "Live native persistent-state identity missing")
    return {"backend": "native", "volume_id": value["volume_id"], "namespace": value["namespace"],
            "pod_id": value["pod_id"], "data_root": host["native"]["data_root"], "payload": value["payload"]}


EMERGENCY_SCRIPT = r'''import json,os,pathlib,stat,sys
p=json.loads(sys.argv[1]);state=pathlib.Path(p['state_dir'])
fd=os.open(state/'.public-soak-attempt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096
 claim=json.loads(os.read(fd,4097));assert claim==p['attempt_claim']
finally:os.close(fd)
assert claim['schema']=='PQBTC-RUNPOD-SOAK-ATTEMPT-1' and claim['pod_id']==p['native']['pod_id'] and claim['namespace']==p['native']['namespace']
assert claim['data_root']==p['native']['data_root'] and os.environ.get('RUNPOD_POD_ID')==claim['pod_id']
sys.path.insert(0,p['repo']+'/contrib/ml-dsa-runpod');from native_backend import NativeManager
manager=NativeManager(state,versions_root=pathlib.Path(p['native']['versions_root']),runtime_root=pathlib.Path(p['native']['runtime_root']),data_root=pathlib.Path(p['native']['data_root']),namespace=p['native']['namespace'])
if (state/'native-runtime.json').exists():
 prior=manager._read_json('native-runtime.json')
 assert prior['namespace']==claim['namespace'] and prior['data_root']==claim['data_root']
 if p.get('expected_volume_id') is not None:assert prior['volume_id']==p['expected_volume_id']
 manager._verify_volume(prior)
else:assert p.get('expected_volume_id') is None
result=manager.emergency_stop()
print(json.dumps({'backend_stopped':True,'backend':'native','namespace':claim['namespace'],'cleanup':result},sort_keys=True))
'''


def emergency_stop_owned(host):
    if not native(host):
        return _docker_emergency(host)
    require(type(host.get("_attempt_claim")) is dict, "Native cleanup requires this attempt claim")
    payload = {"repo": host["repo"], "state_dir": host["state_dir"], "native": host["native"],
               "attempt_claim": host["_attempt_claim"], "expected_volume_id": host.get("_attempt_volume_id")}
    value = base.host_json(host, ["python3", "-B", "-I", "-c", EMERGENCY_SCRIPT, canonical(payload).decode()], timeout=100)
    require(value.get("backend_stopped") is True and value.get("backend") == "native", "Native cleanup did not establish owned shutdown")
    return value


def agent_command(host, until):
    command = ["python3", "-B", host["repo"] + "/contrib/ml-dsa-runpod/runpod_agent.py", "--backend", host["backend"],
               "--state-dir", host["state_dir"], "--descriptor", host["versions"]["a"]["remote_descriptor"],
               "--namespace", host["native"]["namespace"] if native(host) else host["container"],
               "--p2p-port", str(host["p2p_port"]), "--until-utc", until]
    if native(host):
        for name in ("versions_root", "runtime_root", "data_root", "pod_id"):
            command += ["--" + name.replace("_", "-"), str(host["native"][name])]
    elif host["sudo_docker"]:
        command += ["--sudo-docker"]
    if host["role"] == "bootstrap":
        command += ["--bootstrap"]
    return base.host_exec(host, command)


def validate_native_identity(host, value, version):
    payload, expected = value.get("payload", {}), version["payload"]
    require(value.get("schema") == "PQBTC-RUNPOD-NATIVE-IDENTITY-1" and value.get("backend") == "native" and
            value.get("pod_id") == host["native"]["pod_id"] and value.get("namespace") == host["native"]["namespace"] and
            value.get("payload_root") == host["native"]["versions_root"] + "/" + expected["version"] and
            value.get("active_seed") == host["native"]["runtime_root"] + "/seed" and
            all(payload.get(key) == expected[key] for key in ("version", "source_head", "source_tree", "manifest_sha256")) and
            payload.get("node_sha256") == version["node_sha256"] and payload.get("signer_sha256") == version["signer_sha256"] and
            payload.get("payload_sha256") == hashlib.sha256(canonical(expected) + b"\n").hexdigest(),
            "Live native payload/provider identity differs from qualified provenance")
    node = value.get("running_node", {})
    require(node.get("uid") == 1001 and node.get("sha256") == version["node_sha256"] and
            type(node.get("pid")) is int and node["pid"] > 1, "Actual running native node executable mismatch")
    signer = value.get("running_signer")
    require(type(value.get("signer_running")) is bool, "Live signer state must be explicit")
    if value["signer_running"]:
        require(type(signer) is dict and signer.get("uid") == 1000 and signer.get("sha256") == version["signer_sha256"] and
                signer.get("proof_kind") == "PRE_EXEC_IMMUTABLE_FD_HASH_PLUS_PIDFD" and signer.get("live") is True and
                signer.get("pidfd_bound") is True and signer.get("post_exec_executable_observable") is False and
                type(signer.get("pid")) is int and signer["pid"] > 1 and signer.get("session") == signer.get("pgid") == signer["pid"] and
                type(signer.get("start")) is str and signer["start"].isdigit() and signer.get("no_new_privileges") == 1,
                "Hardened signer immutable-FD/pidfd execution proof is invalid")
        caps = signer.get("capabilities", {})
        require(type(caps) is dict and set(caps) == {"CapInh", "CapPrm", "CapEff", "CapAmb"} and all(
            type(item) is str and re.fullmatch(r"0{1,32}", item) for item in caps.values()), "Hardened signer retained capabilities")
        file = signer.get("pre_exec_file", {})
        require(type(file) is dict and file.get("path") in (
            value["payload_root"] + "/seed/demo-signer-bin/pilot-signer", value["active_seed"] + "/demo-signer-bin/pilot-signer") and
            all(type(file.get(key)) is int and file[key] > 0 for key in ("device", "inode", "size")),
            "Hardened signer pre-exec file identity is missing")
    else:
        require(signer is None, "Stopped signer cannot claim live execution identity")


def validate_restart_receipt(value, pod_id):
    require(type(value) is dict and value.get("schema") == "PQBTC-RUNPOD-RESTART-1" and value.get("result") == "PASS" and
            value.get("pod_id") == pod_id and value.get("provider_restart") is True and
            type(value.get("before_generation")) is str and value["before_generation"] and
            type(value.get("after_generation")) is str and value["after_generation"] and
            value["before_generation"] != value["after_generation"], "Actual provider restart generation proof missing")
    validate_ssh(value.get("transport"))
    return value


def public_command(helper, timeout=600):
    """Bound all helper output and time; no operator input enters this process."""
    script = Path(helper["argv"][1])
    require(not script.is_symlink() and script.is_file() and script.stat().st_uid == os.getuid() and
            hashlib.sha256(script.read_bytes()).hexdigest() == helper["script_sha256"], "Provider helper source changed")
    capture = base.load_module(ROOT / "contrib/ml-dsa-qualification/native_process.py", "runpod_lifecycle_capture")
    try:
        result = capture.capture(helper["argv"], timeout=timeout, output_limit=4 * 1024 * 1024,
                                 prefix_limit=0, fail_on_stderr=True)
    except capture.CaptureError:
        raise ValueError("Provider lifecycle helper failed, timed out, or exceeded its public output bound") from None
    require(result.returncode == 0, "Provider lifecycle helper failed")
    require(hashlib.sha256(script.read_bytes()).hexdigest() == helper["script_sha256"], "Provider helper changed during execution")
    return base.public_value(base.parsed(result.stdout))


class Soak(base.Soak):
    def setup(self):
        super().setup()
        self.provider_restart_receipt = self.provider_restart_rehearsal()
        self.config["_provider_restart_receipt"] = self.provider_restart_receipt

    def provider_restart_rehearsal(self):
        """Actual outer lifecycle, before either soak clock begins."""
        helper = self.config["provider_restart"]
        require(helper is not None, "A real provider restart helper is required before public qualification")
        host = self.follower
        config = self.hosts[host]
        self.statuses_now()
        before = copy.deepcopy(self.statuses[host])
        point = self.guard.snapshot(host)
        identity = self.action(host, "identity")
        volume = identity["volume_id"]
        stopped = self.agents[host].close()
        del self.agents[host]
        self.log.append("provider_restart_agent_stopped", {"host": host, "cleanup": stopped})
        receipt = public_command(helper)
        validate_restart_receipt(receipt, config["native"]["pod_id"])
        config["transport"] = validate_ssh(receipt["transport"])
        self.prelaunch[host] = prelaunch_host(config)
        self.agents[host] = base.AgentClient(config, self.until, self.operator_values.values())
        self.action(host, "start", timeout=240)
        self.identity(host, "a")
        require(config["_live_identity"]["volume_id"] == volume, "Provider restart replaced the persistent volume")
        after = self.action(host, "status")
        require(after["wallet"]["wallet_id"] == point["wallet_id"] and
                all(after["wallet"][key] == point[key] for key in ("next_receive", "next_change")),
                "Provider restart changed wallet identity or floors")
        require(len(before["nodes"]) == len(after["nodes"]) == 1 and all(
            before["nodes"][0][key] == after["nodes"][0][key] for key in ("height", "tip", "utxo_hash", "utxo_count")),
            "Provider restart changed the validated chain or full UTXO set")
        self.action(host, "unlock", {"password": self.operator_values[host]})
        self.bridge()
        payment = self.payment(host, self.bootstrap)
        self.last_sample = time.monotonic()
        self.sample()
        result = {"provider": receipt, "volume_id": volume, "wallet_id": point["wallet_id"],
                  "floors_preserved": True, "chain_utxo_preserved": True, "recovery_payment": payment,
                  "performed_before_soak_clock": True}
        self.log.append("actual_provider_restart_verified", result)
        return result

    def identity(self, host, label):
        value = self.action(host, "identity")
        config, version = self.hosts[host], self.hosts[host]["versions"][label]["qualified"]
        if native(config):
            validate_native_identity(config, value, version)
            config["_live_identity"] = value
        else:
            _docker_validate_identity(value, version)

    def sample(self):
        now_mono, now_wall = time.monotonic(), time.time()
        if self.last_sample is not None:
            require(now_mono - self.last_sample <= 90, "Unexplained resource monitoring gap")
        if self.last_clock is not None:
            require(abs((now_wall - self.last_clock[1]) - (now_mono - self.last_clock[0])) <= 5, "Sleep/clock discontinuity cannot count as soak")
        self.last_sample, self.last_clock = now_mono, (now_mono, now_wall)
        for host, config in self.hosts.items():
            value = self.action(host, "sample")
            require(type(value.get("rss_bytes")) is int and 0 < value["rss_bytes"] <= 1024**3 and
                    type(value.get("peak_rss_bytes")) is int and value["rss_bytes"] <= value["peak_rss_bytes"] <= 1024**3 and
                    value.get("maxmempool_bytes") == 32_000_000 and type(value.get("mempool_usage_bytes")) is int and
                    0 <= value["mempool_usage_bytes"] <= 32_000_000, "Actual node memory/mempool budget failed")
            if native(config):
                limits = value.get("provider_container", {})
                validate_resource_identity(limits, config["native"])
                require(0 < limits.get("memory_current_bytes", 0) <= config["native"]["memory_bytes"] and
                        type(limits.get("pids_current")) is int and 0 < limits["pids_current"] <= 256 and
                        base.finite(value.get("pod_cpu_percent")) and 0 <= value["pod_cpu_percent"] < 90,
                        "Runpod provider-container resource budget exceeded")
            if host == self.follower:
                require(value.get("bridge_alive") is True, "Public TLS bridge is not alive")

    def recover(self, host):
        # Both implementations of quarantine_record remove both selected files.
        before = self.guard.snapshot(host)
        require(all(before[key] > self.old_backup_points[host][key] for key in ("next_receive", "next_change")), "Backup is not genuinely old")
        result = self.action(host, "quarantine_record", timeout=120)
        require(result.get("selected_record_missing") is True and result.get("public_record_missing") is True and
                result.get("independent_journal_preserved") is True, "Both current records must actually be missing")
        recovered = self.action(host, "recover", {"backup_id": self.old_backups[host], "password": self.operator_values[host]}, timeout=240)
        require(recovered.get("wallet_id") == before["wallet_id"] and recovered.get("chain_snapshot_restored") is False and
                all(recovered.get(key, -1) >= before[key] for key in ("next_receive", "next_change")), "Recovery lowered public floors or identity")
        self.bridge()

    def fault(self, name):
        if name not in ("upgrade", "rollback", "crash"):
            return super().fault(name)
        started = time.monotonic()
        self.action_deadline = started + 300
        row = {"name": name, "started_elapsed": started - self.started_mono, "result": "FAIL"}
        self.log.append("fault_started", row)
        if name == "crash":
            result = self.action(self.follower, "crash", timeout=120)
            require(result.get("crashed") is True and result.get("restarted") is True and
                    result.get("crash_kind") == "OWNED_NATIVE_APPLICATION_PROCESS_GROUPS", "Actual native application crash/restart missing")
            row["crash_kind"] = result["crash_kind"]
            self.action(self.follower, "unlock", {"password": self.operator_values[self.follower]})
            self.bridge()
            self.identity(self.follower, "a")
        else:
            label, previous = ("b", "a") if name == "upgrade" else ("a", "b")
            for host, config in self.hosts.items():
                self.action(host, "lock")
                version = config["versions"][label]["qualified"]
                params = {"payload_version": version["payload"]["version"]} if native(config) else {"descriptor": version["descriptor"]}
                result = self.action(host, name, params, timeout=240)
                require(result.get("data_rollback") is False and type(result.get("volume_id")) is str, "Binary transition replaced data")
                base.require_original_volume(self.volumes, host, result["volume_id"])
                if native(config):
                    require(result.get("native_payload", {}).get("version") == version["payload"]["version"] and
                            result.get("previous_payload", {}).get("version") == config["versions"][previous]["qualified"]["payload"]["version"] and
                            result.get("outer_provider_image_changed") is False,
                            "Native binary transition source versions missing")
                    row.setdefault("transitions", {})[host] = {"kind": "NATIVE_PAYLOAD_CHANGE", **result}
                else:
                    require(result.get("image") == version["image"] and result.get("previous_image") ==
                            config["versions"][previous]["qualified"]["image"], "Docker image replacement identity mismatch")
                    row.setdefault("transitions", {})[host] = {"kind": "DOCKER_IMAGE_REPLACEMENT", **result}
                self.action(host, "unlock", {"password": self.operator_values[host]})
                self.identity(host, label)
                self.bridge()
        self.agree()
        sender = self.bootstrap if name == "upgrade" else self.follower
        receiver = self.follower if sender == self.bootstrap else self.bootstrap
        row["recovery_payment"] = self.payment(sender, receiver)
        self.last_sample = time.monotonic()
        self.sample()
        row.update(finished_elapsed=time.monotonic() - self.started_mono, result="PASS")
        require(row["finished_elapsed"] - row["started_elapsed"] <= 300, "Fault shared five-minute recovery deadline")
        self.phases.append(row)
        self.log.append("fault_completed", row)
        self.action_deadline = None


def checkout_identity():
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=30).decode().strip()
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "Clean committed launcher checkout required")
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "control_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in CONTROL_FILES}}


def declaration(*args, **kwargs):
    value = _declaration(*args, **kwargs)
    config = args[0]
    for row, host in zip(value["hosts"], config["hosts"]):
        row["backend"] = host["backend"]
        row["launcher_control_identity"] = host["control_identity"]
        if native(host):
            del row["container"]
            row["native_provider"] = host["native"]
            row["versions"] = {label: {"payload": {key: version["qualified"]["payload"][key] for key in
                                                   ("version", "source_head", "source_tree", "manifest_sha256")},
                                       "build_provenance": {key: item for key, item in version["qualified"].items()
                                                            if key not in ("descriptor", "payload")}}
                               for label, version in host["versions"].items()}
    value["acceptance"].pop("research_host_cpu_percent_below", None)
    value["acceptance"].update(provider_container_cpu_percent_below=90, provider_container_pids_observed_maximum=256,
                                provider_hard_allocation_matches_binding=True, current_wallet_and_public_records_missing_before_recovery=True)
    value["native_fault_scope"] = "APPLICATION_PROCESS_GROUP_CRASH_AND_NATIVE_PAYLOAD_UPGRADE_ROLLBACK"
    value["outer_provider_restart"] = "ACTUAL_RESTART_VERIFIED_DURING_SETUP_BEFORE_ELAPSED_CLOCK"
    require(type(config.get("_provider_restart_receipt")) is dict, "Provider restart receipt must precede the declaration")
    value["provider_restart_receipt"] = config["_provider_restart_receipt"]
    value["additional_setup_confirmed_payments"] = 1
    value["maximum_declared_public_entries_per_host"] = 1452 if value["mode"] == "soak" else None
    return value


def install():
    base.RESULT_SCHEMA = "PQBTC-RUNPOD-PUBLIC-SOAK-RESULT-1"
    base.DECLARATION_SCHEMA = "PQBTC-RUNPOD-PUBLIC-SOAK-DECLARATION-1"
    base.prepare_config = prepare_config
    base.host_json = host_json
    base.prelaunch_host = prelaunch_host
    base.require_distinct_daemons = require_distinct_backends
    base.namespace_probe, base.namespace_claim = namespace_probe, namespace_claim
    base.initial_volume, base.emergency_stop_owned = initial_volume, emergency_stop_owned
    base.agent_command, base.Soak = agent_command, Soak
    base.checkout_identity, base.declaration = checkout_identity, declaration


def main(argv=None):
    install()
    return base.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
