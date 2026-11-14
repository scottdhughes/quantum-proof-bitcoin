#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Scoped Runpod CPU rental with a separate, durable local deletion guard.

No import-time network, authentication, scheduling or resource effects. The
provider has no held-expiry field: the local guard depends on Mac power,
networking and provider availability. It is not an outage-proof billing cap.
"""
import argparse
import base64
import contextlib
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid

ORIGIN = "https://api.runpod.io"
MAX_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 28 * 3600
MAX_USD = Decimal("10.00")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
TASK = re.compile(r"pqbtc-runpod-public-[0-9]{8}-[0-9a-f]{16}")
IMAGE = re.compile(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}")
STATES = {"PROVISIONING", "STARTING", "RUNNING", "EXITED", "ERROR", "TERMINATED"}
HOSTKEY_COMMAND = {"command": ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"], "timeoutSeconds": 10}


class Refused(RuntimeError):
    """Fixed public code, never a provider body or authentication value."""


def need(value, code):
    if not value:
        raise Refused(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(Refused("json_number")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Refused("invalid_json") from None


def private_dir(path):
    path = Path(path)
    need(path.is_absolute(), "state_path")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
         stat.S_IMODE(info.st_mode) == 0o700, "state_directory")
    return path


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) in (0o600, 0o500) and info.st_size <= MAX_BYTES, "state_file")
        raw = os.read(fd, MAX_BYTES + 1)
        need(len(raw) <= MAX_BYTES, "state_limit")
        return raw
    finally:
        os.close(fd)


def put(path, value):
    path = Path(path)
    raw = canonical(value) + b"\n"
    need(len(raw) <= MAX_BYTES, "state_limit")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def locked(directory):
    directory = private_dir(directory)
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, "state_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield directory
    finally:
        os.close(fd)


class Credential:
    __slots__ = ("_value",)

    def __init__(self, value):
        need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{16,512}", value), "credential")
        self._value = value

    def __repr__(self):
        return "<configured Runpod authentication>"


def configured_auth():
    """Use only the CLI's configured key; never project or alter its file."""
    path = Path.home() / ".runpod/config.toml"
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             not info.st_mode & 0o033 and info.st_size <= 65536, "credential")
        raw = os.read(fd, 65537)
        need(len(raw) <= 65536, "credential")
        value = tomllib.loads(raw.decode())
        keys = [v for k, v in value.items() if k.lower() == "apikey"]
        need(len(keys) == 1, "credential")
        return Credential(keys[0])
    except (OSError, ValueError, TypeError, UnicodeError):
        raise Refused("credential") from None
    finally:
        if fd is not None:
            os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, _newurl):
        raise Refused("redirect")


def contains(value, secret, depth=0):
    need(depth < 64, "response_depth")
    if isinstance(value, str):
        return secret in value
    if isinstance(value, dict):
        return any(contains(k, secret, depth + 1) or contains(v, secret, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return any(contains(v, secret, depth + 1) for v in value)
    return False


class API:
    def __init__(self, credential=None, opener=None):
        self.credential = credential or configured_auth()
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None):
        base = path.split("?", 1)[0]
        resource = re.fullmatch(r"/v2/(pods|network-volumes)/([A-Za-z0-9][A-Za-z0-9_-]{0,63})(/action|/exec)?", base)
        allowed = ((method == "GET" and base in ("/v2/pods", "/v2/network-volumes", "/v2/catalog/datacenters", "/v2/catalog/cpus/cpu3c")) or
                   (method == "POST" and base in ("/v2/pods", "/v2/network-volumes")) or
                   (resource and method in ("GET", "DELETE") and not resource[3]) or
                   (resource and resource[1] == "pods" and resource[3] == "/action" and method == "POST" and body == {"action": "restart"}) or
                   (resource and resource[1] == "pods" and resource[3] == "/exec" and method == "POST" and body == HOSTKEY_COMMAND))
        need(allowed and ((method in ("GET", "DELETE")) == (body is None)), "api_scope")
        need(path.startswith("/v2/") and "#" not in path and len(path) < 2048, "api_path")
        raw_body = None if body is None else canonical(body)
        secret = self.credential._value
        request = urllib.request.Request(ORIGIN + path, data=raw_body, method=method,
            headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json", "Accept": "application/json"})
        response = None
        try:
            try:
                response = self.opener.open(request, timeout=30)
                status = response.status
            except urllib.error.HTTPError as error:
                response, status = error, error.code
            raw = response.read(MAX_BYTES + 1)
            need(len(raw) <= MAX_BYTES, "response_limit")
            need(secret.encode() not in raw, "credential_echo")
            value = None if raw == b"" and status == 204 else decode(raw)
            need(not contains(value, secret), "credential_echo")
            return status, value
        except Refused:
            raise
        except Exception:
            raise Refused("provider_transport") from None
        finally:
            if response is not None:
                response.close()

    def collection(self, kind):
        need(kind in ("pods", "network-volumes"), "collection")
        key = "pods" if kind == "pods" else "networkVolumes"
        items, cursor, seen = [], None, set()
        for _ in range(32):
            query = {"limit": "1000"}
            if kind == "pods":
                query["includeClusterPods"] = "true"
            if cursor is not None:
                query["cursor"] = cursor
            status, value = self.call("GET", "/v2/" + kind + "?" + urllib.parse.urlencode(query))
            need(status == 200 and type(value) is dict and type(value.get(key)) is list, "list_response")
            items.extend(value[key])
            need(len(items) <= 32000 and all(type(v) is dict for v in items), "list_limit")
            need(all(type(v.get("id")) is str and ID.fullmatch(v["id"]) and type(v.get("name")) is str
                     for v in items), "list_identity")
            need(len({v["id"] for v in items}) == len(items), "list_duplicate_identity")
            page = value.get("pagination")
            need(type(page) is dict and type(page.get("hasNextPage")) is bool and "nextCursor" in page, "pagination")
            if not page["hasNextPage"]:
                need(page["nextCursor"] is None, "pagination")
                return items
            cursor = page["nextCursor"]
            need(type(cursor) is str and 0 < len(cursor) <= 512 and cursor not in seen, "pagination")
            seen.add(cursor)
        raise Refused("pagination_limit")


def cents(value):
    return str(Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_CEILING))


def quote_bound(hourly, *, seconds=MAX_SECONDS, disk_gb=40, volume_gb=20):
    hourly = Decimal(str(hourly))
    need(hourly.is_finite() and 0 < hourly <= Decimal("0.20"), "compute_rate")
    need(type(seconds) is int and 24 * 3600 < seconds <= MAX_SECONDS, "duration")
    need(type(disk_gb) is int and 20 <= disk_gb <= 40 and volume_gb == 20, "storage_size")
    hours = Decimal(seconds) / 3600
    # 28-day divisor and rounding a network-volume billing hour upward are
    # conservative relative to the published per-second/hourly storage rates.
    compute = hourly * hours
    storage = Decimal(disk_gb) * Decimal("0.10") * hours / (28 * 24)
    storage += Decimal(volume_gb) * Decimal("0.07") * (hours.to_integral_value(rounding=ROUND_CEILING) + 1) / (28 * 24)
    upper = (compute + storage) * Decimal("1.50") + Decimal("2.00")
    need(upper <= MAX_USD, "budget")
    return {"hourly_compute_usd": str(hourly), "compute_usd": cents(compute), "storage_usd": cents(storage),
            "tax_contingency_multiplier": "1.50", "additional_reserve_usd": "2.00", "all_in_planned_upper_usd": cents(upper),
            "maximum_total_usd": "10.00", "seconds": seconds,
            "storage_source": "https://docs.runpod.io/pods/pricing", "provider_budget_guarantee": False}


def catalog(api):
    status, cpu = api.call("GET", "/v2/catalog/cpus/cpu3c?include=AVAILABILITY&product=POD&vcpuCount=4")
    need(status == 200 and cpu.get("id") == "cpu3c" and cpu.get("ramGbPerVcpu") == 2 and
         cpu["vcpu"]["min"] <= 4 <= cpu["vcpu"]["max"] and cpu.get("availability") in ("HIGH", "MEDIUM", "LOW"), "cpu_catalog")
    hourly = Decimal(str(cpu["price"]["securePerVcpu"])) * 4
    quote_bound(hourly)
    status, dc = api.call("GET", "/v2/catalog/datacenters?include=CPU_AVAILABILITY&networkVolumeTypes=STANDARD")
    need(status == 200 and type(dc.get("dataCenters")) is list, "datacenter_catalog")
    cpu_stock = {v["id"]: v["availability"] for v in cpu.get("dataCenters", []) if type(v) is dict}
    selected = []
    for item in dc["dataCenters"]:
        if "STANDARD" in item.get("networkVolumeTypes", []) and cpu_stock.get(item.get("id")) in ("HIGH", "MEDIUM", "LOW"):
            selected.append({"id": item["id"], "cpu_availability": cpu_stock[item["id"]], "network_volume_type": "STANDARD"})
    need(selected, "no_storage_cpu_intersection")
    selected.sort(key=lambda v: (not v["id"].startswith("US-"), v["cpu_availability"] != "HIGH", v["id"]))
    return {"observed_at_epoch": int(time.time()), "cpu_id": "cpu3c", "vcpu_count": 4, "memory_gb": 8,
            "hourly_compute_usd": str(hourly), "data_centers": selected, "quote": quote_bound(hourly)}


def validate_plan(plan):
    need(type(plan) is dict and plan.get("schema") == "PQBTC-RUNPOD-LEASE-1" and
         type(plan.get("task")) is str and TASK.fullmatch(plan["task"]), "plan")
    need(IMAGE.fullmatch(plan.get("image", "")) and ID.fullmatch(plan.get("data_center", "")), "plan_identity")
    need(plan.get("mount_path") == "/var/lib/pqbtc" and plan.get("volume_gb") == 20 and plan.get("disk_gb") == 40 and
         plan.get("duration_seconds") == MAX_SECONDS and plan.get("cap_usd") == "10.00", "plan_limits")
    archive_root = Path(plan.get("artifact_root", ""))
    need(archive_root.is_absolute() and not archive_root.is_symlink(), "artifact_root")
    info = archive_root.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "artifact_root")
    quote = quote_bound(plan["catalog"]["hourly_compute_usd"])
    need(plan["quote"] == quote and plan["data_center"] in [v["id"] for v in plan["catalog"]["data_centers"]], "plan_quote")
    return plan


def load(directory):
    directory = private_dir(directory)
    raw = read(directory / "plan.json")
    plan = validate_plan(decode(raw))
    binding = decode(read(directory / "binding.json"))
    need(binding.get("plan_sha256") == digest(raw) and binding.get("task") == plan["task"], "binding")
    if binding.get("guard") is not None:
        guard = binding["guard"]
        need(type(guard) is dict and type(guard.get("armed_at_epoch")) is int and
             guard.get("label") == "org.pqbtc.runpod." + plan["task"].rsplit("-", 1)[1] and
             type(guard.get("script_sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", guard["script_sha256"]) and
             type(binding.get("deadline_epoch")) is int and
             guard["armed_at_epoch"] <= binding["deadline_epoch"] <= guard["armed_at_epoch"] + MAX_SECONDS,
             "guard_bound")
    return plan, binding


def save_binding(directory, binding):
    put(Path(directory) / "binding.json", binding)


def make_plan(directory, api, image, data_center=None, artifact_root=None):
    directory = private_dir(directory)
    need(not (directory / "plan.json").exists() and not (directory / "binding.json").exists(), "fresh_state_required")
    need(type(image) is str and IMAGE.fullmatch(image), "image_digest_required")
    available = catalog(api)
    data_center = data_center or available["data_centers"][0]["id"]
    artifact_root = private_dir(artifact_root or directory.parent)
    task = "pqbtc-runpod-public-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:16]
    plan = {"schema": "PQBTC-RUNPOD-LEASE-1", "task": task, "image": image, "data_center": data_center,
            "mount_path": "/var/lib/pqbtc", "volume_gb": 20, "disk_gb": 40, "duration_seconds": MAX_SECONDS,
            "cap_usd": "10.00", "catalog": available, "quote": available["quote"],
            "provider_expiry": False, "guard_type": "INDEPENDENT_LOCAL_LAUNCHD", "created_at_epoch": int(time.time()),
            "artifact_root": str(artifact_root)}
    validate_plan(plan)
    put(directory / "plan.json", plan)
    binding = {"task": task, "plan_sha256": digest(read(directory / "plan.json")), "phase": "PLANNED",
               "volume_id": None, "pod_id": None, "intents": {}, "deadline_epoch": None, "deleted": {}}
    save_binding(directory, binding)
    return plan


def volume_projection(value, plan, expected_id=None):
    need(type(value) is dict and ID.fullmatch(value.get("id", "")) and value.get("name") == plan["task"] + "-data" and
         value.get("size") == 20 and value.get("dataCenter") == plan["data_center"] and value.get("type") == "STANDARD" and
         (expected_id is None or value["id"] == expected_id), "volume_identity")
    return {k: value[k] for k in ("id", "name", "size", "dataCenter", "type")}


def pod_projection(value, plan, volume_id, expected_id=None):
    need(type(value) is dict and ID.fullmatch(value.get("id", "")) and value.get("name") == plan["task"] and
         value.get("status") in STATES and (expected_id is None or value["id"] == expected_id), "pod_identity")
    need(value.get("image") == plan["image"] and value.get("cloud") == "SECURE" and value.get("disk") == 40 and
         value.get("ports") == ["22/tcp"] and value.get("registry") is None and not value.get("gpu"), "pod_configuration")
    need(value.get("cpu") == {"id": "cpu3c", "vcpuCount": 4, "memory": 8}, "pod_cpu")
    mounts = value.get("mounts")
    need(type(mounts) is dict and set(mounts) <= {"network", "global"} and mounts.get("global", []) == [] and
         mounts.get("network") == [{"volumeId": volume_id, "path": "/var/lib/pqbtc"}], "pod_mount")
    need(value.get("globalNetworking", {}).get("enabled") is False and value.get("dataCenterId") in (None, plan["data_center"]), "pod_network")
    cost = Decimal(str(value.get("cost")))
    need(cost.is_finite() and 0 <= cost <= Decimal(plan["catalog"]["hourly_compute_usd"]), "pod_cost")
    direct = (value.get("ssh") or {}).get("direct")
    ssh = None
    if direct is not None:
        need(type(direct) is dict and direct.get("username") == "root" and type(direct.get("port")) is int and
             1 <= direct["port"] <= 65535, "ssh_endpoint")
        try:
            ip = ipaddress.ip_address(direct["host"])
        except (ValueError, KeyError, TypeError):
            raise Refused("ssh_endpoint") from None
        need(ip.is_global, "ssh_endpoint")
        ssh = {"host": str(ip), "port": direct["port"], "username": "root"}
    return {"id": value["id"], "name": value["name"], "status": value["status"], "image": value["image"],
            "cpu": value["cpu"], "mounts": mounts, "hourly_compute_usd": str(cost), "ssh_direct": ssh,
            "created_at": value.get("createdAt"), "started_at": value.get("startedAt"),
            "runtime_uptime": (value.get("runtime") or {}).get("uptime")}


def live_guard(directory, plan, binding, now=None):
    now = int(time.time()) if now is None else now
    heartbeat = decode(read(Path(directory) / "guard-heartbeat.json"))
    need(heartbeat.get("task") == plan["task"] and heartbeat.get("plan_sha256") == binding["plan_sha256"] and
         type(heartbeat.get("pid")) is int and 0 <= now - heartbeat.get("epoch", 0) <= 10 and
         heartbeat.get("deadline_epoch") == binding["deadline_epoch"], "guard_not_live")
    need(type(binding["deadline_epoch"]) is int and now + 180 < binding["deadline_epoch"], "deadline")
    os.kill(heartbeat["pid"], 0)
    return heartbeat


def reconcile(api, plan, binding):
    for kind, field, intent in (("network-volumes", "volume_id", "volume"), ("pods", "pod_id", "pod")):
        if binding[field] is not None or intent not in binding["intents"]:
            continue
        name = plan["task"] + ("-data" if kind == "network-volumes" else "")
        found = [v for v in api.collection(kind) if v.get("name") == name]
        need(len(found) <= 1, "ambiguous_owned_resource")
        if found:
            # Reconciliation is cleanup-only. A newly created resource with
            # incorrect geometry must still be deleted rather than adopted or
            # left billing. The unpredictable exact name was proven absent
            # before the durable creation intent and single POST.
            need(type(found[0].get("id")) is str and ID.fullmatch(found[0]["id"]), "cleanup_identity")
            binding[field] = found[0]["id"]
        elif binding.get("rejections", {}).get(intent) in (400, 401, 403, 409, 413, 422):
            binding.setdefault("not_created", {})[intent] = {
                "http_status": binding["rejections"][intent], "complete_exact_name_list_absent": True}


def create(directory, api):
    with locked(directory) as directory:
        plan, binding = load(directory)
        live_guard(directory, plan, binding)
        need(binding["phase"] == "PLANNED" and not binding["intents"] and
             0 <= time.time() - plan["catalog"]["observed_at_epoch"] <= 900, "fresh_create_required")
        for kind, name in (("pods", plan["task"]), ("network-volumes", plan["task"] + "-data")):
            need(not any(v.get("name") == name for v in api.collection(kind)), "name_already_exists")
        binding["phase"] = "CREATING"
        binding["intents"]["volume"] = int(time.time())
        save_binding(directory, binding)
        status, value = api.call("POST", "/v2/network-volumes", {"name": plan["task"] + "-data", "size": 20,
                                                              "dataCenter": plan["data_center"], "type": "STANDARD"})
        if status != 201:
            binding.setdefault("rejections", {})["volume"] = status
            save_binding(directory, binding)
        need(status == 201, "volume_create_unconfirmed")
        need(type(value) is dict and value.get("name") == plan["task"] + "-data" and
             type(value.get("id")) is str and ID.fullmatch(value["id"]), "volume_create_identity")
        binding["volume_id"] = value["id"]
        save_binding(directory, binding)
        volume = volume_projection(value, plan, binding["volume_id"])
        binding["intents"]["pod"] = int(time.time())
        save_binding(directory, binding)
        body = {"name": plan["task"], "image": plan["image"], "cpu": {"id": "cpu3c", "vcpuCount": 4},
                "cloud": "SECURE", "disk": 40, "ports": ["22/tcp"], "dataCenterIds": [plan["data_center"]],
                "startSsh": True, "startJupyter": False,
                "mounts": {"network": [{"volumeId": volume["id"], "path": "/var/lib/pqbtc"}]}}
        put(directory / "pod-create-request.json", body)
        status, value = api.call("POST", "/v2/pods", body)
        if status != 201:
            binding.setdefault("rejections", {})["pod"] = status
            save_binding(directory, binding)
        need(status == 201, "pod_create_unconfirmed")
        need(type(value) is dict and value.get("name") == plan["task"] and ID.fullmatch(value.get("id", "")), "pod_create_identity")
        binding["pod_id"] = value["id"]
        save_binding(directory, binding)  # Cleanup identity survives strict readback failure.
        result = pod_projection(value, plan, volume["id"], binding["pod_id"])
        binding["phase"] = "ACTIVE"
        binding["startup_deadline_epoch"] = int(time.time()) + 3600
        save_binding(directory, binding)
        put(directory / "created.json", result)
        return result


def get(directory, api):
    with locked(directory) as directory:
        plan, binding = load(directory)
        need(binding["pod_id"] is not None and not binding["deleted"].get("pod"), "pod_not_bound")
        status, value = api.call("GET", "/v2/pods/" + binding["pod_id"])
        need(status == 200, "pod_read")
        result = pod_projection(value, plan, binding["volume_id"], binding["pod_id"])
        put(directory / "latest.json", result)
        return result


def ssh_transport(directory, api):
    """Bind a public host key obtained over authenticated provider TLS."""
    before = get(directory, api)
    need(before["status"] == "RUNNING" and before["ssh_direct"] and before["started_at"], "ssh_not_ready")
    status, value = api.call("POST", "/v2/pods/" + before["id"] + "/exec", HOSTKEY_COMMAND)
    need(status == 200 and type(value) is dict and type(value.get("exitCode")) is int and value["exitCode"] == 0 and value.get("timedOut") is False and
         value.get("truncated") is False and value.get("stderr") == "" and type(value.get("stdout")) is str,
         "provider_hostkey_unavailable")
    fields = value["stdout"].strip().split()
    need(len(fields) in (2, 3) and fields[0] == "ssh-ed25519" and len(fields[1]) <= 128, "provider_hostkey_shape")
    try:
        wire = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise Refused("provider_hostkey_shape") from None
    need(len(wire) == 51 and wire[:4] == b"\0\0\0\x0b" and wire[4:15] == b"ssh-ed25519" and wire[15:19] == b"\0\0\0\x20",
         "provider_hostkey_shape")
    after = get(directory, api)
    need((after["id"], after["started_at"], after["ssh_direct"]) ==
         (before["id"], before["started_at"], before["ssh_direct"]), "ssh_generation_changed")
    endpoint = before["ssh_direct"]
    generation = digest(before["started_at"].encode())[:16]
    known = Path(directory) / ("known-hosts-" + generation + "-" + digest(canonical(endpoint))[:8])
    host = endpoint["host"] if endpoint["port"] == 22 else "[" + endpoint["host"] + "]:" + str(endpoint["port"])
    content = (host + " ssh-ed25519 " + fields[1] + "\n").encode()
    try:
        fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        need(read(known) == content, "hostkey_changed_within_generation")
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(known), "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-p", str(endpoint["port"]), "root@" + endpoint["host"]]
    result = {"kind": "ssh", "argv": argv, "pod_id": before["id"], "generation": before["started_at"],
              "hostkey_source": "AUTHENTICATED_PROVIDER_EXEC_PUBLIC_KEY_ONLY", "known_hosts_sha256": digest(content)}
    put(Path(directory) / "ssh-transport.json", result)
    return result


def generation_epoch(value):
    need(type(value) is str and 0 < len(value) <= 64, "provider_generation")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        need(parsed.tzinfo is not None, "provider_generation")
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise Refused("provider_generation") from None


def restart(directory, api, *, clock=time.time, sleep=time.sleep):
    with locked(directory) as directory:
        plan, binding = load(directory)
        live_guard(directory, plan, binding)
        status, value = api.call("GET", "/v2/pods/" + binding["pod_id"])
        need(status == 200, "pod_read")
        before = pod_projection(value, plan, binding["volume_id"], binding["pod_id"])
        need(before["status"] == "RUNNING" and "restart" in value.get("actions", []) and before["started_at"], "restart_not_available")
        previous_epoch = generation_epoch(before["started_at"])
        put(directory / "restart-intent.json", {"before": before, "epoch": int(clock())})
        status, value = api.call("POST", "/v2/pods/" + binding["pod_id"] + "/action", {"action": "restart"})
        need(status == 200, "restart_unconfirmed")
        applied = pod_projection(value, plan, binding["volume_id"], binding["pod_id"])
        put(directory / "restart-accepted.json", {"before": before, "applied": applied, "http_status": 200,
                                                 "epoch": int(clock()), "mutation_retry_permitted": False})
    until = clock() + 180
    while clock() < until:
        after = get(directory, api)
        if (after["status"] == "RUNNING" and after["ssh_direct"] is not None and after["started_at"] and
                generation_epoch(after["started_at"]) > previous_epoch):
            try:
                transport = ssh_transport(directory, api)
            except Refused as error:
                if str(error) not in ("provider_hostkey_unavailable", "ssh_not_ready", "ssh_generation_changed", "provider_transport"):
                    raise
                sleep(2)
                continue
            need(transport["generation"] == after["started_at"], "restart_generation_changed")
            result = {"schema": "PQBTC-RUNPOD-RESTART-1", "result": "PASS", "kind": "PROVIDER_CONTAINER_RESTART",
                      "pod_id": before["id"], "before_generation": before["started_at"], "after_generation": after["started_at"],
                      "provider_restart": True, "transport": transport, "before": before, "after": after,
                      "same_pod_id": True, "same_persistent_volume": True, "finished_at_epoch": int(clock())}
            put(Path(directory) / ("restart-completed-" + str(time.time_ns()) + ".json"), result)
            return result
        sleep(2)
    raise Refused("restart_deadline")


def validate_export(receipt, plan, binding, api):
    raw = read(receipt)
    value = decode(raw)
    need(type(value) is dict and value.get("schema") == "PQBTC-RUNPOD-STATE-EXPORT-1" and
         value.get("result") == "PASS" and value.get("task_generated_auth_cookies_excluded") is True, "export_receipt")
    exported = value.get("binding")
    need(type(exported) is dict and exported.get("task") == plan["task"] and
         exported.get("pod_id") == binding["pod_id"] and exported.get("volume_id") == binding["volume_id"], "export_identity")
    generation_epoch(exported.get("generation"))
    archive = Path(value.get("path", ""))
    need(archive.is_absolute() and archive.suffix == ".tar" and
         archive.resolve().is_relative_to(Path(plan["artifact_root"]).resolve()), "export_path")
    need(type(value.get("bytes")) is int and 1024 <= value["bytes"] <= 512 * 1024 * 1024 and
         type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "export_size_hash")
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == value["bytes"], "export_archive")
        checksum, size, header = hashlib.sha256(), 0, b""
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            if not header:
                header = block[:512]
            size += len(block)
            need(size <= value["bytes"], "export_archive_changed")
            checksum.update(block)
        need(size == value["bytes"] and checksum.hexdigest() == value["sha256"] and
             len(header) == 512 and header[257:263] in (b"ustar\x00", b"ustar "), "export_archive_hash")
    finally:
        os.close(fd)
    if not binding.get("delete_accepted", {}).get("pod"):
        status, current = api.call("GET", "/v2/pods/" + binding["pod_id"])
        need(status == 200, "export_current_identity")
        current = pod_projection(current, plan, binding["volume_id"], binding["pod_id"])
        need(current["started_at"] == exported["generation"], "export_generation")
    return {"path": str(Path(receipt).resolve()), "sha256": digest(raw), "archive_path": str(archive),
            "archive_sha256": value["sha256"], "archive_bytes": size, "binding": exported}


def terminate(directory, api, *, export_receipt=None, emergency=False):
    with locked(directory) as directory:
        plan, binding = load(directory)
        if export_receipt is not None:
            binding["export"] = validate_export(export_receipt, plan, binding, api)
        elif not emergency and "export" in binding:
            previous = binding["export"]
            binding["export"] = validate_export(Path(previous["path"]), plan, binding, api)
            need(binding["export"]["sha256"] == previous["sha256"], "export_receipt_changed")
        need(emergency or "export" in binding, "export_required")
        binding["phase"] = "TERMINATING"
        reconcile(api, plan, binding)
        save_binding(directory, binding)
        for kind, field, label in (("pods", "pod_id", "pod"), ("network-volumes", "volume_id", "volume")):
            resource_id = binding[field]
            if resource_id is None or binding["deleted"].get(label):
                continue
            status, value = api.call("GET", "/v2/" + kind + "/" + resource_id)
            if status == 404:
                need(binding.get("delete_accepted", {}).get(label) is True, "unproven_absence")
            else:
                need(status == 200, "cleanup_read")
                if kind == "pods":
                    need(value.get("id") == resource_id and value.get("name") == plan["task"], "cleanup_identity")
                else:
                    need(value.get("id") == resource_id and value.get("name") == plan["task"] + "-data", "cleanup_identity")
                    for item in api.collection("pods"):
                        mounts = item.get("mounts") or {}
                        need(not any(v.get("volumeId") == resource_id for v in mounts.get("network", [])), "volume_still_attached")
                if not binding.get("delete_accepted", {}).get(label):
                    status, _ = api.call("DELETE", "/v2/" + kind + "/" + resource_id)
                    need(status == 204, "delete_unconfirmed")
                    binding.setdefault("delete_accepted", {})[label] = True
                    save_binding(directory, binding)
            # DELETE may be eventually consistent; caller/guard will retry
            # confirmation, retaining the durable accepted-DELETE prerequisite.
            status, _ = api.call("GET", "/v2/" + kind + "/" + resource_id)
            need(status == 404, "delete_pending")
            rows = api.collection(kind)
            need(not any(v.get("id") == resource_id for v in rows), "delete_pending")
            binding["deleted"][label] = {"id": resource_id, "confirmed_at_epoch": int(time.time()), "contract": "DELETE204_GET404_COMPLETE_LIST_ABSENT"}
            save_binding(directory, binding)
        # No-created-resource and unknown-create cases remain armed until the
        # deadline so a delayed POST cannot escape exact-name reconciliation.
        complete = all(
            binding["deleted"].get(label) or binding.get("not_created", {}).get(label) or intent not in binding["intents"]
            for label, intent in (("pod", "pod"), ("volume", "volume")))
        binding["phase"] = "CLOSED" if complete else "TERMINATING"
        save_binding(directory, binding)
        return {"task": plan["task"], "phase": binding["phase"], "deleted": binding["deleted"]}


def launchctl(*args):
    result = subprocess.run(["/bin/launchctl", *args], capture_output=True, timeout=15)
    need(len(result.stdout) <= MAX_BYTES and len(result.stderr) <= MAX_BYTES, "launchd_output")
    return result


def arm(directory):
    directory = private_dir(directory)
    with locked(directory):
        plan, binding = load(directory)
        need(binding["phase"] == "PLANNED" and binding.get("guard") is None, "guard_already_armed")
        need(sys.platform == "darwin", "mac_guard_required")
        capsule = directory / "guard-capsule"
        capsule.mkdir(mode=0o700)
        script = capsule / "provider_control.py"
        raw = Path(__file__).read_bytes()
        fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        label = "org.pqbtc.runpod." + plan["task"].rsplit("-", 1)[1]
        deadline = int(time.time()) + MAX_SECONDS
        binding["deadline_epoch"] = deadline
        binding["guard"] = {"label": label, "script_sha256": digest(raw), "armed_at_epoch": int(time.time())}
        save_binding(directory, binding)
        arguments = [sys.executable, str(script), "watch", "--state", str(directory), "--script-sha256", digest(raw)]
        payload = {"Label": label, "ProgramArguments": arguments, "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                   "ThrottleInterval": 30, "StandardOutPath": str(directory / "guard.stdout"),
                   "StandardErrorPath": str(directory / "guard.stderr"),
                   "EnvironmentVariables": {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}}
        plist = directory / "guard.plist"
        fd = os.open(plist, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            plistlib.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        for name in ("guard.stdout", "guard.stderr"):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        result = launchctl("bootstrap", "gui/" + str(os.getuid()), str(plist))
        need(result.returncode == 0, "guard_bootstrap")
    until = time.monotonic() + 15
    while time.monotonic() < until:
        try:
            heartbeat = live_guard(directory, plan, binding)
            result = launchctl("print", "gui/" + str(os.getuid()) + "/" + label)
            need(result.returncode == 0 and re.search(rb"\bpid = " + str(heartbeat["pid"]).encode() + rb"\b", result.stdout), "guard_launchd_identity")
            return {"task": plan["task"], "label": label, "deadline_epoch": deadline,
                    "pid": heartbeat["pid"], "provider_expiry": False, "guard": "INDEPENDENT_LOCAL_LAUNCHD"}
        except (Refused, OSError):
            time.sleep(0.2)
    raise Refused("guard_not_live")


def watch_tick(directory, api, *, now=None):
    now = time.time() if now is None else now
    directory = private_dir(directory)
    plan, binding = load(directory)
    put(directory / "guard-heartbeat.json", {"task": plan["task"], "plan_sha256": binding["plan_sha256"],
          "pid": os.getpid(), "epoch": int(now), "deadline_epoch": binding["deadline_epoch"]})
    if binding["phase"] == "CLOSED":
        return True
    startup_expired = (binding["phase"] == "ACTIVE" and not binding.get("ready") and
                       now >= binding.get("startup_deadline_epoch", binding["deadline_epoch"]))
    if now >= binding["deadline_epoch"] or binding["phase"] in ("ABORT_REQUESTED", "TERMINATING") or startup_expired:
        try:
            terminate(directory, api, emergency=True)
        except Refused as error:
            put(directory / "guard-last-refusal.json", {"code": str(error), "epoch": int(now)})
    return False


def watch(directory, expected_script_sha256):
    need(digest(Path(__file__).read_bytes()) == expected_script_sha256, "guard_source_changed")
    directory = private_dir(directory)
    api = API()
    while True:
        _, binding = load(directory)
        need(binding["guard"]["script_sha256"] == expected_script_sha256, "guard_source_changed")
        if watch_tick(directory, api):
            return
        time.sleep(2)


def disarm(directory):
    with locked(directory) as directory:
        plan, binding = load(directory)
        need(binding["phase"] == "CLOSED" and all(
            binding["deleted"].get(v) or binding.get("not_created", {}).get(v) or v not in binding["intents"]
            for v in ("pod", "volume")), "cleanup_not_confirmed")
        label = binding["guard"]["label"]
        need(label == "org.pqbtc.runpod." + plan["task"].rsplit("-", 1)[1], "guard_identity")
        result = launchctl("bootout", "gui/" + str(os.getuid()) + "/" + label)
        need(result.returncode == 0, "guard_bootout")
        binding["guard_disarmed_epoch"] = int(time.time())
        save_binding(directory, binding)
        return {"task": plan["task"], "disarmed": True, "deleted": binding["deleted"]}


def ready(directory, receipt):
    with locked(directory) as directory:
        plan, binding = load(directory)
        live_guard(directory, plan, binding)
        need(binding["phase"] == "ACTIVE", "not_active")
        raw = read(receipt)
        value = decode(raw)
        need(type(value) is dict and value.get("result") == "PASS" and
             value.get("pod_id") == binding["pod_id"], "readiness_receipt")
        binding["ready"] = {"path": str(Path(receipt).resolve()), "sha256": digest(raw), "epoch": int(time.time())}
        save_binding(directory, binding)
        return {"task": plan["task"], "pod_id": binding["pod_id"], "ready": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("catalog", "plan", "arm", "create", "get", "ssh", "restart", "ready", "terminate", "disarm", "watch"))
    parser.add_argument("--state", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--data-center")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--script-sha256")
    parser.add_argument("--export-receipt", type=Path)
    parser.add_argument("--emergency", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.operation == "catalog":
            result = catalog(API())
        else:
            need(args.state is not None and args.state.is_absolute(), "state_path")
            if args.operation == "plan":
                result = make_plan(args.state, API(), args.image, args.data_center, args.artifact_root)
            elif args.operation == "arm":
                result = arm(args.state)
            elif args.operation == "watch":
                watch(args.state, args.script_sha256)
                return 0
            elif args.operation == "disarm":
                result = disarm(args.state)
            elif args.operation == "get":
                result = get(args.state, API())
            elif args.operation == "restart":
                result = restart(args.state, API())
            elif args.operation == "ssh":
                result = ssh_transport(args.state, API())
            elif args.operation == "ready":
                need(args.export_receipt is not None, "readiness_receipt")
                result = ready(args.state, args.export_receipt)
            elif args.operation == "terminate":
                result = terminate(args.state, API(), export_receipt=args.export_receipt, emergency=args.emergency)
            else:
                try:
                    result = create(args.state, API())
                except Exception:
                    with locked(args.state):
                        _, binding = load(args.state)
                        binding["phase"] = "ABORT_REQUESTED"
                        save_binding(args.state, binding)
                    raise
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except Exception as error:
        code = str(error) if type(error) is Refused else "operation_failed"
        print(json.dumps({"result": "REFUSED", "code": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
