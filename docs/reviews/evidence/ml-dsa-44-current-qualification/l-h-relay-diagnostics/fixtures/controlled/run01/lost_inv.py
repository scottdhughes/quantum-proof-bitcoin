#!/usr/bin/env python3
"""Prepare/run one private v1 loss diagnostic. This is not a public soak."""
import argparse
import collections
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parent
SOURCE = CANDIDATE / "source-clean-7223772e"
DESCRIPTOR = CANDIDATE / "arm-gcc-runtime.json"
DESCRIPTOR_SHA = "c483f14b416eeb25c90d635a98f872faecda00d57259c5f35130816c2bf0eefb"
HEAD = "7223772e76d2d0a0bb7fd1d35e0e16fba61918fd"
TREE = "33b36275b1da7f7fbc27fae00d519206b0f7c16f"
IMAGE = "sha256:fc470f630a0eaa679aa49563d13b1a1e1d183528eb4348877c7cbb60b3c0e6f3"
ENGINE = "4d2c0ea7-0efe-46b4-9ca7-f8cb3ee300ab"
CONTEXT = "desktop-linux"
NAMES = ("pqbtc-mldsa-public-lostinv-a-20261117-01", "pqbtc-mldsa-public-lostinv-b-20261117-01")
PORTS = (23936, 23937)
REMOTE = "/tmp/pqbtc-lostinv-20261117-01"
CONTROL = REMOTE + ".sock"
CONTROL_CLIENT_SCRIPT = r'''import socket,sys
s=socket.socket(socket.AF_UNIX)
s.settimeout(float(sys.argv[2]))
s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read(513))
data=b""
while not data.endswith(b"\n") and len(data)<=32768:
    chunk=s.recv(32769-len(data))
    assert chunk
    data+=chunk
assert len(data)<=32768 and data.endswith(b"\n")
sys.stdout.buffer.write(data)
s.close()
'''


class Refused(Exception):
    pass


def require(value, label):
    if not value:
        raise Refused(label)


def left(deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "DEADLINE")
    return remaining


def command(args, *, timeout=20):
    # No raw argv, stdout, stderr or exception text enters reports.
    return subprocess.run(args, capture_output=True, timeout=timeout, check=False)


def engine_guard():
    require("DOCKER_HOST" not in os.environ, "DOCKER_HOST_OVERRIDE")
    require(os.environ.get("DOCKER_CONTEXT") == CONTEXT, "CONTEXT")
    result = command(["docker", "info", "--format", "{{json .ID}}"], timeout=10)
    require(result.returncode == 0 and json.loads(result.stdout) == ENGINE, "ENGINE")


def host_guard():
    require(sys.platform == "darwin" and os.geteuid() != 0, "HOST_PLATFORM_OR_UID")
    require("DOCKER_HOST" not in os.environ, "DOCKER_HOST_OVERRIDE")
    held = []
    try:
        for port in PORTS:
            sock = socket.socket()
            held.append(sock)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                raise Refused("HOST_PORT_UNAVAILABLE") from None
    finally:
        for sock in held:
            sock.close()


def inspect_absent(result, kind, target):
    errors = {"Error: No such object: " + target}
    if kind == "container":
        errors.update({"Error: No such container: " + target,
                       "Error response from daemon: No such container: " + target})
    else:
        errors.update({"Error: No such volume: " + target,
                       "Error response from daemon: get " + target + ": no such volume"})
    return (result.returncode == 1 and result.stdout.strip() in (b"", b"[]") and
            result.stderr.strip() in {value.encode("ascii") for value in errors})


def fresh_namespaces():
    for name in NAMES:
        for kind, target in (("container", name), ("volume", name + "-data-v1")):
            result = command(["docker", kind, "inspect", "--format", "{{json .}}", target])
            require(inspect_absent(result, kind, target), "FRESH_NAMESPACE_PROBE_REFUSED")


def source_guard():
    def git(*args):
        result = command(["git", "-C", str(SOURCE), *args])
        require(result.returncode == 0, "SOURCE_GIT")
        return result.stdout.strip().decode()
    require(git("rev-parse", "HEAD") == HEAD and git("rev-parse", "HEAD^{tree}") == TREE and
            not git("status", "--porcelain=v1", "--untracked-files=all"), "SOURCE_IDENTITY")
    require(hashlib.sha256(DESCRIPTOR.read_bytes()).hexdigest() == DESCRIPTOR_SHA, "DESCRIPTOR_SHA")
    value = json.loads(DESCRIPTOR.read_bytes())
    require(value["image"] == IMAGE and value["manifest"]["source_head"] == HEAD and
            value["manifest"]["source_tree"] == TREE, "DESCRIPTOR_IDENTITY")
    return value


def ownership_guard(value, controller, identity):
    require(type(value) is dict and value.get("Id") == identity and
            re.fullmatch("[0-9a-f]{64}", identity or ""), "CONTAINER_ID")
    require(controller.manager.container in NAMES and controller.manager.port == PORTS[NAMES.index(controller.manager.container)] and
            controller.manager.volume == controller.manager.container + "-data-v1", "OWNED_NAMESPACE")
    require(value.get("Name") == "/" + controller.manager.container, "OWNED_CONTAINER_NAME")
    controller.manager.layout(value)
    require(value["Image"] == IMAGE, "OWNED_IMAGE")


class OwnedSlot:
    """Registered before ensure: bind an unknown ID only after full layout proof."""
    def __init__(self, controller):
        self.controller = controller
        self.identity = None

    def bind(self):
        engine_guard()
        manager = self.controller.manager
        result = manager.run(["inspect", "--format", "{{json .}}", manager.container], check=False, timeout=10)
        if inspect_absent(result, "container", manager.container):
            require(self.identity is None, "OWNED_CONTAINER_DISAPPEARED")
            return None
        require(result.returncode == 0 and len(result.stdout) <= 131072, "OWNED_INSPECT_PROBE_REFUSED")
        value = json.loads(result.stdout)
        identity = self.identity or value.get("Id")
        ownership_guard(value, self.controller, identity)
        self.identity = identity
        return identity

    def stop(self):
        identity = self.bind()
        if identity is None:
            return {"container": self.controller.manager.container, "container_absent": True}
        return stop_owned(self.controller, identity)


def stop_owned(controller, identity):
    engine_guard()
    value = controller.manager.inspect()
    ownership_guard(value, controller, identity)
    controller.manager.run(["stop", "--time", "5", identity], timeout=15)
    value = controller.manager.inspect()
    ownership_guard(value, controller, identity)
    require(value["State"]["Running"] is False and value["State"]["Pid"] == 0, "STOP_PID_PROOF")
    volume = controller.manager.run(["volume", "inspect", "--format", "{{json .}}", controller.manager.volume], timeout=10)
    record = json.loads(volume.stdout)
    require(record["Name"] == controller.manager.volume and record.get("Labels") == importlib.import_module("public_controller").LABELS,
            "RETAINED_VOLUME_PROOF")
    return {"id": identity, "stopped": True, "pid": 0, "volume_retained": True}


class Trace:
    def __init__(self, output):
        self.path = output / "events.jsonl"
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.count = 0

    def event(self, name, **data):
        row = {"event": name, "monotonic_ns": time.monotonic_ns(), **data}
        raw = json.dumps(row, sort_keys=True, allow_nan=False).encode() + b"\n"
        require(len(raw) <= 32768, "TRACE_BOUND")
        offset = 0
        while offset < len(raw):
            offset += os.write(self.fd, raw[offset:])
        os.fsync(self.fd)
        self.count += 1


def write_json(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        require(os.write(fd, raw) == len(raw), "REPORT_WRITE")
        os.fsync(fd)
    finally:
        os.close(fd)


def fresh_ping(rpc, expected, deadline):
    before = rpc("peers", deadline)["peers"]
    require(len(before) == 1 and before[0]["id"] == expected and before[0]["transport"] == "v1", "PING_PEER_ID")
    rpc("ping", deadline)
    while True:
        rows = rpc("peers", deadline)["peers"]
        require(len(rows) == 1 and rows[0]["id"] == expected and rows[0]["transport"] == "v1", "PING_PEER_CHANGED")
        after = rows[0]
        if after["ping_sent"] > before[0]["ping_sent"] and after["pong_received"] > before[0]["pong_received"] and not after["ping_pending"]:
            return {"id": expected, "ping_sent_before": before[0]["ping_sent"], "ping_sent_after": after["ping_sent"],
                    "pong_received_before": before[0]["pong_received"], "pong_received_after": after["pong_received"]}
        time.sleep(min(0.05, left(deadline)))


def target_matches(drop, tx):
    require(len(drop) == 1 and drop[0]["type"] in (1, 5), "DROP_COUNT")
    require(drop[0]["hash"] == tx["txid" if drop[0]["type"] == 1 else "wtxid"], "DROP_TARGET_HASH")


def payment_phase(ops, trace, *, seconds=60):
    """One send only. Reannouncement never retries an ambiguous operation."""
    started = time.monotonic()
    deadline = started + seconds
    ids = ops.ready(deadline)
    trace.event("target_readiness", ids=ids, budget_seconds=seconds)
    prior_floors = ops.floors()
    ops.arm(deadline)
    sent = ops.send(deadline)
    tx = ops.txmeta(sent["txid"], deadline)
    floors = ops.floors()
    expected_floors = copy.deepcopy(prior_floors)
    expected_floors[0]["next_change"] += 1
    require(floors == expected_floors, "TARGET_ONE_CHANGE_ISSUANCE")
    trace.event("target_broadcast_once", **tx, checkpoints=floors)
    next_rebroadcast, count, polls, matched = started + 10, 0, 0, False
    while time.monotonic() < deadline:
        # Stop dispatching before expiry; never reset the original payment clock.
        if deadline - time.monotonic() < 0.25:
            time.sleep(max(0, deadline - time.monotonic()))
            break
        proxy = ops.proxy(deadline)
        if proxy["dropped"]:
            target_matches(proxy["dropped"], tx)
            matched = True
        require(not ops.present(tx["txid"], deadline), "BASELINE_RECIPIENT_RECEIVED")
        polls += 1
        require(ops.floors() == floors, "BASELINE_FLOORS_CHANGED")
        if count < 5 and time.monotonic() >= next_rebroadcast:
            before = ops.pings(ids, deadline)
            value = ops.reannounce(tx["txid"], deadline)
            require(value["raw_transaction_sha256"] == tx["raw_transaction_sha256"] and
                    value.get("reissued_payment") is False, "REANNOUNCEMENT_BYTES")
            after = ops.pings(ids, deadline)
            require(ops.floors() == floors, "REANNOUNCEMENT_FLOORS")
            count += 1
            trace.event("same_connection_same_known_rebroadcast", ordinal=count,
                        elapsed_seconds=time.monotonic() - started, before=before, after=after, **value)
            next_rebroadcast = started + 10 * (count + 1)
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    require(matched and count == 5 and time.monotonic() >= deadline, "BASELINE_INCOMPLETE")
    trace.event("original_budget_expired_without_receipt", elapsed_seconds=time.monotonic() - started,
                recipient_absent_queries=polls, reannouncements=count, ids=ids)
    return tx, floors, ids


def run(output):
    require(output.parent == HERE and not os.path.lexists(output), "NEW_OUTPUT_ONLY")
    host_guard()
    os.environ["DOCKER_CONTEXT"] = CONTEXT
    engine_guard()
    descriptor = source_guard()
    fresh_namespaces()
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(SOURCE / "contrib/ml-dsa-console")]
    controls = importlib.import_module("public_controller")
    output.mkdir(mode=0o700)
    trace = Trace(output)
    controllers, slots, passwords = [], [], []
    action_counts = collections.Counter()
    finished = threading.Event()
    timed_out = threading.Event()
    report = {"schema": "PQBTC-LOST-INV-DIAGNOSTIC-1", "scope": "PRIVATE_V1_DIAGNOSTIC_ZERO_PUBLIC_SOAK_CREDIT",
              "source_head": HEAD, "source_tree": TREE, "image": IMAGE, "descriptor_sha256": DESCRIPTOR_SHA,
              "result": "FAIL", "diagnostic_limit": "Forced native v1 transport, one frame dropped by disposable proxy"}
    proxy_process = None

    class BoundedController(controls.PublicController):
        operation_deadline = None

        def _line(self, process, timeout, maximum):
            if self.operation_deadline is not None:
                timeout = min(timeout, left(self.operation_deadline))
            return controls.PublicController._line(process, timeout, maximum)

        def _invoke(self, user, *args, data=None, timeout=90):
            if self.operation_deadline is not None:
                timeout = min(timeout, left(self.operation_deadline))
            return super()._invoke(user, *args, data=data, timeout=timeout)

    def action(index, name, params=None, deadline=None):
        controller = controllers[index]
        if deadline is not None:
            left(deadline)
        controller.operation_deadline = deadline
        try:
            action_counts[str(index) + ":" + name] += 1
            value = controller.action(name, params, include_status=name not in ("transaction", "rebroadcast", "peer_status"))["result"]
            if deadline is not None:
                left(deadline)
            return value
        finally:
            controller.operation_deadline = None

    def rpc(index, op, deadline, **params):
        controller = controllers[index]
        budget = left(deadline)
        raw = controller._invoke("1001:1000", "python3", "-B", REMOTE + "-rpc.py", controls.SOURCE,
                                 controls.DATA + "/node/chain", data=json.dumps({"op": op, "timeout": min(3, budget), **params}).encode(),
                                 timeout=min(5, budget))
        left(deadline)
        require(len(raw) <= 4096, "RPC_RESULT_BOUND")
        value = json.loads(raw)
        require(value.get("ok") is True, "RPC_FAILED")
        return value

    def proxy(op, deadline):
        raw = controllers[1]._invoke("1001:1000", "python3", "-B", "-c", CONTROL_CLIENT_SCRIPT, CONTROL, str(min(2, left(deadline))),
                                     data=json.dumps({"op": op}).encode() + b"\n", timeout=min(4, left(deadline)))
        left(deadline)
        require(len(raw) <= 32768, "PROXY_RESULT_BOUND")
        value = json.loads(raw)
        require(value.get("ok") is True and value.get("active_connections") == 1 and value.get("connections") in (1, 2), "PROXY_STATE")
        return value

    def peers(deadline):
        result = [rpc(i, "peers", deadline)["peers"] for i in range(2)]
        require(all(len(rows) == 1 and rows[0]["version"] > 0 and rows[0]["relaytxes"] is True and
                    rows[0]["transport"] == "v1" for rows in result), "EXACT_V1_PEERS")
        require(result[0][0]["addr"] == endpoint and re.fullmatch(r"127\.0\.0\.1:[0-9]+", result[1][0]["addr"]), "PEER_ENDPOINTS")
        return [rows[0]["id"] for rows in result]

    def wait(predicate, deadline, label):
        while not predicate():
            left(deadline)
            time.sleep(min(0.05, left(deadline)))

    def agreement(deadline):
        snapshots = []
        for controller in controllers:
            controller.operation_deadline = deadline
            try:
                snapshots.append(controller.status()["nodes"])
            finally:
                controller.operation_deadline = None
        left(deadline)
        return all(snapshots) and len({tuple(rows[0][key] for key in ("height", "tip", "utxo_hash", "utxo_count")) for rows in snapshots}) == 1

    def pings(ids, deadline):
        return [fresh_ping(lambda op, d, i=i: rpc(i, op, d), ids[i], min(deadline, time.monotonic() + 3)) for i in range(2)]

    def confirm(txid, deadline):
        wait(lambda: action(1, "transaction", {"txid": txid}, deadline)["in_mempool"], deadline, "MEMPOOL")
        block = action(1, "mine", deadline=deadline)["blocks"][0]
        wait(lambda: agreement(deadline), deadline, "AGREEMENT")
        for i in range(2):
            value = action(i, "transaction", {"txid": txid, "block_hash": block}, deadline)
            require(value["confirmed"] is True and value["block_hash"] == block and value["confirmations"] >= 1, "BLOCK_MEMBERSHIP")
        return block

    def watchdog():
        if not finished.wait(600):
            timed_out.set()
            for slot in list(slots):
                try:
                    slot.stop()
                except Exception:
                    pass

    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()
    try:
        for i, name in enumerate(NAMES):
            controller = BoundedController(output / ("wallet-" + str(i)), descriptor, container=name, p2p_port=PORTS[i])
            controllers.append(controller)
            slot = OwnedSlot(controller)
            slots.append(slot)
            controller.manager.ensure(descriptor)
            require(slot.bind() is not None, "OWNED_CREATED_CONTAINER_MISSING")
            action(i, "start")
            passwords.append(secrets.token_urlsafe(32))
            for local, remote in ((HERE / "native_rpc.py", REMOTE + "-rpc.py"),):
                data = local.read_bytes()
                install = ('import os,sys;data=sys.stdin.buffer.read(1048577);assert len(data)<=1048576;'
                           'fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);'
                           'assert os.write(fd,data)==len(data);os.fsync(fd);os.close(fd)')
                controller._invoke("1001:1000", "python3", "-B", "-c", install, remote, data=data)
        trace.event("two_fresh_owned_nodes_started", container_ids=[slot.identity for slot in slots])
        controllers[1]._invoke("1001:1000", "python3", "-B", "-c", install, REMOTE + "-proxy.py", data=(HERE / "inv_proxy.py").read_bytes())
        proxy_process = subprocess.Popen(controllers[1]._command("1001:1000", "python3", "-B", REMOTE + "-proxy.py", "--control", CONTROL),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready_deadline = time.monotonic() + 5
        while True:
            require(proxy_process.poll() is None, "PROXY_START")
            exists = controllers[1]._invoke("1001:1000", "python3", "-B", "-c",
                                           "import pathlib,sys;print(int(pathlib.Path(sys.argv[1]).is_socket()))", CONTROL,
                                           timeout=min(2, left(ready_deadline)))
            if exists.strip() == b"1":
                break
            time.sleep(min(0.05, left(ready_deadline)))
        action(0, "bootstrap")
        endpoint = controllers[1].manager.inspect()["NetworkSettings"]["Networks"]["bridge"]["IPAddress"] + ":23834"
        rpc(0, "connect", time.monotonic() + 5, endpoint=endpoint)
        wait(lambda: agreement(time.monotonic() + 10), time.monotonic() + 60, "BOOTSTRAP_RELAY")
        for i in range(2):
            action(i, "setup", {"password": passwords[i]})
        addresses = [action(i, "receive")["address"] for i in range(2)]
        for i in range(2):
            action(i, "fund")
            wait(lambda: agreement(time.monotonic() + 10), time.monotonic() + 60, "FUNDING_RELAY")
        baseline = action(0, "send", {"address": addresses[1], "amount_sats": 100000, "fee_sats": 5000}, time.monotonic() + 60)
        baseline_block = confirm(baseline["txid"], time.monotonic() + 60)
        trace.event("baseline_cross_node_payment_confirmed", txid=baseline["txid"], block_hash=baseline_block)
        for i in range(2):
            policy = action(i, "peer_status")
            require(policy["declared_endpoints"] == [], "DIAGNOSTIC_AUTOMATIC_PEERS")

        class Operations:
            def ready(self, deadline):
                ids = peers(deadline)
                trace.event("fresh_target_readiness_pongs", pings=pings(ids, deadline))
                return ids

            def arm(self, deadline):
                value = proxy("arm", deadline)
                require(value["armed"] is True and value["dropped"] == [], "ARM")

            def send(self, deadline):
                return action(0, "send", {"address": addresses[1], "amount_sats": 100000, "fee_sats": 5000}, deadline)

            def txmeta(self, txid, deadline):
                value = rpc(0, "txmeta", deadline, txid=txid)
                return {key: value[key] for key in ("txid", "wtxid", "raw_transaction_sha256")}

            def floors(self):
                return [copy.deepcopy(c.journal["checkpoint"]) for c in controllers]

            def proxy(self, deadline):
                return proxy("status", deadline)

            def present(self, txid, deadline):
                return action(1, "transaction", {"txid": txid}, deadline)["in_mempool"]

            def pings(self, ids, deadline):
                return pings(ids, deadline)

            def reannounce(self, txid, deadline):
                value = action(0, "rebroadcast", {"txid": txid}, deadline)
                require(value.get("txid") == txid and value.get("known_in_mempool") is True and value.get("rebroadcast") is True, "KNOWN_REANNOUNCEMENT")
                return value

        ops = Operations()
        target, floors, ids = payment_phase(ops, trace)
        require(peers(time.monotonic() + 5) == ids, "BASELINE_IDS_CHANGED")
        require(ops.present(target["txid"], time.monotonic() + 5) is False and ops.floors() == floors,
                "BASELINE_AFTER_BUDGET_RECEIPT_OR_ISSUANCE")
        trace.event("post_budget_absence_and_fresh_pongs", pings=pings(ids, time.monotonic() + 6),
                    recipient_absent=True, checkpoints_unchanged=True)
        final_proxy = proxy("status", time.monotonic() + 5)
        target_matches(final_proxy["dropped"], target)
        require(final_proxy["connections"] == 1 and final_proxy["armed"] is False, "BASELINE_PROXY_CONNECTION")
        report["baseline"] = {"result": "LOSS_REPRODUCED", "target": target, "peer_ids": ids, "proxy": final_proxy,
                              "budget_seconds": 60, "reissued_payment": False}
        # A separately declared control clock starts here; target send is never repeated.
        control_started = time.monotonic()
        control_deadline = control_started + 60
        trace.event("positive_control_budget_declared", budget_seconds=60, old_peer_ids=ids)
        rpc(0, "disconnect", control_deadline, endpoint=endpoint, id=ids[0])
        wait(lambda: all(not rpc(i, "peers", control_deadline)["peers"] for i in range(2)), control_deadline, "DISCONNECT")
        rpc(0, "connect", control_deadline, endpoint=endpoint)
        new_ids = None
        while new_ids is None:
            rows = [rpc(i, "peers", control_deadline)["peers"] for i in range(2)]
            if all(len(rows_i) == 1 and rows_i[0]["version"] > 0 for rows_i in rows):
                new_ids = peers(control_deadline)
            else:
                time.sleep(min(0.05, left(control_deadline)))
        require(all(old != new for old, new in zip(ids, new_ids)), "RECONNECT_IDS")
        fresh = pings(new_ids, control_deadline)
        reannounced = ops.reannounce(target["txid"], control_deadline)
        require(reannounced["raw_transaction_sha256"] == target["raw_transaction_sha256"] and
                reannounced["reissued_payment"] is False and ops.floors() == floors, "CONTROL_SAME_BYTES_FLOORS")
        block = confirm(target["txid"], control_deadline)
        require(ops.floors() == floors, "CONTROL_FLOORS")
        final_proxy = proxy("status", control_deadline)
        target_matches(final_proxy["dropped"], target)
        require(final_proxy["connections"] == 2, "CONTROL_CONNECTION_COUNT")
        trace.event("positive_control_same_bytes_confirmed_after_exact_reconnect", target=target,
                    block_hash=block, new_peer_ids=new_ids, fresh_pongs=fresh, elapsed_seconds=time.monotonic() - control_started)
        report["positive_control"] = {"result": "PASS", "block_hash": block, "peer_ids": new_ids,
                                       "budget_seconds": 60, "elapsed_seconds": time.monotonic() - control_started}
        require(not timed_out.is_set(), "WATCHDOG")
        require(action_counts["0:send"] == 2 and action_counts["1:send"] == 0 and
                action_counts["0:receive"] == 1 and action_counts["1:receive"] == 1 and
                action_counts["0:rebroadcast"] == 6, "NO_ADDITIONAL_PAYMENT_ISSUANCE")
        report["action_counts"] = dict(action_counts)
        source_guard()
        require(not any(secret in json.dumps(report) or secret.encode() in trace.path.read_bytes() for secret in passwords), "REPORT_REDACTION")
        report["result"] = "REPRODUCED_WITH_PASSING_POSITIVE_CONTROL"
    except Exception:
        report["error"] = "DIAGNOSTIC_FAILED_NO_AMBIGUOUS_ACTION_RETRIED"
    finally:
        cleanup = []
        if proxy_process is not None:
            try:
                proxy("stop", time.monotonic() + 4)
                proxy_process.communicate(timeout=5)
                require(proxy_process.returncode == 0, "PROXY_EXIT")
            except Exception:
                cleanup.append("PROXY_CLOSE_FAILED")
        for slot in slots:
            controller = slot.controller
            try:
                identity = slot.bind()
                require(identity is not None or (controller._worker is None and controller._signer is None), "UNBOUND_NATIVE_HANDLES")
                controller.operation_deadline = time.monotonic() + 45
                controller.close()
            except Exception:
                cleanup.append("CONTROLLER_CLOSE_FAILED")
            finally:
                controller.operation_deadline = None
            try:
                report.setdefault("retained_containers", []).append(slot.stop())
            except Exception:
                cleanup.append("OWNED_STOP_PROOF_FAILED")
        finished.set()
        thread.join(timeout=1)
        report["cleanup_errors"] = cleanup
        report["watchdog_fired"] = timed_out.is_set()
        if cleanup or timed_out.is_set():
            report["result"] = "FAIL"
        trace.event("terminal", result=report["result"], cleanup_errors=cleanup)
        os.close(trace.fd)
        passwords.clear()
        report["trace_events"] = trace.count
        report["trace_sha256"] = hashlib.sha256(trace.path.read_bytes()).hexdigest()
        write_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Only after parent review of this helper hash")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    require(args.execute, "EXECUTION_SWITCH_REQUIRED")
    report = run(args.output_dir.resolve())
    print(json.dumps({"result": report["result"], "report": str(args.output_dir / "report.json")}))
    return 0 if report["result"] == "REPRODUCED_WITH_PASSING_POSITIVE_CONTROL" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"result":"FAIL","error":"DIAGNOSTIC_PREFLIGHT_REFUSED"}')
        raise SystemExit(1)
