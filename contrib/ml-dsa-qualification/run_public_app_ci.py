#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Private two-container public-profile app flow. This is not public soak time."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "contrib/ml-dsa-console"
sys.path.insert(0, str(CONSOLE))
import app  # noqa: E402
import public_app  # noqa: E402
import public_controller as controls  # noqa: E402
from run_assembled_ci import checkout_identity  # noqa: E402


def require(value, message):
    if not value:
        raise ValueError(message)


def wait(predicate, label, seconds=180):
    deadline = time.monotonic() + seconds
    while True:
        if predicate():
            return
        require(time.monotonic() < deadline, label + " deadline")
        time.sleep(0.1)


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, "Private peer recovery deadline")
    return value


def peer_snapshot(controller, deadline):
    remaining(deadline)
    value = controller.action("peer_status", include_status=False)["result"]
    remaining(deadline)
    require(type(value.get("network_active")) is bool and type(value.get("transaction_peers")) is int and
            0 <= value["transaction_peers"] <= 256, "Native transaction-peer evidence missing")
    return value


def wait_transaction_peers(controllers, deadline, *, endpoint=None):
    while True:
        values = [peer_snapshot(controller, deadline) for controller in controllers]
        require(all(value["network_active"] for value in values), "Native network unexpectedly inactive")
        exact = endpoint is None or (endpoint in values[0].get("declared_endpoints", []) and
                                     endpoint in values[0].get("connected_endpoints", []))
        if exact and all(value["transaction_peers"] >= 1 for value in values):
            return values
        time.sleep(min(0.1, remaining(deadline)))


def reannounce_known(controller, txid, deadline):
    require(type(txid) is str and re.fullmatch("[0-9a-f]{64}", txid), "Known transaction identity required")
    before = copy.deepcopy(controller.journal["checkpoint"])
    remaining(deadline)
    value = controller.action("rebroadcast", {"txid": txid}, include_status=False)["result"]
    remaining(deadline)
    require(value.get("txid") == txid and value.get("known_in_mempool") is True and
            value.get("rebroadcast") is True and value.get("reissued_payment") is False,
            "Known reannouncement identity proof failed")
    require(controller.journal["checkpoint"] == before, "Reannouncement changed the wallet checkpoint or floors")
    return value


def native_peer(controller, endpoint, deadline, *, disconnect=False):
    """Only the generated owned-node RPC may disconnect its exact target ID."""
    require(type(endpoint) is str and re.fullmatch(r"[0-9.]+:23833", endpoint), "Exact private native peer endpoint required")
    script = r'''import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1]+"/contrib/ml-dsa-console")
sys.path.insert(0,sys.argv[1]+"/test/functional")
from public_runtime import PublicNode
from test_framework.authproxy import AuthServiceProxy
node=PublicNode("",Path(sys.argv[2]),AuthServiceProxy)
endpoint=sys.argv[3];deadline=time.monotonic()+float(sys.argv[5])
def peers():
    left=deadline-time.monotonic();assert left>0
    values=node.rpc(timeout=min(0.5,left)).getpeerinfo();assert isinstance(values,list) and len(values)<=256
    return [{"id":p["id"],"addr":p["addr"],"version":p.get("version",0),"relaytxes":p.get("relaytxes",False)}
            for p in values if p["addr"]==endpoint]
before=peers();result={"endpoint":endpoint,"matches":before}
if sys.argv[4]=="disconnect":
    assert len(before)==1 and type(before[0]["id"]) is int and before[0]["version"]>0 and before[0]["relaytxes"] is True
    old=before[0]["id"]
    node.rpc(timeout=min(0.5,deadline-time.monotonic())).disconnectnode(nodeid=old)
    while True:
        after=peers()
        if all(p["id"]!=old for p in after):break
        time.sleep(0.05)
    result.update(disconnected_node_id=old,old_peer_absent=True,matches=after)
print(json.dumps(result,sort_keys=True))'''
    raw = controller._invoke("1001:1000", "python3", "-B", "-c", script, controls.SOURCE,
                             controls.DATA + "/node/chain", endpoint, "disconnect" if disconnect else "observe",
                             str(min(2, remaining(deadline))), timeout=min(5, remaining(deadline)))
    remaining(deadline)
    require(len(raw) <= 4096, "Native peer evidence bound")
    value = json.loads(raw)
    require(type(value) is dict and value.get("endpoint") == endpoint and type(value.get("matches")) is list and
            len(value["matches"]) <= 4 and all(type(row) is dict and row.get("addr") == endpoint and
            type(row.get("id")) is int and row["id"] >= 0 for row in value["matches"]), "Exact native peer evidence refused")
    if disconnect:
        require(value.get("old_peer_absent") is True and type(value.get("disconnected_node_id")) is int and
                all(row["id"] != value["disconnected_node_id"] for row in value["matches"]), "Native peer disconnect was not proved")
    return value


class HTTPConsole:
    def __init__(self, controller):
        self.controller = controller
        self.token = secrets.token_urlsafe(32)
        self.server = app.make_server(controller, port=0, token=self.token, action_validator=public_app.validate_action,
                                      assets_dir=CONSOLE / "web-public")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)

    def request(self, action=None, params=None, *, succeeds=True, timeout=300):
        require(type(timeout) in (int, float) and 0 < timeout <= 300, "HTTP app operation timeout refused")
        if action is None:
            request = Request(self.url + "/api/status")
        else:
            request = Request(self.url + "/api/action", data=json.dumps({"action": action, "params": params or {},
                              "request_id": uuid.uuid4().hex}).encode(), headers={"Content-Type": "application/json",
                              "Origin": self.url, "X-Console-Token": self.token})
        try:
            with urlopen(request, timeout=timeout) as response:
                value = json.load(response)
        except HTTPError as error:
            with error:
                value = json.load(error)
        require(value.get("ok") is succeeds, action + ": " + str(value.get("error", "unexpected admission")) if action else "status refused")
        return value["data"] if succeeds else value

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run(descriptor, output, *, docker=("docker",), expected_head=None):
    descriptor = controls.source.validate_descriptor(descriptor)
    require(expected_head is None or descriptor["manifest"]["source_head"] == expected_head, "Public app source HEAD mismatch")
    identity = checkout_identity(ROOT, expected_head) if expected_head is not None else None
    require(identity is None or descriptor["manifest"]["source_tree"] == identity["tree"], "Public app source tree mismatch")
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), "Public app evidence directory must be new")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "PQBTC-MLDSA44-PUBLIC-APP-FLOW-1", "scope": "PRIVATE_TWO_CONTAINER_APP_FLOW_NOT_PUBLIC_SOAK",
              "source_head": descriptor["manifest"]["source_head"], "source_tree": descriptor["manifest"]["source_tree"],
              "image": descriptor["image"], "manifest_sha256": descriptor["manifest_sha256"], "events": [], "result": "FAIL"}
    report["clean_source_qualified"] = False
    controllers, consoles, passwords = [], [], []
    passed = False

    def event(name, **data):
        item = {"name": name, "monotonic_ns": time.monotonic_ns(), **data}
        report["events"].append(item)
        print(json.dumps(item, sort_keys=True), flush=True)

    def connect():
        target = controllers[1].manager.inspect()["NetworkSettings"]["Networks"]["bridge"]["IPAddress"] + ":23833"
        consoles[0].request("peer", {"endpoint": target})

    def agreement(deadline=None):
        values = [console.request(timeout=min(300, remaining(deadline)) if deadline is not None else 300) for console in consoles]
        return all(value["nodes"] for value in values) and len({tuple(value["nodes"][0][key] for key in ("height", "tip", "utxo_hash", "utxo_count")) for value in values}) == 1

    def cipher_digest(controller):
        script = ('import hashlib,os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;'
                  'print(hashlib.sha256(os.read(fd,168)).hexdigest());os.close(fd)')
        return controller._invoke("1000:1000", "python3", "-c", script, controls.DATA + "/signer/current/wallet.dat").decode().strip()

    def confirmed_send(source_index, destination, amount=100000):
        deadline = time.monotonic() + 60
        sent = consoles[source_index].request("send", {"address": destination, "amount_sats": amount, "fee_sats": 5000},
                                             timeout=min(300, remaining(deadline)))["result"]
        confirm_known(sent, source_index, deadline)
        return sent

    def confirm_known(sent, source_index, deadline=None):
        deadline = time.monotonic() + 60 if deadline is None else deadline
        peer = controllers[1 - source_index]
        def relayed():
            remaining(deadline)
            value = peer.action("transaction", {"txid": sent["txid"]}, include_status=False)["result"]
            remaining(deadline)
            require(value.get("txid") == sent["txid"], "Native relay query changed transaction identity")
            return value.get("in_mempool") is True
        wait(relayed, "native P2P transaction relay", seconds=remaining(deadline))
        block = consoles[1 - source_index].request("mine", timeout=min(300, remaining(deadline)))["result"]["blocks"][0]
        wait(lambda: agreement(deadline), "full tip/UTXO agreement", seconds=remaining(deadline))
        for controller in controllers:
            remaining(deadline)
            membership = controller.action("transaction", {"txid": sent["txid"], "block_hash": block}, include_status=False)["result"]
            require(membership.get("confirmed") is True and membership.get("txid") == sent["txid"] and membership.get("block_hash") == block and
                    type(membership.get("confirmations")) is int and membership["confirmations"] >= 1,
                    "relayed payment missing from the active block")
        remaining(deadline)
        event("confirmed_cross_container_send", txid=sent["txid"], block_hash=block, source=source_index)

    try:
        for index in range(2):
            name = "pqbtc-mldsa-public-ci-" + uuid.uuid4().hex[:12]
            # Refuse adoption of existing state, even if ownership labels match.
            for kind, target in (("container", name), ("volume", name + "-data-v1")):
                result = subprocess.run([*docker, kind, "inspect", target], capture_output=True, timeout=20)
                require(result.returncode != 0, "Private app namespace already exists")
            controller = controls.PublicController(output / ("wallet" + str(index)), descriptor, container=name,
                                                   p2p_port=23933 + index, docker=docker)
            controllers.append(controller)
            consoles.append(HTTPConsole(controller))
            passwords.append(secrets.token_urlsafe(32))
            consoles[-1].request("start")
        event("two_fresh_private_containers_started", containers=[c.manager.container for c in controllers])
        original_volumes = [c.manager._read_json("public-runtime.json")["volume_id"] for c in controllers]
        # Before H1, setup must refuse before creating custody.
        consoles[0].request("setup", {"password": passwords[0]}, succeeds=False)
        require(controllers[0].journal["checkpoint"] is None, "pre-activation setup created custody")
        consoles[0].request("bootstrap")
        connect()
        wait(agreement, "activation relay")
        for index, console in enumerate(consoles):
            console.request("setup", {"password": passwords[index]})
        addresses = [console.request("receive")["result"]["address"] for console in consoles]
        for console in consoles:
            console.request("fund")
            wait(agreement, "coinbase funding relay")
        require(all(console.request()["wallet"]["spendable_sats"] > 100000 for console in consoles), "coinbase maturity missing")
        event("two_native_test_wallets_funded", wallet_ids=[console.request()["wallet"]["wallet_id"] for console in consoles])
        old_backup = consoles[0].request("backup")["result"]["id"]
        consoles[0].request("unlock", {"password": passwords[0]})
        later = consoles[0].request("receive")["result"]
        require(later["index"] == 1, "second issued receive index mismatch")
        confirmed_send(0, addresses[1])
        confirmed_send(1, later["address"])
        # Disconnect the exact existing native peer without changing its
        # maintained policy, bridge, wallet state or network-active control.
        endpoint = controllers[1].manager.inspect()["NetworkSettings"]["Networks"]["bridge"]["IPAddress"] + ":23833"
        started = time.monotonic()
        deadline = started + 60
        dropped = native_peer(controllers[0], endpoint, deadline, disconnect=True)
        ready = wait_transaction_peers(controllers, deadline, endpoint=endpoint)
        replaced = native_peer(controllers[0], endpoint, deadline)
        require(replaced["matches"] and all(row["id"] != dropped["disconnected_node_id"] for row in replaced["matches"]),
                "Native peer recovery did not establish a fresh exact connection")
        event("unexpected_native_peer_disconnect_repaired", endpoint=endpoint, old_node_id=dropped["disconnected_node_id"],
              new_node_ids=[row["id"] for row in replaced["matches"]], transaction_peers=[value["transaction_peers"] for value in ready],
              elapsed_seconds=time.monotonic() - started)
        # Create one known mempool transaction while disconnected, then repair
        # and reannounce those same bytes. No receive/send is repeated.
        started = time.monotonic()
        deadline = started + 60
        paused = consoles[0].request("network", {"active": False}, timeout=min(300, remaining(deadline)))
        require(paused["status"]["nodes"][0]["network_active"] is False, "HTTP status hid the paused network")
        inactive = peer_snapshot(controllers[0], deadline)
        require(inactive["network_active"] is False and inactive["transaction_peers"] == 0, "Private partition did not disable native relay")
        pending = consoles[0].request("send", {"address": addresses[1], "amount_sats": 100000, "fee_sats": 5000},
                                      timeout=min(300, remaining(deadline)))["result"]
        require(pending.get("broadcast") is True and type(pending.get("txid")) is str and re.fullmatch("[0-9a-f]{64}", pending["txid"]),
                "Partitioned sender did not retain its one known transaction")
        relay = controllers[1].action("transaction", {"txid": pending["txid"]}, include_status=False)["result"]
        require(relay.get("txid") == pending["txid"] and relay.get("in_mempool") is False, "Partitioned payment was already relayed")
        consoles[0].request("network", {"active": True}, timeout=min(300, remaining(deadline)))
        wait_transaction_peers(controllers, deadline, endpoint=endpoint)
        reannounced = reannounce_known(controllers[0], pending["txid"], deadline)
        confirm_known(pending, 0, deadline)
        event("same_known_transaction_rebroadcast_after_rejoin", **reannounced, elapsed_seconds=time.monotonic() - started)
        adverse = controllers[0].action("adverse")["result"]
        require(adverse["invalid_signature_allowed"] is False and adverse["wrong_network_refused"] is True, "adverse controls failed")
        event("actual_signature_and_wrong_network_controls", **adverse)
        # A live service can be locked through IPC; process liveness is not unlock evidence.
        controllers[0]._request("lock")
        require(consoles[0].request()["wallet"]["locked"] is True, "native IPC lock was hidden by process liveness")
        consoles[0].request("unlock", {"password": passwords[0]})
        require(consoles[0].request()["wallet"]["locked"] is False, "locked service did not reauthenticate")
        baseline = consoles[0].request()
        consoles[0].request("network", {"active": False})
        controllers[0].action("reindex")
        inactive = peer_snapshot(controllers[0], time.monotonic() + 10)
        require(inactive["network_active"] is False and inactive["transaction_peers"] == 0, "Reindex lost durable network-off policy")
        event("durable_network_off_survived_native_reindex")
        consoles[0].request("network", {"active": True})
        connect()
        wait(agreement, "chainstate reindex agreement")
        event("chainstate_reindex_preserved_full_agreement", tip=baseline["nodes"][0]["tip"])
        # Actual Docker restart, plus an interrupted public metadata write.
        consoles[0].request("network", {"active": False})
        orphan = b"INTERRUPTED_PUBLIC_METADATA_ONLY"
        script = ('import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);'
                  'data=sys.stdin.buffer.read(4096);assert os.write(fd,data)==len(data);os.fsync(fd);os.close(fd)')
        controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node/public/public-wallet.tmp", data=orphan)
        peer_orphan = b'{"UNCERTAIN_PUBLIC_PEER_POLICY":'
        script = ('import hashlib,os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);'
                  'fd=os.open(p/"peer-policy.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=4096;'
                  'before=os.read(fd,4097);os.close(fd);'
                  'fd=os.open(p/"peer-policy.tmp",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);'
                  'data=sys.stdin.buffer.read(4096);assert os.write(fd,data)==len(data);os.fsync(fd);os.close(fd);'
                  'print(hashlib.sha256(before).hexdigest())')
        peer_policy_before = controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node", data=peer_orphan).decode().strip()
        require(re.fullmatch("[0-9a-f]{64}", peer_policy_before), "Public peer policy pre-restart digest missing")
        controllers[0].manager.run(["restart", "--time", "2", controllers[0].manager.container])
        wait(lambda: controllers[0]._worker.poll() is not None, "Docker exec disconnect", seconds=30)
        require(consoles[0].request()["wallet"]["locked"] is True, "Docker restart retained an unlocked claim")
        restarted_status = consoles[0].request("start")["status"]
        require(restarted_status["nodes"][0]["network_active"] is False, "HTTP restart status hid conservative network-off")
        inactive = peer_snapshot(controllers[0], time.monotonic() + 10)
        require(inactive["network_active"] is False and inactive["transaction_peers"] == 0, "Restart lost durable network-off policy")
        require(controllers[0].manager._read_json("public-runtime.json")["volume_id"] == original_volumes[0], "Restart changed public volume identity")
        event("durable_network_off_survived_docker_restart", volume_id=original_volumes[0])
        script = ('import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);q=list(p.glob("peer-policy.orphan-*/peer-policy.tmp"));'
                  'assert len(q)==1 and q[0].read_bytes()==sys.stdin.buffer.read(4096) and not (p/"peer-policy.tmp").exists();'
                  'old=(q[0].parent/"peer-policy.json").read_bytes();assert hashlib.sha256(old).hexdigest()==sys.argv[2];'
                  'current=json.loads((p/"peer-policy.json").read_bytes());assert current["network_active"] is False and current["endpoints"]==json.loads(old)["endpoints"];'
                  'print(json.dumps({"preserved":True,"network_active":False,"endpoints":current["endpoints"],"original_sha256":sys.argv[2]}))')
        peer_policy_recovered = json.loads(controllers[0]._invoke("1001:1000", "python3", "-c", script,
                                                                controls.DATA + "/node", peer_policy_before, data=peer_orphan))
        event("peer_policy_orphan_preserved_and_recovered_inactive", **peer_policy_recovered)
        consoles[0].request("unlock", {"password": passwords[0]})
        recovered_after_restart = consoles[0].request("receive")["result"]
        require(recovered_after_restart["index"] >= 2, "Docker restart reused a receive index")
        script = ('import pathlib,sys;p=pathlib.Path(sys.argv[1]);q=list(p.glob("public-wallet.orphan-*/public-wallet.tmp"));'
                  'assert len(q)==1 and q[0].read_bytes()==b"INTERRUPTED_PUBLIC_METADATA_ONLY";print("preserved")')
        require(controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node/public").strip() == b"preserved",
                "interrupted public write diagnostic not preserved")
        consoles[0].request("network", {"active": True})
        connect()
        wait(agreement, "Docker restart agreement")
        event("actual_docker_restart_and_public_orphan_recovery", receive_index=recovered_after_restart["index"])
        # Controlled SIGKILL exercises encrypted durable state, not clean shutdown.
        controllers[0].action("crash")
        require(consoles[0].request()["wallet"]["locked"] is True, "crash restart failed to lock")
        consoles[0].request("unlock", {"password": passwords[0]})
        connect()
        wait(agreement, "SIGKILL restart agreement")
        event("actual_sigkill_restart_preserved_agreement")
        consoles[0].request("lock")
        selected_before = cipher_digest(controllers[0])
        consoles[0].request("recover", {"backup_id": old_backup, "password": passwords[0] + "-wrong"}, succeeds=False)
        require(cipher_digest(controllers[0]) == selected_before, "wrong password changed selected custody")
        backup = controls.validate_backup(controllers[0]._read_json("backups/" + old_backup + ".json"))
        damaged = copy.deepcopy(backup)
        damaged["ciphertext"] = damaged["ciphertext"][:-2] + ("00" if damaged["ciphertext"][-2:] != "00" else "01")
        payload = {key: value for key, value in damaged.items() if key != "sha256"}
        damaged["sha256"] = hashlib.sha256(controls.canonical(payload)).hexdigest()
        damaged_id = uuid.uuid4().hex
        controllers[0]._write_json("backups/" + damaged_id + ".json", damaged)
        consoles[0].request("recover", {"backup_id": damaged_id, "password": passwords[0]}, succeeds=False)
        require(cipher_digest(controllers[0]) == selected_before, "AEAD-corrupt backup changed selected custody")
        event("wrong_password_and_rechecksummed_corrupt_ciphertext_preserved_selected_record")
        # Quarantine both current records; recovery must use independent host floors.
        before = controllers[0].status()["wallet"]
        token = uuid.uuid4().hex
        script = ('import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);os.rename(p/"wallet.dat",p/("wallet.dat.missing-"+sys.argv[2]));'
                  'fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
        controllers[0]._invoke("1000:1000", "python3", "-c", script, controls.DATA + "/signer/current", token)
        script = ('import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);os.rename(p/"public",p/("public.missing-"+sys.argv[2]));'
                  'fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
        controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node", token)
        recovery = consoles[0].request("recover", {"backup_id": old_backup, "password": passwords[0]})["result"]
        require(all(recovery[key] >= before[key] for key in ("next_receive", "next_change")), "old backup lowered independent floors")
        after = consoles[0].request("receive")["result"]
        require(after["index"] >= before["next_receive"], "old backup reused an issued receive index")
        connect()
        wait(agreement, "old-backup missing-record agreement")
        confirmed_send(0, addresses[1])
        event("old_backup_missing_both_records_recovered_and_spent", wallet_id=recovery["wallet_id"], receive_index=after["index"],
              next_receive=recovery["next_receive"], next_change=recovery["next_change"])
        final = [console.request() for console in consoles]
        require([c.manager._read_json("public-runtime.json")["volume_id"] for c in controllers] == original_volumes,
                "Recovery changed an original public volume identity")
        require(final[0]["nodes"][0]["utxo_hash"] == final[1]["nodes"][0]["utxo_hash"], "final full UTXO mismatch")
        report["final"] = {"tip": final[0]["nodes"][0]["tip"], "height": final[0]["nodes"][0]["height"],
                           "utxo_hash": final[0]["nodes"][0]["utxo_hash"], "wallet_ids": [value["wallet"]["wallet_id"] for value in final]}
        report["final"]["volume_ids"] = original_volumes
        for controller in controllers:
            for path in controller.state_dir.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    require(not any(password.encode() in data for password in passwords), "operator secret reached persisted evidence")
        require(not any(password in json.dumps(report) for password in passwords), "operator secret reached report")
        if identity is not None:
            require(checkout_identity(ROOT, expected_head) == identity, "Public app checkout changed during the run")
            report["clean_source_qualified"] = True
        passed = True
    except Exception as error:
        report["error"] = str(error)[:1200]
        raise
    finally:
        errors = []
        for console in consoles:
            try:
                console.close()
            except Exception as error:
                errors.append(str(error)[:300])
        for controller in controllers:
            try:
                controller.close()
                controller.manager.run(["stop", "--time", "5", controller.manager.container], check=False)
                if passed:
                    controller.manager.run(["rm", controller.manager.container])
                    controller.manager.run(["volume", "rm", controller.manager.volume])
            except Exception as error:
                errors.append(str(error)[:300])
        report["cleanup_errors"] = errors
        report["result"] = "PASS" if passed and not errors else "FAIL"
        if descriptor["manifest"].get("qualification_scope") == "DEVELOPMENT_ONLY":
            report["qualification_scope"] = "DEVELOPMENT_ONLY"
        (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        os.chmod(output / "report.json", 0o600)
        passwords.clear()
        require(not errors, "Public app cleanup failed; inspect retained report")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expect-head")
    parser.add_argument("--docker-sudo", action="store_true")
    args = parser.parse_args()
    identity = checkout_identity(ROOT, args.expect_head)
    report = run(controls.source.load_descriptor(args.descriptor), args.output_dir,
                 docker=("sudo", "-n", "docker") if args.docker_sudo else ("docker",), expected_head=identity["head"])
    require(report["result"] == "PASS", "Public app flow failed")
    print(json.dumps({"result": "PASS", "scope": report["scope"], "report": str(args.output_dir / "report.json")}))


if __name__ == "__main__":
    main()
