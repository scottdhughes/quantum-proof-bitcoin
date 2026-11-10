#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Private two-container public-profile app flow. This is not public soak time."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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
import app
import public_app
import public_controller as controls
from run_assembled_ci import checkout_identity


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


class HTTPConsole:
    def __init__(self, controller):
        self.controller = controller
        self.token = secrets.token_urlsafe(32)
        self.server = app.make_server(controller, port=0, token=self.token, action_validator=public_app.validate_action,
                                      assets_dir=CONSOLE / "web-public")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)

    def request(self, action=None, params=None, *, succeeds=True):
        if action is None:
            request = Request(self.url + "/api/status")
        else:
            request = Request(self.url + "/api/action", data=json.dumps({"action": action, "params": params or {},
                              "request_id": uuid.uuid4().hex}).encode(), headers={"Content-Type": "application/json",
                              "Origin": self.url, "X-Console-Token": self.token})
        try:
            with urlopen(request, timeout=300) as response:
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

    def agreement():
        values = [console.request() for console in consoles]
        return all(value["nodes"] for value in values) and len({tuple(value["nodes"][0][key] for key in ("height", "tip", "utxo_hash", "utxo_count")) for value in values}) == 1

    def cipher_digest(controller):
        script = ('import hashlib,os,stat,sys;fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(fd);'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;'
                  'print(hashlib.sha256(os.read(fd,168)).hexdigest());os.close(fd)')
        return controller._invoke("1000:1000", "python3", "-c", script, controls.DATA + "/signer/current/wallet.dat").decode().strip()

    def confirmed_send(source_index, destination, amount=100000):
        sent = consoles[source_index].request("send", {"address": destination, "amount_sats": amount, "fee_sats": 5000})["result"]
        peer = controllers[1 - source_index]
        wait(lambda: peer._request("transaction", {"txid": sent["txid"]})["in_mempool"], "native P2P transaction relay")
        block = consoles[1 - source_index].request("mine")["result"]["blocks"][0]
        wait(agreement, "full tip/UTXO agreement")
        for controller in controllers:
            require(controller._request("transaction", {"txid": sent["txid"], "block_hash": block})["confirmed"] is True,
                    "relayed payment missing from the active block")
        event("confirmed_cross_container_send", txid=sent["txid"], block_hash=block, source=source_index)
        return sent

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
        adverse = controllers[0].action("adverse")["result"]
        require(adverse["invalid_signature_allowed"] is False and adverse["wrong_network_refused"] is True, "adverse controls failed")
        event("actual_signature_and_wrong_network_controls", **adverse)
        # A live service can be locked through IPC; process liveness is not unlock evidence.
        controllers[0]._request("lock")
        require(consoles[0].request()["wallet"]["locked"] is True, "native IPC lock was hidden by process liveness")
        consoles[0].request("unlock", {"password": passwords[0]})
        require(consoles[0].request()["wallet"]["locked"] is False, "locked service did not reauthenticate")
        baseline = consoles[0].request()
        controllers[0].action("reindex")
        connect()
        wait(agreement, "chainstate reindex agreement")
        event("chainstate_reindex_preserved_full_agreement", tip=baseline["nodes"][0]["tip"])
        # Actual Docker restart, plus an interrupted public metadata write.
        orphan = b"INTERRUPTED_PUBLIC_METADATA_ONLY"
        script = ('import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);'
                  'data=sys.stdin.buffer.read(4096);assert os.write(fd,data)==len(data);os.fsync(fd);os.close(fd)')
        controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node/public/public-wallet.tmp", data=orphan)
        controllers[0].manager.run(["restart", "--time", "2", controllers[0].manager.container])
        wait(lambda: controllers[0]._worker.poll() is not None, "Docker exec disconnect", seconds=30)
        require(consoles[0].request()["wallet"]["locked"] is True, "Docker restart retained an unlocked claim")
        consoles[0].request("start")
        consoles[0].request("unlock", {"password": passwords[0]})
        recovered_after_restart = consoles[0].request("receive")["result"]
        require(recovered_after_restart["index"] >= 2, "Docker restart reused a receive index")
        script = ('import pathlib,sys;p=pathlib.Path(sys.argv[1]);q=list(p.glob("public-wallet.orphan-*/public-wallet.tmp"));'
                  'assert len(q)==1 and q[0].read_bytes()==b"INTERRUPTED_PUBLIC_METADATA_ONLY";print("preserved")')
        require(controllers[0]._invoke("1001:1000", "python3", "-c", script, controls.DATA + "/node/public").strip() == b"preserved",
                "interrupted public write diagnostic not preserved")
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
        require(final[0]["nodes"][0]["utxo_hash"] == final[1]["nodes"][0]["utxo_hash"], "final full UTXO mismatch")
        report["final"] = {"tip": final[0]["nodes"][0]["tip"], "height": final[0]["nodes"][0]["height"],
                           "utxo_hash": final[0]["nodes"][0]["utxo_hash"], "wallet_ids": [value["wallet"]["wallet_id"] for value in final]}
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
