#!/usr/bin/env python3
"""Real Docker Desktop/container/app restart and old-backup spend test.

Runs only the disposable local fixture. Requires permission to restart the
shared Docker engine, and refuses if unrelated containers are running.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid

HERE = Path(__file__).resolve().parent


def main():
    if not __debug__:
        raise ValueError("Optimized Python is not permitted for restart evidence or engine safety checks")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, default=Path.home() / "quantum-proof-bitcoin-evidence/local-console")
    parser.add_argument("--container", default="pqbtc-mldsa-local")
    parser.add_argument("--port", type=int, default=8844)
    parser.add_argument("--allow-docker-restart", action="store_true", required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Choose a new evidence file")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    url = "http://127.0.0.1:" + str(args.port)
    events = []
    report = {"schema": 1, "scope": "REAL_DOCKER_DESKTOP_CONTAINER_APP_RESTART_AND_OLD_BACKUP_SPEND", "result": "FAIL"}
    process = None
    log = args.output.with_suffix(".log").open("x")

    def step(name, **details):
        print(name, flush=True)
        events.append({"step": name, "time": time.time(), **details})

    def command(*values, timeout=240):
        step("command", argv=list(values))
        child = subprocess.Popen(values, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if time.monotonic() >= deadline:
                child.terminate()
                child.wait(timeout=15)
                raise AssertionError("Command timed out: " + str(values))
            time.sleep(0.5)
        if child.returncode:
            raise AssertionError("Command failed; inspect evidence log: " + str(values))

    def read(path):
        with urlopen(url + path, timeout=30) as response:
            return json.load(response)

    def status():
        body = read("/api/status")
        if body.get("ok") is not True:
            raise AssertionError(body)
        return body["data"]

    def wait_ready(running=True):
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("Launcher exited before serving; inspect evidence log")
            try:
                value = status()
                if not running or (value["phase"] == "running" and value["ready"]):
                    return value
            except (OSError, URLError, ValueError):
                pass
            time.sleep(0.5)
        raise AssertionError("Console did not resume")

    def launch():
        step("one_click_launch")
        return subprocess.Popen([str(HERE / "launch.command"), "--no-browser", "--port", str(args.port),
                                 "--container", args.container, "--state-dir", str(args.state_dir)],
                                stdout=log, stderr=subprocess.STDOUT)

    def reopen():
        command(str(HERE / "launch.command"), "--no-browser", "--port", str(args.port),
                "--container", args.container, "--state-dir", str(args.state_dir))
        return wait_ready()

    def action(name, params=None):
        with urlopen(url, timeout=15) as response:
            html = response.read().decode()
        token = re.search(r'name="console-token"\s+content="([A-Za-z0-9_-]+)"', html)[1]
        request = Request(url + "/api/action", data=json.dumps({"action": name, "params": params or {},
                          "request_id": str(uuid.uuid4())}).encode(), headers={"Content-Type": "application/json",
                          "Origin": url, "X-Console-Token": token})
        try:
            with urlopen(request, timeout=240) as response:
                body = json.load(response)
        except HTTPError as error:
            with error:
                body = json.load(error)
            raise AssertionError(name + ": " + str(body)) from error
        if body.get("ok") is not True:
            raise AssertionError(body)
        step(name, result=body["data"]["result"])
        return body["data"]

    def agree(value, expected, identity):
        nodes = value["nodes"]
        assert value["wallet"]["wallet_id"] == identity, "Wallet identity changed"
        assert value["wallet"]["spendable_sats"] == expected, "Confirmed balance changed"
        assert len(nodes) == 2 and nodes[0]["tip"] == nodes[1]["tip"], "Node tips differ"
        assert nodes[0]["utxo_hash"] and nodes[0]["utxo_hash"] == nodes[1]["utxo_hash"], "UTXO inventories differ"
        step("wallet_and_nodes_agree", wallet_id=identity, balance_sats=expected,
             next_receive=value["wallet"]["next_receive"], nodes=nodes)

    def exclusive_engine():
        running = subprocess.check_output(["docker", "ps", "--format", "{{.Names}}"], text=True,encoding="utf8").splitlines()
        assert set(running) <= {args.container, "pqbtc-mldsa-demo-20261109"}, "Unrelated running containers; engine restart refused"

    try:
        try:
            read("/api/identity")
        except URLError:
            pass
        else:
            raise AssertionError("Stop the existing console before this owned-process test")
        process = launch()
        initial = wait_ready()
        identity = initial["wallet"]["wallet_id"]
        balance = initial["wallet"]["spendable_sats"]
        assert balance >= 500000, "Use a disposable funded fixture for this test"
        agree(initial, balance, identity)
        backup = action("backup")["result"]
        destination = action("receive")["result"]
        first = action("send", {"address": destination["address"], "amount_sats": 200000, "fee_sats": 1000})["result"]
        action("mine", {"blocks": 1})
        balance -= 1000
        agree(status(), balance, identity)

        exclusive_engine()
        command("docker", "desktop", "restart", "--timeout", "180")
        agree(reopen(), balance, identity)
        after_engine = action("receive")["result"]
        assert after_engine["index"] > destination["index"], "Engine restart reused an address"
        step("actual_docker_desktop_restart_pass")

        old_id = subprocess.check_output(["docker", "inspect", "--format", "{{.Id}}", args.container], text=True,encoding="utf8").strip()
        command("docker", "kill", args.container)
        command("docker", "rm", args.container)
        agree(reopen(), balance, identity)
        new_id = subprocess.check_output(["docker", "inspect", "--format", "{{.Id}}", args.container], text=True,encoding="utf8").strip()
        assert old_id != new_id, "Container was not recreated"
        after_recreate = action("receive")["result"]
        assert after_recreate["index"] > after_engine["index"], "Container recreation reused an address"
        step("container_loss_and_recreation_pass", old_container_id=old_id, new_container_id=new_id)

        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=90) == 0, "Host app shutdown failed"
        exclusive_engine()
        command("docker", "desktop", "stop", "--timeout", "120")
        process = launch()  # the same one-click path must start Docker itself
        agree(wait_ready(), balance, identity)
        after_cold = action("receive")["result"]
        assert after_cold["index"] > after_recreate["index"], "Cold launch reused an address"
        step("docker_stopped_and_new_app_one_click_resume_pass")

        # Preserve the generated fixture record rather than deleting it. This
        # is a real damaged-current-wallet drill; no record bytes reach macOS.
        action("stop")
        fd = os.open(args.state_dir / "session.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 24 * 1024 * 1024):
                raise ValueError("Fixture session metadata refused")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                selected = json.load(handle)["signer_dir"]
        finally:
            os.close(fd)
        if not re.fullmatch(r"/tmp/mldsa-console-signer-[a-zA-Z0-9_]+", selected):
            raise ValueError("Fixture signer directory refused")
        preserve = ('import os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1])/"wallet/wallet.dat";'
                    's=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and '
                    'stat.S_IMODE(s.st_mode)==0o600 and s.st_size==167;'
                    'q=p.with_name("wallet.dat.restart-test-retained-"+sys.argv[2]);assert not q.exists();'
                    'os.rename(p,q);fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)')
        diagnostic = uuid.uuid4().hex
        command("docker", "exec", "--user", "1000:1000", args.container, "python3", "-c", preserve, selected, diagnostic)
        step("current_record_preserved_and_missing", path=selected + "/wallet/wallet.dat.restart-test-retained-" + diagnostic)
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=90) == 0, "Host app shutdown failed before damaged-wallet launch"
        process = launch()
        damaged = wait_ready(running=False)
        assert damaged["phase"] != "running" and damaged.get("startup_error"), "Missing wallet did not show recovery controls"
        assert damaged["backups"], "Saved recovery points unavailable"
        step("missing_current_record_keeps_recovery_available", startup_error=damaged["startup_error"])

        action("recover", {"backup_id": backup["id"]})
        agree(status(), balance, identity)
        recovered = action("receive")["result"]
        assert recovered["index"] > after_cold["index"], "Older backup reused a later address"
        second = action("send", {"address": recovered["address"], "amount_sats": 100000, "fee_sats": 1000})["result"]
        action("mine", {"blocks": 1})
        balance -= 1000
        final = status()
        agree(final, balance, identity)
        assert first["txid"] != second["txid"]
        action("stop")
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=90) == 0, "Final app shutdown failed"
        report.update(result="PASS", initial_wallet_id=identity, first_txid=first["txid"],
                      restored_txid=second["txid"], final_status=final)
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                report["result"] = "FAIL"
                report["cleanup_error"] = "Owned host app did not finish cleanup"
        log.close()
        report["events"] = events
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("DURABLE_RUNTIME_RESTART_RECOVERY_PASS", flush=True)


if __name__ == "__main__":
    main()
