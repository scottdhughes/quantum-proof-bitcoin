#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Exercise the real local HTTP controls; native work stays in offline Docker."""

import argparse
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8844")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--leave-running", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", args.url):
        raise ValueError("A local console URL is required")
    if args.output.exists():
        raise ValueError("Choose a new evidence output file")
    with urlopen(args.url, timeout=10) as response:
        html = response.read().decode()
    match = re.search(r'<meta\s+name="console-token"\s+content="([A-Za-z0-9_-]+)"', html)
    if not match:
        raise ValueError("Local console token is unavailable")
    token = match[1]
    events = []

    def action(name, params=None, expected=200):
        request = Request(args.url + "/api/action", data=json.dumps({
            "action": name, "params": params or {}, "request_id": str(uuid.uuid4()),
        }).encode(), headers={"Content-Type": "application/json", "Origin": args.url,
                              "X-Console-Token": token})
        try:
            with urlopen(request, timeout=180) as response:
                code, body = response.status, json.load(response)
        except HTTPError as error:
            with error:
                code, body = error.code, json.load(error)
        events.append({"action": name, "http_status": code, "body": body})
        print(name + ": " + str(code), flush=True)
        if code != expected:
            raise AssertionError(name + " failed: " + str(body))
        if expected == 200:
            if body.get("ok") is not True:
                raise AssertionError(body)
            return body["data"]
        if body.get("ok") is not False:
            raise AssertionError(body)
        return body

    def confirmed(expected):
        deadline = time.monotonic() + 20
        while True:
            with urlopen(args.url + "/api/status", timeout=30) as response:
                body = json.load(response)
            if body.get("ok") is not True:
                raise AssertionError(body)
            status = body["data"]
            wallet = status["wallet"]
            nodes = status["nodes"]
            if wallet["spendable_sats"] == expected and len(nodes) == 2 and nodes[0]["tip"] == nodes[1]["tip"]:
                if nodes[0].get("utxo_hash") != nodes[1].get("utxo_hash") or not nodes[0].get("utxo_hash"):
                    raise AssertionError("Node UTXO inventories disagree")
                return status
            if time.monotonic() >= deadline:
                raise AssertionError("Confirmed balance or two-node agreement: " + str(status))
            time.sleep(0.2)

    result = {"schema": 1, "scope": "REAL_LOCAL_CONSOLE_HTTP_SPEND_OLD_BACKUP_RESTORE", "result": "FAIL"}
    try:
        started = action("start")
        if started["status"]["phase"] != "running":
            raise AssertionError(started)
        first = action("receive")["result"]
        action("fund", {"address": first["address"], "amount_sats": 2000000})
        initial = confirmed(2000000)
        identity = initial["wallet"]["wallet_id"]
        old_backup = action("backup")["result"]
        destination = action("receive")["result"]
        sent = action("send", {"address": destination["address"], "amount_sats": 1000000, "fee_sats": 1000})
        if not sent["result"].get("txid"):
            raise AssertionError("Broadcast transaction ID missing")
        action("mine", {"blocks": 1})
        confirmed(1999000)
        action("stop")
        restarted = action("start")
        if restarted["status"]["wallet"]["wallet_id"] != identity:
            raise AssertionError("Stop/start changed the wallet")
        confirmed(1999000)
        action("recover", {"backup_id": old_backup["id"]})
        recovered = confirmed(1999000)
        if recovered["wallet"]["wallet_id"] != identity:
            raise AssertionError("Recovery changed the wallet")
        fresh = action("receive")["result"]
        if fresh["index"] <= destination["index"]:
            raise AssertionError("Older backup reused an issued address index")
        resent = action("send", {"address": fresh["address"], "amount_sats": 200000, "fee_sats": 1000})
        action("mine", {"blocks": 1})
        final = confirmed(1998000)
        action("lock")
        action("send", {"address": fresh["address"], "amount_sats": 1000}, expected=409)
        action("unlock")
        action("send", {"address": "rq1-invalid-local-address", "amount_sats": 1000}, expected=409)
        action("send", {"address": fresh["address"], "amount_sats": 100000000}, expected=409)
        final = confirmed(1998000)
        result.update(result="PASS", first_txid=sent["result"]["txid"], restored_txid=resent["result"]["txid"],
                      recovered_address_index=fresh["index"], old_backup_id=old_backup["id"], final_status=final)
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        try:
            if not args.leave_running:
                action("stop")
        except Exception as error:
            result["result"] = "FAIL"
            result["cleanup_error"] = str(error)
            raise
        finally:
            result["events"] = events
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, default=str) + "\n")
    print("LOCAL_CONSOLE_END_TO_END_PASS", flush=True)


if __name__ == "__main__":
    main()
