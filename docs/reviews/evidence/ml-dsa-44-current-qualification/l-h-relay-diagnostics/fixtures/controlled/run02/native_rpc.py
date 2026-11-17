#!/usr/bin/env python3
"""Contained RPC adapter: return only explicitly selected public evidence."""
import hashlib
import json
from pathlib import Path
import re
import sys


def check(value):
    if not value:
        raise ValueError("NATIVE_RPC_REFUSED")


def dispatch(node, value):
    check(type(value) is dict and set(value) <= {"op", "endpoint", "id", "txid", "timeout"})
    timeout = value.get("timeout")
    check(type(timeout) in (int, float) and 0 < timeout <= 3)
    rpc = node.rpc(timeout=timeout)
    op = value.get("op")
    if op == "peers":
        rows = rpc.getpeerinfo()
        check(type(rows) is list and len(rows) <= 2)
        result = []
        for row in rows:
            check(type(row["id"]) is int and type(row["addr"]) is str and len(row["addr"]) <= 64)
            result.append({"id": row["id"], "addr": row["addr"], "version": row.get("version", 0),
                           "relaytxes": row.get("relaytxes", False), "transport": row.get("transport_protocol_type"),
                           "ping_sent": row.get("bytessent_per_msg", {}).get("ping", 0),
                           "pong_received": row.get("bytesrecv_per_msg", {}).get("pong", 0),
                           "ping_pending": "pingwait" in row})
        return {"peers": result}
    if op == "connect":
        check(type(value.get("endpoint")) is str and re.fullmatch(r"[0-9.]+:23834", value["endpoint"]))
        rpc.addnode(value["endpoint"], "onetry", False)
        return {"requested": True, "v2transport": False}
    if op == "disconnect":
        rows = rpc.getpeerinfo()
        check(len(rows) == 1 and rows[0]["id"] == value.get("id") and rows[0]["addr"] == value.get("endpoint"))
        rpc.disconnectnode(nodeid=value["id"])
        return {"requested": True, "old_id": value["id"]}
    if op == "ping":
        rpc.ping()
        return {"requested": True}
    if op == "txmeta":
        txid = value.get("txid")
        check(type(txid) is str and re.fullmatch("[0-9a-f]{64}", txid))
        raw = rpc.getrawtransaction(txid, False)
        check(type(raw) is str and len(raw) <= 2000000 and len(raw) % 2 == 0 and re.fullmatch("[0-9a-f]+", raw))
        decoded = rpc.decoderawtransaction(raw)
        check(decoded.get("txid") == txid and re.fullmatch("[0-9a-f]{64}", decoded.get("hash", "")))
        return {"txid": txid, "wtxid": decoded["hash"], "raw_transaction_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
    raise ValueError("NATIVE_RPC_OPERATION")


if __name__ == "__main__":
    try:
        check(sys.platform.startswith("linux") and __import__("os").geteuid() == 1001)
        sys.path[:0] = [sys.argv[1] + "/contrib/ml-dsa-console", sys.argv[1] + "/test/functional"]
        from public_runtime import PublicNode
        from test_framework.authproxy import AuthServiceProxy
        raw = sys.stdin.buffer.read(4097)
        check(len(raw) <= 4096)
        result = dispatch(PublicNode("", Path(sys.argv[2]), AuthServiceProxy), json.loads(raw))
        print(json.dumps({"ok": True, **result}, sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"NATIVE_RPC_FAILED"}', flush=True)
        raise SystemExit(1)
