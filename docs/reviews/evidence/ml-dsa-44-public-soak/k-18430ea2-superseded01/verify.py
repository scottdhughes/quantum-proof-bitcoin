#!/usr/bin/env python3
"""Offline verification of one controlled, incomplete K TEST attempt only."""

import datetime
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import stat
import sys

FILES = {
    ".gitattributes",
    "report.json",
    "declaration.json",
    "evidence-sha256.json",
    "events.jsonl.gz",
    "stop-request.json",
    "coordinator-start.json",
    "classification.json",
    "source.json",
    "readme.md",
    "verify.py",
    "sha256sums",
}
CLASS = "CONTROLLED_SOURCE_SUPERSESSION_NOT_OBSERVED_NETWORK_WORKLOAD_FAILURE"
SOURCE = {
    "head": "18430ea2cfcac66cca0e8612605db47a5c0e935b",
    "tree": "d397b324f83b82017722073c3c53688e0765fb30",
    "driver_sha256": "6668f219acff79a25161d57bf505a3204ab50ef434adbb3487f913f0f913a6d0",
}
CONFIG = "1ae557418c82da103cb656311d58941b9a73a559d7b3be774f8c2f959c35f704"
PRIVATE = {
    "password",
    "passphrase",
    "secret",
    "private_key",
    "seed",
    "ciphertext",
    "operator_input",
    "wallet_seed",
    "mnemonic",
    "authorization",
    "cookie",
    "access_token",
    "refresh_token",
    "rpcpassword",
    "rpcauth",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def parse(raw):
    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )


def public(value):
    if isinstance(value, dict):
        require(not {str(k).lower() for k in value} & PRIVATE, "Private field refused")
        for child in value.values():
            public(child)
    elif isinstance(value, list):
        for child in value:
            public(child)
    elif isinstance(value, str):
        require("-----BEGIN PRIVATE KEY-----" not in value, "Private key text refused")


def verify(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "Unsafe packet root")
    entries = list(root.iterdir())
    require({p.name for p in entries} == FILES, "Exact flat packet membership required")
    for path in entries:
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_size <= 16 * 1024**2,
            "Every entry must be a bounded regular file; symlinks refused",
        )
    raw = {p.name: p.read_bytes() for p in entries}
    sums = {}
    for line in raw["sha256sums"].decode().splitlines():
        value, name = line.split("  ", 1)
        require(
            name in FILES and name != "sha256sums" and name not in sums,
            "Checksum member",
        )
        sums[name] = value
    require(set(sums) == FILES - {"sha256sums"}, "Complete checksum list required")
    require(
        all(digest(raw[name]) == value for name, value in sums.items()),
        "Packet checksum mismatch",
    )
    require(raw[".gitattributes"] == b"* -text\n", "Git byte policy")
    data = {name: parse(value) for name, value in raw.items() if name.endswith(".json")}
    for value in data.values():
        public(value)
    index = data["source.json"]
    require(
        index["schema"] == "PQBTC-K-CONTROLLED-SUPERSESSION-PUBLIC-PACKET-1"
        and index["classification"] == CLASS
        and index["source"] == SOURCE
        and index["public_24h_soak_credit_seconds"] == 0
        and index["production_admitted"] is False,
        "Packet scope",
    )
    indexed = {row["path"]: row for row in index["files"]}
    require(
        len(indexed) == len(index["files"])
        and set(indexed) == FILES - {"source.json", "sha256sums"},
        "Exact provenance membership",
    )
    for name, row in indexed.items():
        require(
            row["bytes"] == len(raw[name]) and row["sha256"] == digest(raw[name]),
            "Provenance hash/size",
        )
        if row["transform"] == "NONE":
            require(
                row["origin_bytes"] == len(raw[name])
                and row["origin_sha256"] == digest(raw[name]),
                "Original byte preservation",
            )
    report, declaration = data["report.json"], data["declaration.json"]
    inventory, request = data["evidence-sha256.json"], data["stop-request.json"]
    coordinator, audit = data["coordinator-start.json"], data["classification.json"]
    require(
        report["result"] == "FAIL"
        and report["error_class"] == "KeyboardInterrupt"
        and report["error"] == ""
        and report["cleanup_ok"] is True,
        "Unmodified raw FAIL/interrupt outcome",
    )
    require(
        report["mode"] == declaration["mode"] == coordinator["mode"] == "soak"
        and declaration["duration_seconds"] == 86400
        and report["host_runner_source"] == declaration["host_runner_source"] == SOURCE
        and report["configuration_sha256"]
        == declaration["configuration_sha256"]
        == coordinator["config_sha256"]
        == CONFIG,
        "Exact intended mode/source/configuration",
    )
    require(
        request["classification"] == audit["classification"] == CLASS
        and request["signal"] == "SIGINT"
        and request["signal_count_requested"] == 1
        and request["exact_argv_verified"] is True
        and request["coordinator_pid"] == coordinator["pid"] == 10537
        and request["partial_elapsed_credit_seconds"]
        == audit["public_24h_soak_credit_seconds"]
        == 0,
        "Controlled source supersession and zero credit",
    )
    require(
        audit["raw_result_unchanged"] == "FAIL"
        and audit["raw_error_class"] == "KeyboardInterrupt"
        and audit["full_clock_completed"] is False
        and audit["all7faults_completed"] is False
        and audit["final_postclock_recovery_and_spend_claimed"] is False,
        "No partial PASS promotion",
    )
    require(
        set(inventory) == {"events.jsonl", "report.json", "declaration.json"},
        "Original inventory allowlist",
    )
    require(
        inventory["report.json"] == digest(raw["report.json"])
        and inventory["declaration.json"]
        == digest(raw["declaration.json"])
        == report["declaration_sha256"],
        "Original report/declaration hashes",
    )
    compressed = raw["events.jsonl.gz"]
    require(
        compressed[:4] == b"\x1f\x8b\x08\x00"
        and compressed[4:8] == b"\0" * 4
        and compressed[8] == 2,
        "Deterministic gzip header",
    )
    expected = indexed["events.jsonl.gz"]
    require(
        type(expected["origin_bytes"]) is int
        and 0 < expected["origin_bytes"] <= 16 * 1024**2,
        "Original event bound",
    )
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        original = stream.read(expected["origin_bytes"] + 1)
        require(
            len(original) == expected["origin_bytes"] and not stream.read(1),
            "Bounded lossless gzip",
        )
    require(
        digest(original) == expected["origin_sha256"] == inventory["events.jsonl"],
        "Original event bytes",
    )
    events, prior, last_mono, bounds = [], "0" * 64, -1, {}
    for line in original.splitlines(keepends=True):
        require(
            line.endswith(b"\n") and len(line) <= 2 * 1024**2, "Complete bounded event"
        )
        event = parse(line)
        public(event)
        require(
            set(event)
            == {
                "sequence",
                "utc",
                "monotonic_ns",
                "kind",
                "data",
                "previous_sha256",
                "sha256",
            },
            "Event shape",
        )
        require(
            type(event["sequence"]) is int
            and event["sequence"] == len(events)
            and event["previous_sha256"] == prior
            and type(event["monotonic_ns"]) is int
            and event["monotonic_ns"] >= last_mono
            and digest(canonical({k: v for k, v in event.items() if k != "sha256"}))
            == event["sha256"],
            "Event chain/sequence/clock",
        )
        stamp = datetime.datetime.fromisoformat(event["utc"])
        require(
            stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0,
            "UTC event time",
        )
        if event["kind"] in ("public_clock_started", "public_clock_completed"):
            require(event["kind"] not in bounds, "Duplicate public clock")
            bounds[event["kind"]] = {
                k: event[k] for k in ("utc", "monotonic_ns", "data")
            }
        prior, last_mono = event["sha256"], event["monotonic_ns"]
        events.append(event)
    chain = {"count": len(events), "last_sha256": prior, "clock_boundaries": bounds}
    require(
        chain == report["event_chain"] == audit["event_chain"] and len(events) == 16164,
        "Complete original hash-chain binding",
    )
    require(
        set(bounds) == {"public_clock_started"}
        and bounds["public_clock_started"]["data"]["duration_seconds"] == 86400,
        "Only intended full-day clock start; no completion",
    )
    failure = [e for e in events if e["kind"] == "attempt_failed"]
    require(
        len(failure) == 1
        and failure[0]["data"] == {"error_class": "KeyboardInterrupt", "detail": ""},
        "Only controlled interrupt failure recorded",
    )
    require(
        datetime.datetime.fromisoformat(request["utc"])
        <= datetime.datetime.fromisoformat(failure[0]["utc"]),
        "Stop request must precede interrupt event",
    )
    start = bounds["public_clock_started"]
    mono = (failure[0]["monotonic_ns"] - start["monotonic_ns"]) / 1e9
    wall = (
        datetime.datetime.fromisoformat(failure[0]["utc"])
        - datetime.datetime.fromisoformat(start["utc"])
    ).total_seconds()
    require(
        0 < mono < 86400
        and 0 < wall < 86400
        and audit["partial_clock_to_interrupt"]
        == {"monotonic_seconds": mono, "wall_seconds": wall},
        "Partial clocks only",
    )
    slots = [e["data"] for e in events if e["kind"] == "normal_slot"]
    require(
        len(slots) == 143
        and [s["slot"] for s in slots] == list(range(143))
        and all(
            s["success"] is True
            and 0 <= s["settle_seconds"] <= 60
            and s["slot"] * 60 <= s["payment_started_elapsed"] < (s["slot"] + 1) * 60
            for s in slots
        ),
        "Recorded partial normal workload",
    )
    payments = [e["data"] for e in events if e["kind"] == "confirmed_payment"]
    require(
        len(payments) == len({p["txid"] for p in payments}) == 146,
        "Recorded unique payments",
    )
    faults = [e["data"] for e in events if e["kind"] == "fault_completed"]
    require(
        len(faults) == 1
        and faults[0]["name"] == "crash"
        and faults[0]["result"] == "PASS"
        and 7200 <= faults[0]["started_elapsed"] <= 7260
        and 0 <= faults[0]["finished_elapsed"] - faults[0]["started_elapsed"] <= 300
        and faults[0]["recovery_payment"] in payments,
        "Only completed crash phase",
    )
    require(
        audit["normal_slots"]["outcomes"] == audit["normal_slots"]["successful"] == 143
        and audit["normal_slots"]["missed"] == 0
        and audit["confirmed_unique_payments"] == 146
        and audit["completed_faults"] == faults,
        "Derived partial summary",
    )
    latencies = sorted(s["settle_seconds"] for s in slots)
    require(
        audit["normal_slots"]["p95_settle_seconds"]
        == latencies[math.ceil(0.95 * 143) - 1],
        "Partial settlement summary",
    )
    require(
        events[-2]["kind"] == "cleanup"
        and events[-2]["data"]["errors"] == []
        and events[-2]["data"]["results"] == report["cleanup"]
        and events[-1]["kind"] == "attempt_completed"
        and events[-1]["data"] == {"result": "FAIL", "cleanup_ok": True},
        "Owned cleanup and raw terminal FAIL",
    )
    for host in ("mac", "research"):
        row = report["cleanup"][host]
        stop = row["backend_stop_proofs"]["after_exit"]
        require(
            row["exit_code"] == 0
            and row["stderr_bytes"] == 0
            and stop["backend_stopped"] is True
            and stop["state"] == "STOPPED",
            "Owned backend stopped",
        )
    return {
        "result": "VERIFIED_CONTROLLED_PARTIAL_SOURCE_SUPERSESSION",
        "raw_result": "FAIL",
        "classification": CLASS,
        "events": 16164,
        "normal_successes": 143,
        "missed_slots": 0,
        "confirmed_unique_payments": 146,
        "completed_faults": 1,
        "cleanup_ok": True,
        "partial_monotonic_seconds": mono,
        "partial_wall_seconds": wall,
        "public_24h_soak_credit_seconds": 0,
        "production_admitted": False,
    }


if __name__ == "__main__":
    try:
        require(
            __debug__ and len(sys.argv) <= 2,
            "Use ordinary Python3: verify.py [packet-root]",
        )
        root = (
            Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent
        )
        print(json.dumps(verify(root), sort_keys=True))
    except Exception as error:
        print("VERIFICATION_FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
