#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license; https://opensource.org/license/mit/
"""Offline selected-public L preflight verification; no native/network operations."""
import sys

if not __debug__:
    raise SystemExit("Optimized Python refused")
if not sys.flags.isolated:
    raise SystemExit("Isolated Python (-I) is required")

import ast
import builtins
import datetime
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

SOURCE = {"head": "7223772e76d2d0a0bb7fd1d35e0e16fba61918fd",
          "tree": "33b36275b1da7f7fbc27fae00d519206b0f7c16f",
          "driver_sha256": "6668f219acff79a25161d57bf505a3204ab50ef434adbb3487f913f0f913a6d0"}
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
CONFIGS = {"l01": "524d1fabc4f4766441c3b599d3447ea3854abd6089f2c02d6d592506cb40ca9c",
           "l02": "a5dc036b4b58d07571b05211579262c2a3b93aa354a80efc5c672a0f34aa8ab1"}
EXPECTED_COUNTS = {"l01": (2429, 17, 10, 0, 5), "l02": (2663, 22, 12, 3, 7)}
MEMBERS = {
    ".gitattributes", "README.md", "SOURCE.json", "verify.py", "SHA256SUMS", "verification-controls.json",
    "frozen-l-public-soak-driver.py", "closeout/l02-backend-observer-result.json",
    "l01/declaration.json", "l01/report.json", "l01/evidence-sha256.json",
    "l01/events.jsonl.gz", "l01/independent-review.json",
    "l02/declaration.json", "l02/report.json", "l02/evidence-sha256.json",
    "l02/events.jsonl.gz", "l02/independent-review.json", "l02/root-terminal-review.json",
}
PRIVATE = {"password", "passphrase", "secret", "ciphertext", "operator_input", "private_key", "seed",
           "wallet_seed", "mnemonic", "rpcpassword", "rpcauth", "access_token", "refresh_token",
           "authorization", "cookie"}
LIMIT = 8 * 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def public(value):
    if type(value) is dict:
        need(not PRIVATE.intersection(key.lower() for key in value), "Private field refused")
        for key, item in value.items():
            if "credit" in key.lower() and type(item) in (int, float, bool):
                need(item == 0, "Positive credit refused")
            public(item)
    elif type(value) is list:
        for item in value:
            public(item)
    elif type(value) is float:
        need(math.isfinite(value), "Nonfinite JSON")
    elif type(value) is str:
        need(not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
                           r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
                           r"(?i:Authorization\s*:\s*(?:Bearer|token)\s+\S+)|"
                           r"https://[^\s<>]*(?:[?&](?:sig|signature|token|X-Amz-Signature|X-Amz-Credential|se)=)",
                           value), "Credential or signed URL refused")


def member_parts(name):
    path = PurePosixPath(name)
    need(type(name) is str and not path.is_absolute() and path.parts and
         path.as_posix() == name and not {".", ".."}.intersection(path.parts) and "\\" not in name,
         "Unsafe member name")
    return path.parts


def open_root(value):
    need(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
         "POSIX no-follow directory APIs required")
    path = Path(value)
    need(".." not in path.parts, "Parent traversal refused")
    if not path.is_absolute():
        path = Path.cwd() / path
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def tree_members(fd, prefix=""):
    files, directories = set(), set()
    for entry in os.scandir(fd):
        name = prefix + entry.name
        member_parts(name)
        state = entry.stat(follow_symlinks=False)
        need(not stat.S_ISLNK(state.st_mode), "Symlink component refused")
        if stat.S_ISDIR(state.st_mode):
            directories.add(name)
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                more, dirs = tree_members(child, name + "/")
            finally:
                os.close(child)
            files |= more
            directories |= dirs
        else:
            need(stat.S_ISREG(state.st_mode) and state.st_nlink == 1, "Nonregular/hardlink member refused")
            files.add(name)
    return files, directories


def read_member(root_fd, name):
    parts = member_parts(name)
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            start = os.fstat(child)
            need(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size <= LIMIT,
                 "Unsafe or oversized packet member")
            chunks, size = [], 0
            while True:
                part = os.read(child, min(65536, LIMIT + 1 - size))
                if not part:
                    break
                size += len(part)
                need(size <= LIMIT, "Packet member size exceeded")
                chunks.append(part)
            end = os.fstat(child)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            need(tuple(getattr(start, key) for key in fields) == tuple(getattr(end, key) for key in fields),
                 "Packet member changed while reading")
            need(size == start.st_size, "Packet member partial read")
            return b"".join(chunks)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def pure_validators(raw):
    need(sha(raw) == SOURCE["driver_sha256"], "Pinned L driver bytes differ")
    constants = {"PRIVATE_FIELDS", "FAULTS"}
    functions = {"require", "canonical", "pairs", "parsed", "finite", "hex64", "public_value",
                 "duration_for", "require_elapsed", "require_event_duration", "validate_phases",
                 "validate_outcome"}
    classes = {"SlotLedger"}
    selected, found = [], set()
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in constants:
                selected.append(node)
                found.add(name)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
            found.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name in classes:
            selected.append(node)
            found.add(node.name)
    need(found == constants | functions | classes, "Pure validator selection differs")
    allowed = ("__build_class__", "ValueError", "all", "any", "bool", "dict", "enumerate", "float",
               "int", "len", "list", "range", "set", "sorted", "str", "type", "zip")
    namespace = {"__builtins__": {name: getattr(builtins, name) for name in allowed},
                 "__name__": "pinned_pure_l_validators", "json": json, "math": math, "re": re,
                 "datetime": datetime.datetime}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<pinned-pure-L-validators>", "exec"), namespace)
    return namespace


def event_chain(raw):
    events, clocks, previous, last = [], {}, "0" * 64, -1
    for sequence, line in enumerate(raw.splitlines(keepends=True)):
        need(line.endswith(b"\n") and len(line) <= 2 * 1024 * 1024, "Truncated/oversized event")
        value = parsed(line)
        public(value)
        need(set(value) == {"sequence", "utc", "monotonic_ns", "kind", "data",
                            "previous_sha256", "sha256"}, "Event field set differs")
        unsigned = {key: item for key, item in value.items() if key != "sha256"}
        need(type(value["sequence"]) is int and value["sequence"] == sequence and
             value["previous_sha256"] == previous and type(value["monotonic_ns"]) is int and
             value["monotonic_ns"] >= last and sha(canonical(unsigned)) == value["sha256"],
             "Event hash/sequence/clock differs")
        stamp = datetime.datetime.fromisoformat(value["utc"])
        need(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, "Event UTC differs")
        if value["kind"] in ("public_clock_started", "public_clock_completed"):
            need(value["kind"] not in clocks, "Duplicate public clock boundary")
            clocks[value["kind"]] = {key: value[key] for key in ("utc", "monotonic_ns", "data")}
        previous, last = value["sha256"], value["monotonic_ns"]
        events.append(value)
    return events, {"count": len(events), "last_sha256": previous, "clock_boundaries": clocks}


def unwrap(value):
    return value["result"] if "status" in value and type(value.get("result")) is dict else value


def native_payments(events, payments):
    prior = -1
    for payment in payments:
        proof = payment["data"]
        need(re.fullmatch("[0-9a-f]{64}", proof["txid"]) and
             re.fullmatch("[0-9a-f]{64}", proof["block_hash"]) and
             {proof["sender"], proof["receiver"]} == {"mac", "research"} and
             proof["recipient_in_mempool"] is True and
             0 <= proof["recipient_relay_seconds"] <= proof["settle_seconds"] <= 60,
             "Native payment relay/identity differs")
        sends, relays, mines, confirmations = [], [], [], {}
        for event in events[prior + 1:payment["sequence"]]:
            if event["kind"] != "action":
                continue
            data = event["data"]
            result = unwrap(data["result"])
            if data["action"] == "send":
                need(data["host"] == proof["sender"] and result["txid"] == proof["txid"] and
                     result["broadcast"] is True, "Send identity differs")
                sends.append(event["sequence"])
            elif data["action"] == "transaction" and result.get("txid") == proof["txid"]:
                if data["host"] == proof["receiver"] and result.get("in_mempool") is True:
                    relays.append(event["sequence"])
                if result.get("confirmed") is True and result.get("block_hash") == proof["block_hash"]:
                    need(type(result.get("confirmations")) is int and result["confirmations"] >= 1,
                         "Native confirmation count differs")
                    confirmations[data["host"]] = event["sequence"]
            elif data["action"] == "mine" and proof["block_hash"] in result.get("blocks", []):
                need(data["host"] == proof["sender"], "Mine sender differs")
                mines.append(event["sequence"])
            elif data["action"] == "rebroadcast":
                need(result.get("reissued_payment") is False and result.get("known_in_mempool") is True,
                     "Rebroadcast issuance boundary differs")
        need(len(sends) == len(mines) == 1 and relays and set(confirmations) == {"mac", "research"} and
             sends[0] < relays[0] < mines[0] < min(confirmations.values()),
             "Native send/relay/mine/both-host confirmation order differs")
        prior = payment["sequence"]


def verify_attempt(label, raw, manifest, pure):
    prefix = label + "/"
    report = parsed(raw[prefix + "report.json"])
    declaration = parsed(raw[prefix + "declaration.json"])
    inventory = parsed(raw[prefix + "evidence-sha256.json"])
    review = parsed(raw[prefix + "independent-review.json"])
    expected_result = "FAIL" if label == "l01" else "PREFLIGHT_PASS"
    need(report["host_runner_source"] == declaration["host_runner_source"] == SOURCE,
         "Pinned attempt source differs")
    need(report["configuration_sha256"] == declaration["configuration_sha256"] == CONFIGS[label],
         "Pinned attempt configuration differs")
    need(report["mode"] == declaration["mode"] == "preflight" and report["result"] == expected_result and
         declaration["duration_seconds"] == 900 and report["scope"] == declaration["scope"] == SCOPE and
         report["production_admitted"] is declaration["production_admitted"] is False and
         declaration["profile_sha256"] == PROFILE, "Attempt result/scope/profile differs")
    compressed = raw[prefix + "events.jsonl.gz"]
    need(compressed[:4] == b"\x1f\x8b\x08\x00" and compressed[4:8] == b"\0" * 4 and compressed[8] == 2,
         "Deterministic gzip header differs")
    expected = manifest["attempts"][label]["original_events"]
    need(type(expected["bytes"]) is int and 0 < expected["bytes"] <= LIMIT, "Event size bound differs")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as handle:
        event_bytes = handle.read(expected["bytes"] + 1)
        need(len(event_bytes) == expected["bytes"] and not handle.read(1), "Expanded events size differs")
    need(sha(event_bytes) == expected["sha256"], "Expanded events provenance differs")
    need(set(inventory) == {"events.jsonl", "report.json", "declaration.json"}, "Original inventory members differ")
    originals = {"events.jsonl": event_bytes, "report.json": raw[prefix + "report.json"],
                 "declaration.json": raw[prefix + "declaration.json"]}
    need(inventory == {name: sha(value) for name, value in originals.items()} and
         report["declaration_sha256"] == inventory["declaration.json"], "Original inventory/declaration hashes differ")
    events, chain = event_chain(event_bytes)
    need(chain == report["event_chain"] == review["event_chain"], "Original report/review chain differs")
    phases = [v["data"] for v in events if v["kind"] == "fault_completed"]
    slots = [v["data"] for v in events if v["kind"] == "normal_slot"]
    payments = [v for v in events if v["kind"] == "confirmed_payment"]
    success = sum(v["success"] is True for v in slots)
    misses = sum(v["success"] is False for v in slots)
    need((len(events), len(payments), success, misses, len(phases)) == EXPECTED_COUNTS[label],
         "Exact recorded attempt counts differ")
    summary = manifest["attempts"][label]
    need(summary["result"] == expected_result and summary["mode"] == "preflight" and
         summary["configuration_sha256"] == CONFIGS[label] and
         (summary["events"], summary["confirmed_payments"], summary["normal_success"],
          summary["fault_misses"], summary["completed_phases"]) == EXPECTED_COUNTS[label] and
         summary["completed_900_second_clock"] is (label == "l02") and
         summary["public_24_hour_credit_seconds"] == 0, "Manifest attempt outcome/counts differ")
    need(len({v["data"]["txid"] for v in payments}) == len(payments), "Payment transaction reused")
    native_payments(events, payments)
    for phase in phases:
        need(sum(v["data"] == phase["recovery_payment"] for v in payments) == 1,
             "Phase recovery payment differs")
    clock = None
    if label == "l02":
        clock = pure["require_event_duration"](chain, "preflight")
        need(clock == {"monotonic_seconds": 900.172816125, "wall_seconds": 900.177095},
             "Pinned actual dual clocks differ")
        need(summary["event_clock_elapsed"] == clock, "Manifest dual clocks differ")
        need(report["slots"] == slots and report["phases"] == phases and
             report["event_clock_elapsed"] == clock, "Successful workload report differs")
        ledger = pure["SlotLedger"]("preflight")
        ledger.rows = slots
        outcome = pure["validate_outcome"](
            "preflight", report["elapsed"]["monotonic_seconds"], report["elapsed"]["wall_seconds"],
            ledger, phases, final_recovered_spend=report["final_recovered_spend"],
            cleanup_ok=report["cleanup_ok"], public_start=report["public_start"], public_end=report["public_end"])
        need(all(report[key] == value for key, value in outcome.items()), "Recomputed outcome differs")
        need(not any(v["kind"] == "attempt_failed" for v in events), "Passed attempt contains failure")
    else:
        need(set(chain["clock_boundaries"]) == {"public_clock_started"}, "Failed clock incorrectly completed")
        need([v["name"] for v in phases] == [name for name, _ in pure["FAULTS"][:5]] and
             all(v["result"] == "PASS" for v in phases), "Failed-attempt completed phase prefix differs")
        failures = [v for v in events if v["kind"] == "attempt_failed"]
        need(len(failures) == 1 and failures[0]["data"]["detail"] == report["error"] ==
             "Owned public action failed: upgrade (ConsoleError)", "Original failure detail differs")
        need(events[2425]["kind"] == "action_dispatched" and events[2425]["data"] ==
             {"host": "research", "action": "upgrade"}, "Original failure host/action differs")
    floors, addresses, paths, backups, quarantine, recoveries = {}, set(), set(), {}, {}, []
    pending = None
    for event in events:
        if event["kind"] == "action_dispatched":
            need(pending is None, "Overlapping action dispatch")
            pending = event
        elif event["kind"] == "attempt_failed":
            pending = None
        elif event["kind"] == "action":
            data = event["data"]
            need(pending is not None and all(data[key] == pending["data"][key] for key in ("host", "action")),
                 "Action response differs from dispatch")
            pending = None
            host, action, value = data["host"], data["action"], data["result"]
            before = dict(floors[host]) if host in floors else None
            status_value = value if action == "status" else value.get("status")
            if status_value and status_value.get("wallet", {}).get("wallet_id"):
                wallet = status_value["wallet"]
                point = {key: wallet[key] for key in ("wallet_id", "next_receive", "next_change")}
                need(all(type(point[key]) is int and 0 <= point[key] < 2**31 for key in ("next_receive", "next_change")),
                     "Public floor type/range differs")
                if before:
                    need(point["wallet_id"] == before["wallet_id"] and
                         all(point[key] >= before[key] for key in ("next_receive", "next_change")),
                         "Public wallet identity/floor rollback")
                need(all(other == host or point["wallet_id"] != observed["wallet_id"]
                         for other, observed in floors.items()), "Cloned two-host custody")
                floors[host] = point
            result = unwrap(value)
            if action == "backup":
                need(host not in backups, "Unexpected later backup")
                backups[host] = dict(floors[host])
            elif action == "receive":
                key = (host, result["branch"], result["index"])
                need(result["branch"] == 0 and before["next_receive"] <= result["index"] < floors[host]["next_receive"] and
                     key not in paths and result["address"] not in addresses, "Receive address/path reused")
                paths.add(key)
                addresses.add(result["address"])
            elif action == "quarantine_record":
                need(result["selected_record_missing"] is True and result["independent_journal_preserved"] is True and
                     all(result[key] > backups[host][key] for key in ("next_receive", "next_change")),
                     "Public selected-record/retained-journal boundary differs")
                quarantine[host] = {"sequence": event["sequence"], "result": result}
            elif action == "recover":
                prior = quarantine[host]["result"]
                need(result["chain_snapshot_restored"] is False and result["wallet_id"] == prior["wallet_id"] and
                     all(result[key] >= prior[key] for key in ("next_receive", "next_change")),
                     "Old selected-record restoration differs")
                recoveries.append({"host": host, "quarantine_sequence": quarantine[host]["sequence"],
                                   "recovery_sequence": event["sequence"]})
    need(len(recoveries) == (1 if label == "l01" else 2), "Public recovery count differs")
    if label == "l02":
        end = next(v["sequence"] for v in events if v["kind"] == "public_clock_completed")
        final = [v for v in payments if v["sequence"] > end]
        recovered = next(v for v in recoveries if v["host"] == "research")
        need(len(final) == 1 and final[0]["data"]["sender"] == "research" and
             end < recovered["quarantine_sequence"] < recovered["recovery_sequence"] < final[0]["sequence"],
             "Final clock/recovery/native spend order differs")
    need(report["cleanup_ok"] is True, "Reported cleanup failed")
    for host in ("mac", "research"):
        cleanup = report["cleanup"][host]
        stop = cleanup["backend_stop_proofs"]["after_exit"]
        need(cleanup["exit_code"] == 0 and stop["backend_stopped"] is True and
             stop["state"] == "STOPPED" and stop["last_id"] in stop["stopped_ids"], "Reported STOPPED proof differs")
    need(review["source"] == SOURCE and review["attempt_result"] == expected_result and
         review["evidence_integrity_result"] == "PASS" and review["confirmed_payments"] == len(payments),
         "Independent review result/source differs")
    for name, value in originals.items():
        need(review["raw_member_identities"][name] == {"bytes": len(value), "sha256": sha(value)},
             "Independent original byte hash differs")
    need(review["raw_member_identities"]["evidence-sha256.json"] ==
         {"bytes": len(raw[prefix + "evidence-sha256.json"]), "sha256": sha(raw[prefix + "evidence-sha256.json"])},
         "Independent inventory hash differs")
    return {"result": expected_result, "events": len(events), "payments": len(payments),
            "normal_success": success, "fault_misses": misses, "phases": len(phases),
            "dual_clocks": clock, "last_sha256": chain["last_sha256"]}


def verify(root):
    fd = open_root(root)
    try:
        files, dirs = tree_members(fd)
        expected_dirs = {str(PurePosixPath(name).parent) for name in MEMBERS if "/" in name}
        need(files == MEMBERS and dirs == expected_dirs, "Exact public packet membership differs")
        sums = read_member(fd, "SHA256SUMS").decode("ascii")
        expected = {}
        for line in sums.splitlines():
            digest, name = line.split("  ", 1)
            member_parts(name)
            need(re.fullmatch("[0-9a-f]{64}", digest) and name not in expected, "Checksum line differs")
            expected[name] = digest
        need(set(expected) == MEMBERS - {"SHA256SUMS"}, "Checksum scope differs")
        raw = {name: read_member(fd, name) for name in expected}
        need(all(sha(value) == expected[name] for name, value in raw.items()), "Packet checksum mismatch")
        need(raw[".gitattributes"] == b"* -text\n", "Byte preservation attributes differ")
        source = parsed(raw["SOURCE.json"])
        for name, value in raw.items():
            if name.endswith(".json"):
                public(parsed(value))
        need(source["source_subject"] == SOURCE and source["scope"] == SCOPE and
             source["original_failure_status"] == "UNKNOWN_UNREPRODUCED" and
             source["original_failure_proven_fixed"] is False and
             source["public_both_records_missing_recovery_claimed"] is False and
             source["independent_public_floor_journal_retained"] is True and
             source["production_admitted"] is False and source["public_24_hour_credit_seconds"] == 0 and
             source["resumption_allowed"] is False,
             "Manifest source/failure/acceptance scope differs")
        rows = {row["path"]: row for row in source["files"]}
        need(len(rows) == len(source["files"]) and set(rows) == set(raw) - {"SOURCE.json"},
             "Manifest exact file closure differs")
        for name, row in rows.items():
            need(row["bytes"] == len(raw[name]) and row["sha256"] == sha(raw[name]), "Manifest payload hash differs")
            provenance = row["provenance"]
            if provenance["transform"] == "NONE":
                need(provenance["original_bytes"] == len(raw[name]) and
                     provenance["original_sha256"] == sha(raw[name]), "Exact-copy provenance differs")
            else:
                need(provenance["transform"] in {"DERIVED", "DETERMINISTIC_LOSSLESS_GZIP_MTIME0_LEVEL9"},
                     "Unknown transformation")
        pure = pure_validators(raw["frozen-l-public-soak-driver.py"])
        results = {label: verify_attempt(label, raw, source, pure) for label in ("l01", "l02")}
        root_review = parsed(raw["l02/root-terminal-review.json"])
        need(root_review["result"] == "PREFLIGHT_PASS" and root_review["source"] == SOURCE and
             root_review["unique_confirmed_payments"] == 22 and root_review["public_24h_credit_seconds"] == 0 and
             root_review["complete_faults"] == 7 and root_review["final_old_record_recovery_spend"] is True and
             root_review["independent_public_floor_journal_retained"] is True and
             root_review["event_clock_elapsed"] == results["l02"]["dual_clocks"] and
             root_review["previous_failure_preserved"] is True and
             root_review["previous_failure_root_cause_reproduced_or_fixed"] is False and
             root_review["report_sha256"] == sha(raw["l02/report.json"]) and
             root_review["inventory_sha256"] == sha(raw["l02/evidence-sha256.json"]),
             "Root terminal receipt binding differs")
        backend = parsed(raw["closeout/l02-backend-observer-result.json"])
        need(backend["source"]["head"] == SOURCE["head"] and backend["source"]["tree"] == SOURCE["tree"] and
             backend["source"]["status"] == "" and backend["immutable_public_report_sha256"] == sha(raw["l02/report.json"]) and
             backend["immutable_public_result"] == "PREFLIGHT_PASS" and backend["public_soak_credit_seconds"] == 0 and
             backend["agent235790_original_gone"] is True and backend["observer237941_original_gone"] is True and
             backend["observer_unit"]["ActiveState"] == "inactive" and
             all(not engine["running"] for engine in backend["engines"].values()) and
             backend["aggregate_before"]["cpu.max"] == backend["aggregate_after"]["cpu.max"] == "200000 100000",
             "Selected backend/observer closeout differs")
        pinned_receipts = {
            "l01/independent-review.json": "a39f768307403435cc866fff87aeee2a348066d0dc91bf9f5338265235544a01",
            "l02/independent-review.json": "f67fcafc7526e7828dbda1262ac0ddb8ae723782579078a556a88a299f663a54",
            "l02/root-terminal-review.json": "8281f0b7d7930859fcdd4e2aa776e7b720d985f70bfb441ab4501837ef30e6ef",
            "closeout/l02-backend-observer-result.json": "c38266c8f9eea3aa0f5bb553171feebdc63dafa06ae8a7410b3d23ec065f1bdf",
        }
        need(all(sha(raw[name]) == digest for name, digest in pinned_receipts.items()),
             "Pinned exact-copy review/closeout receipt differs")
        need(tree_members(fd) == (files, dirs) and read_member(fd, "SHA256SUMS").decode("ascii") == sums and
             all(read_member(fd, name) == value for name, value in raw.items()),
             "Packet changed during verification")
        return {"result": "VERIFIED_SELECTED_PUBLIC_L_PREFLIGHTS", "source": SOURCE, "attempts": results,
                "original_failure_status": "UNKNOWN_UNREPRODUCED", "public_24_hour_credit_seconds": 0,
                "private_or_native_operations": False, "local_files_including_seal": len(MEMBERS)}
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        result = verify(sys.argv[1] if len(sys.argv) == 2 else Path(__file__).absolute().parent)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        raise SystemExit("Verification refused: " + str(error))
