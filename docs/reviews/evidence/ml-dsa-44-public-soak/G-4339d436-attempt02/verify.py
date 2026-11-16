#!/usr/bin/env python3
"""Read-only, standard-library verification of this selected failed-attempt packet."""

import collections
import datetime
import gzip
import hashlib
import io
import json
import pathlib
import stat
import sys

EXPECTED_SOURCE = {
    "head": "4339d436cdcfce9724476b9786994d347f1a4b06",
    "tree": "b9923bede37da41119ac69a39d57f16a8a89b3eb",
    "driver_sha256": "62a2a8af09ead25ff8a0d1cf379dd60bf5b70643611e8c1c0f2a86199bdce616",
}
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
PRIVATE_FIELDS = {
    "password",
    "passphrase",
    "secret",
    "ciphertext",
    "operator_input",
    "private_key",
    "seed",
}


def must(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    d = {}
    for k, v in items:
        must(k not in d, "Duplicate JSON member")
        d[k] = v
    return d


def parse(raw):
    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )


def canonical(x):
    return json.dumps(
        x, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public(x):
    if isinstance(x, dict):
        must(not PRIVATE_FIELDS.intersection(x), "Private object field")
        for v in x.values():
            public(v)
    elif isinstance(x, list):
        for v in x:
            public(v)


def safe_path(root, name):
    p = pathlib.PurePosixPath(name)
    must(
        not p.is_absolute()
        and name == p.as_posix()
        and ".." not in p.parts
        and "." not in p.parts,
        "Unsafe member name",
    )
    target = root.joinpath(*p.parts)
    for ancestor in [target, *list(target.parents)[: len(p.parts) - 1]]:
        must(not ancestor.is_symlink(), "Symlink member refused")
    must(stat.S_ISREG(target.lstat().st_mode), "Nonregular member")
    return target


def verify_chain(raw):
    previous, last_mono, boundaries = "0" * 64, -1, {}
    counter, successes, misses, faults, payments, size = (
        collections.Counter(),
        0,
        [],
        [],
        0,
        0,
    )
    for size, line in enumerate(raw.splitlines(), 1):
        e = parse(line)
        public(e)
        must(
            set(e)
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
        must(
            e["sequence"] == size - 1 and e["previous_sha256"] == previous,
            "Event sequence/previous hash",
        )
        must(
            type(e["monotonic_ns"]) is int and e["monotonic_ns"] >= last_mono,
            "Event clock reversed",
        )
        unsigned = {k: v for k, v in e.items() if k != "sha256"}
        must(sha(canonical(unsigned)) == e["sha256"], "Event digest mismatch")
        stamp = datetime.datetime.fromisoformat(e["utc"])
        must(
            stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0,
            "Non-UTC event",
        )
        previous, last_mono = e["sha256"], e["monotonic_ns"]
        counter[e["kind"]] += 1
        if e["kind"] in ("public_clock_started", "public_clock_completed"):
            must(e["kind"] not in boundaries, "Duplicate clock boundary")
            boundaries[e["kind"]] = {k: e[k] for k in ("utc", "monotonic_ns", "data")}
        if e["kind"] == "confirmed_payment":
            payments += 1
        elif e["kind"] == "normal_slot":
            must(type(e["data"].get("success")) is bool, "Slot result shape")
            if e["data"]["success"]:
                successes += 1
            else:
                misses.append(e["data"])
        elif e["kind"] == "fault_completed":
            faults.append(e["data"])
    return (
        {"count": size, "last_sha256": previous, "clock_boundaries": boundaries},
        counter,
        successes,
        misses,
        faults,
        payments,
    )


def verify_packet(root):
    root = pathlib.Path(root)
    checksum = (root / "SHA256SUMS").read_text()
    hashes = {}
    for line in checksum.splitlines():
        digest, name = line.split("  ", 1)
        must(
            len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest)
            and name not in hashes,
            "Checksum line",
        )
        hashes[name] = digest
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    must(actual == set(hashes) | {"SHA256SUMS"}, "Unexpected or missing packet member")
    raw = {}
    for name, digest in hashes.items():
        raw[name] = safe_path(root, name).read_bytes()
        must(sha(raw[name]) == digest, "Packet checksum mismatch: " + name)
    source, report, decl, inventory = [
        parse(raw[n])
        for n in (
            "SOURCE.json",
            "report.json",
            "declaration.json",
            "evidence-sha256.json",
        )
    ]
    for value in (source, report, decl, inventory):
        public(value)
    must(raw[".gitattributes"] == b"* -text\n", "Byte-preservation policy")
    must(
        source["source_subject"]
        == report["host_runner_source"]
        == decl["host_runner_source"]
        == EXPECTED_SOURCE,
        "Source binding",
    )
    must(
        source["result"] == report["result"] == "FAIL"
        and report["mode"] == decl["mode"] == "soak",
        "Failed-attempt outcome",
    )
    must(source["scope"] == report["scope"] == decl["scope"] == SCOPE, "Scope binding")
    must(
        source["production_admitted"]
        is report["production_admitted"]
        is decl["production_admitted"]
        is False,
        "Production scope",
    )
    must(
        source["partial_elapsed_seconds_credited_to_future_soak"] == 0
        and source["resumption_allowed"] is False,
        "Partial credit/resume",
    )
    files = {row["path"]: row for row in source["files"]}
    must(set(files) == set(hashes) - {"SOURCE.json"}, "SOURCE payload membership")
    for name, row in files.items():
        must(
            row["bytes"] == len(raw[name]) and row["sha256"] == sha(raw[name]),
            "SOURCE payload hash/size",
        )
        if row["provenance"]["transform"] == "NONE":
            must(
                row["provenance"]["original_bytes"] == len(raw[name])
                and row["provenance"]["original_sha256"] == sha(raw[name]),
                "Unchanged-copy provenance",
            )
    compressed = raw["events.jsonl.gz"]
    must(
        compressed[:4] == b"\x1f\x8b\x08\x00"
        and compressed[4:8] == b"\x00" * 4
        and compressed[8] == 2,
        "Deterministic gzip header",
    )
    expected_size = source["original_events"]["bytes"]
    must(
        type(expected_size) is int and 0 < expected_size <= 128 * 1024 * 1024,
        "Original event size bound",
    )
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        events = stream.read(expected_size + 1)
        must(
            len(events) == expected_size and not stream.read(1),
            "Uncompressed event size",
        )
    must(
        set(inventory) == {"events.jsonl", "report.json", "declaration.json"},
        "Original inventory members",
    )
    originals = {
        "events.jsonl": events,
        "report.json": raw["report.json"],
        "declaration.json": raw["declaration.json"],
    }
    for name, value in originals.items():
        must(sha(value) == inventory[name], "Original inventory digest: " + name)
    must(
        sha(events) == source["original_events"]["sha256"], "Original events provenance"
    )
    must(
        report["declaration_sha256"] == inventory["declaration.json"],
        "Declaration binding",
    )
    chain, kinds, successes, misses, faults, payments = verify_chain(events)
    must(chain == report["event_chain"] == source["event_chain"], "Report event chain")
    must(
        chain["count"] == 59862
        and payments == 1010
        and kinds["normal_slot"] == 1005
        and successes == 1002
        and len(misses) == 3
        and len(faults) == 6,
        "Recorded G counts",
    )
    must(
        all(x.get("fault") in {"partition", "upgrade"} for x in misses),
        "Fault miss attribution",
    )
    must(
        [x["name"] for x in faults]
        == [
            "crash",
            "partition",
            "hostile",
            "old_backup_missing_record",
            "reindex",
            "upgrade",
        ]
        and all(x["result"] == "PASS" for x in faults),
        "Completed fault phases",
    )
    must(
        set(chain["clock_boundaries"]) == {"public_clock_started"}
        and decl["duration_seconds"] == 86400,
        "Incomplete 24-hour clock",
    )
    must(kinds["action"] == kinds["action_dispatched"] == 28862, "Action counts")
    must(report["cleanup_ok"] is True, "Cleanup outcome")
    for host in ("mac", "research"):
        c = report["cleanup"][host]
        stop = c["backend_stop_proofs"]["after_exit"]
        must(
            stop["backend_stopped"] is True
            and stop["state"] == "STOPPED"
            and c["exit_code"] == 0
            and c["stderr_bytes"] == 0,
            "Owned cleanup proof",
        )
    allowed = {
        "bridge_pid",
        "instance_id",
        "event",
        "hostname",
        "loopback_port",
        "public_ips",
        "until_utc",
        "public_ip",
        "tls",
        "reason",
        "bytes",
    }
    transport_counts = collections.Counter()
    for name in sorted(
        n
        for n in raw
        if n.startswith("public-transport/public-transport-") and n.endswith(".jsonl")
    ):
        for line in raw[name].splitlines():
            row = parse(line)
            public(row)
            must(set(row) <= allowed, "Transport field allowlist")
            transport_counts[row.get("event", "bridge_identity")] += 1
    must(
        dict(transport_counts)
        == {
            "bridge_identity": 3,
            "bridge_started": 3,
            "public_tls_connected": 7,
            "public_tls_disconnected": 6,
        },
        "Public transport counts",
    )
    return {
        "result": "VERIFIED_FAILED_ATTEMPT",
        "report_result": "FAIL",
        "events": chain["count"],
        "confirmed_payments": payments,
        "normal_successes": successes,
        "fault_misses": len(misses),
        "completed_phases": len(faults),
        "both_backends": "STOPPED_REPORTED",
        "elapsed_seconds_credited": 0,
        "source_head": EXPECTED_SOURCE["head"],
        "last_sha256": chain["last_sha256"],
    }


if __name__ == "__main__":
    try:
        must(__debug__, "Optimized Python is refused")
        print(
            json.dumps(
                verify_packet(pathlib.Path(__file__).resolve().parent), sort_keys=True
            )
        )
    except Exception as error:
        print("VERIFICATION_FAILED: " + str(error), file=sys.stderr)
        raise SystemExit(1)
