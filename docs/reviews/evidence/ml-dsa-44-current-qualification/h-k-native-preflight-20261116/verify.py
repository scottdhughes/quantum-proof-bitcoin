#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license; https://opensource.org/license/mit/
"""Offline selected-record verification. No native execution, network or Docker."""

import collections
import datetime
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

SOURCES = {
    "h": {
        "head": "52f26f31e2d8fcf52459f9cb2e9159564395f74a",
        "tree": "d2e07ad8db149f6d3eac1cb15379d97e1484e2e6",
    },
    "k": {
        "head": "18430ea2cfcac66cca0e8612605db47a5c0e935b",
        "tree": "d397b324f83b82017722073c3c53688e0765fb30",
    },
}
DRIVER = "6668f219acff79a25161d57bf505a3204ab50ef434adbb3487f913f0f913a6d0"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
PRIVATE = {
    "password",
    "passphrase",
    "secret",
    "ciphertext",
    "operator_input",
    "private_key",
    "seed",
    "wallet_seed",
    "mnemonic",
    "rpcpassword",
    "rpcauth",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
}
REQUIRED = {
    "integration-normal",
    "integration-asan-ubsan",
    "signer-normal",
    "signer-asan-ubsan",
    "key-lifecycle-normal-and-sanitized",
    "node-profile-and-resource-units",
    "actual-node-spend-old-record-restore",
    "actual-public-accepted-set-and-both-reindex-paths",
    "actual-node-30-full-blocks-and-mempool-pressure",
}
PROFILE_IDS = {
    "h/linux-aarch64-gcc",
    "h/linux-x86_64-gcc",
    "h/linux-x86_64-clang",
    "k/linux-aarch64-gcc",
    "k/linux-aarch64-clang",
    "k/linux-x86_64-gcc",
    "k/linux-x86_64-clang",
}
APP_EVENTS = [
    "two_fresh_private_containers_started",
    "two_native_test_wallets_funded",
    "confirmed_cross_container_send",
    "confirmed_cross_container_send",
    "unexpected_native_peer_disconnect_repaired",
    "confirmed_cross_container_send",
    "same_known_transaction_rebroadcast_after_rejoin",
    "actual_signature_and_wrong_network_controls",
    "durable_network_off_survived_native_reindex",
    "chainstate_reindex_preserved_full_agreement",
    "durable_network_off_survived_docker_restart",
    "peer_policy_orphan_preserved_and_recovered_inactive",
    "actual_docker_restart_and_public_orphan_recovery",
    "actual_sigkill_restart_preserved_agreement",
    "wrong_password_and_rechecksummed_corrupt_ciphertext_preserved_selected_record",
    "confirmed_cross_container_send",
    "old_backup_missing_both_records_recovered_and_spent",
]
FAULTS = [
    "crash",
    "partition",
    "hostile",
    "old_backup_missing_record",
    "reindex",
    "upgrade",
    "rollback",
]
FAULT_SECONDS = [75, 150, 225, 300, 450, 600, 675]
NODE = "/tmp/mldsa-demo-build/bin/pqbtcd"
SIGNER = "/tmp/demo-signer-bin/pilot-signer"
TMPFS = {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def hex64(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


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
        require(
            not {str(k).lower() for k in value} & PRIVATE, "Secret-bearing object field"
        )
        for item in value.values():
            public(item)
    elif isinstance(value, list):
        for item in value:
            public(item)
    elif isinstance(value, str):
        require(
            "-----BEGIN PRIVATE KEY-----" not in value
            and "-----BEGIN OPENSSH PRIVATE KEY-----" not in value,
            "Private key text",
        )
        require(
            re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", value) is None,
            "Credential-like text",
        )


def member(root, name):
    require(
        type(name) is str
        and re.fullmatch("[a-z0-9._/-]+", name)
        and name == Path(name).as_posix()
        and not name.startswith("/")
        and all(p not in (".", "..") for p in name.split("/")),
        "Unsafe or nonlowercase packet path",
    )
    current = root
    for part in name.split("/"):
        require(part in {p.name for p in current.iterdir()}, "Case-mismatched member")
        current = current / part
        require(not current.is_symlink(), "Symlink member")
    info = current.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_size <= 8 * 1024**2,
        "Unsafe packet member",
    )
    return current


# Frozen K DATA-only validator definitions are inserted here by the builder.
# BEGIN DATA VALIDATORS
def normalize_architecture(value):
    aliases = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }
    require(type(value) is str and value in aliases, "Unsupported native architecture")
    return aliases[value]


def validate_native_identity(
    expected, container_architecture, vm_architecture, manifest_architecture
):
    values = [
        normalize_architecture(value)
        for value in (
            expected,
            container_architecture,
            vm_architecture,
            manifest_architecture,
        )
    ]
    require(
        len(set(values)) == 1,
        "Requested, image, process and Docker VM native architecture must match; emulation is not qualification",
    )
    return values[0]


def validate_runtime(runtime, expected_image):
    require(
        type(expected_image) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image),
        "An exact source-built image identity is required",
    )
    require(
        type(runtime) is dict and runtime.get("image") == expected_image,
        "Qualification image differs from the requested source image",
    )
    require(
        runtime.get("ro") is True
        and runtime.get("network") == "none"
        and runtime.get("mounts") == [],
        "Qualification requires a read-only offline container without host mounts",
    )
    require(
        runtime.get("memory") == 4 * 1024**3
        and runtime.get("cpus") == 4_000_000_000
        and runtime.get("pids") == 512,
        "Qualification CPU, memory or PID limits differ from the declared configuration",
    )
    require(
        runtime.get("drop") == ["ALL"]
        and runtime.get("security") == ["no-new-privileges"]
        and runtime.get("tmpfs") == TMPFS,
        "Qualification isolation or temporary-state limits differ",
    )


def validate_resource_report(value):
    require(
        type(value) is dict
        and value.get("result") == "PASS"
        and value.get("timing_class") == "release"
        and value.get("qualification_scope") == "RELEASE_RESOURCE_CONFIGURATION"
        and value.get("release_timing_pass") is True,
        "A complete release resource qualification is required",
    )
    samples = value.get("samples")
    require(
        type(samples) is list
        and len(samples) == 30
        and all(
            type(row) is dict
            and row.get("block_weight") == 4_000_000
            and row.get("native_verifications") == 128
            and type(row.get("wall_ns")) is int
            and row["wall_ns"] >= 0
            and type(row.get("transaction_input_counts")) is list
            and row["transaction_input_counts"]
            and all(
                type(count) is int and count > 0
                for count in row["transaction_input_counts"]
            )
            and sum(row["transaction_input_counts"]) == 128
            and type(row.get("after")) is dict
            and type(row["after"].get("peak_rss_bytes")) is int
            and row["after"]["peak_rss_bytes"] > 0
            for row in samples
        ),
        "Thirty actual full-weight, 128-verification block observations are required",
    )
    for field in ("block_hash", "wire_sha256"):
        require(
            all(
                type(row.get(field)) is str
                and re.fullmatch(r"[0-9a-f]{64}", row[field])
                for row in samples
            )
            and len({row[field] for row in samples}) == len(samples),
            "Thirty distinct block and wire identities are required",
        )
    p95 = sorted(row["wall_ns"] for row in samples)[math.ceil(0.95 * len(samples)) - 1]
    require(
        type(value.get("p95_wall_ns")) is int
        and 0 <= value["p95_wall_ns"] <= 2_000_000_000
        and value["p95_wall_ns"] == p95
        and type(value.get("node_peak_rss_bytes")) is int
        and max(row["after"]["peak_rss_bytes"] for row in samples)
        <= value["node_peak_rss_bytes"]
        <= 1_073_741_824,
        "Declared release wall-time or memory threshold was exceeded",
    )
    pressure = value.get("pressure")
    require(
        type(pressure) is dict
        and type(pressure.get("evicted")) is int
        and pressure["evicted"] > 0,
        "Actual bounded mempool pressure/eviction evidence is required",
    )
    mempool = pressure.get("mempool", {})
    try:
        fee_floor = Decimal(str(mempool["mempoolminfee"]))
        initial_floor = Decimal(str(pressure["initial_mempoolminfee"]))
    except (KeyError, InvalidOperation):
        raise ValueError(
            "Actual mempool fee-floor observations are missing or malformed"
        ) from None
    require(
        type(mempool.get("usage")) is int
        and 0 < mempool["usage"] <= mempool.get("maxmempool", 0) == 32_000_000
        and fee_floor.is_finite()
        and initial_floor.is_finite()
        and fee_floor > initial_floor >= 0,
        "The 32 MB pressure bound and rising fee floor were not established",
    )


def validate_dependency_inventory(value):
    require(
        type(value) is dict
        and value
        and all(
            type(path) is str
            and re.fullmatch(r"dependencies/openssl/[A-Za-z0-9_./+-]+", path)
            and ".." not in Path(path).parts
            and type(digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in value.items()
        ),
        "Pinned qualification dependency inventory is invalid",
    )
    require(
        {
            "dependencies/openssl/bin/openssl",
            "dependencies/openssl/lib/libcrypto.a",
            "dependencies/openssl/source-archive.sha256",
        }
        <= set(value),
        "Required pinned qualification dependency identities are missing",
    )


CONSENSUS_SCHEMA = "PQBTC-MLDSA44-PUBLIC-CONSENSUS-CONTROLS-1"
CONSENSUS_SCOPE = "ACTUAL_NODE_PUBLIC_PROFILE_ACCEPTED_SET_AND_REINDEX"
POSITIVE_CONTROLS = {
    "canonical_empty_push",
    "canonical_direct_byte_01",
    "canonical_direct_80_bytes",
    "same_coin_valid_native_spend",
}
CONTROL_NAMES = (
    "classical_H1_coinbase",
    "classical_OP_TRUE",
    "witness_v0",
    "witness_v1_rc2",
    "future_v3",
    "P2SH",
    "OP_RETURN_smallint_alias",
    "OP_RETURN_81bytes",
    "nonempty_scriptSig",
    "actual_wrong_network_signature",
    "same_coin_valid_native_spend",
    "canonical_direct_byte_01",
    "canonical_empty_push",
    "canonical_direct_80_bytes",
    "reindex-chainstate_full_history_and_native_rejection",
    "reindex_full_history_and_native_rejection",
)


def validate_consensus_report(value):
    require(
        type(value) is dict
        and value.get("schema") == CONSENSUS_SCHEMA
        and value.get("scope") == CONSENSUS_SCOPE
        and value.get("result") == "PASS"
        and hex64(value.get("binary_sha256"))
        and value.get("owned_node_cleanup") == "STOPPED",
        "Public consensus control report is incomplete",
    )
    observations = value.get("observations")
    require(
        type(observations) is list
        and len(observations) == len(CONTROL_NAMES)
        and all(type(row) is dict for row in observations),
        "All sixteen actual public consensus controls are required",
    )
    rows = {row.get("control"): row for row in observations}
    require(
        set(rows) == set(CONTROL_NAMES),
        "Public consensus controls are missing, duplicated or unknown",
    )
    baseline = value.get("state_before_reindex")
    require(
        type(baseline) is dict
        and hex64(baseline.get("tip"))
        and type(baseline.get("height")) is int
        and type(baseline.get("utxo")) is dict
        and hex64(baseline["utxo"].get("muhash"))
        and baseline["utxo"].get("height") == baseline["height"]
        and baseline["utxo"].get("bestblock") == baseline["tip"]
        and type(baseline["utxo"].get("txouts")) is int
        and "total_amount" in baseline["utxo"],
        "Full pre-reindex UTXO fingerprint is missing",
    )
    for name, row in rows.items():
        admission = row.get("testmempoolaccept", {})
        if name in POSITIVE_CONTROLS:
            require(
                admission.get("allowed") is True
                and "submitblock" in row
                and row["submitblock"] is None,
                "A canonical/native positive control did not pass: " + name,
            )
        else:
            reason = (
                "bad-mldsa44-prevout"
                if name == "nonempty_scriptSig"
                else "bad-mldsa44-output"
            )
            if name == "actual_wrong_network_signature":
                require(
                    admission.get("allowed") is False
                    and "script-verify" in admission.get("reject-reason", "")
                    and type(row.get("submitblock")) is str
                    and "script-verify" in row["submitblock"],
                    "The actual wrong-network signature was not rejected by both paths",
                )
            else:
                require(
                    row.get("submitblock") == reason
                    and (
                        name == "classical_H1_coinbase"
                        or (
                            admission.get("allowed") is False
                            and admission.get("reject-reason") == reason
                        )
                    ),
                    "A forbidden public-profile shape was not rejected by both paths: "
                    + name,
                )
            require(
                row.get("tip_unchanged") is True,
                "Rejected control changed the valid tip: " + name,
            )
        if name.startswith("reindex"):
            require(
                row.get("state") == baseline and hex64(row.get("rejected_block_hash")),
                "Reindex did not retain the complete valid state or a new rejected block identity",
            )
    full = rows["reindex_full_history_and_native_rejection"]
    prior = rows["reindex-chainstate_full_history_and_native_rejection"][
        "rejected_block_hash"
    ]
    require(
        full.get("revisited_stored_block_hash") == prior
        and hex64(full.get("fresh_reindex_log_sha256"))
        and type(full.get("stored_rejection_log_line")) is str
        and "ConnectBlock " + prior + " failed, bad-mldsa44-output"
        in full["stored_rejection_log_line"],
        "Full reindex did not demonstrably reject the exact previously stored forbidden block",
    )


# END DATA VALIDATORS


def native_profile(raw, row):
    subject = row["subject"]
    expected = SOURCES[subject]
    paths = row["paths"]
    d, n, inventory, resource, consensus, app = [
        parse(raw[paths[k]])
        for k in ("descriptor", "native", "inventory", "resource", "consensus", "app")
    ]
    require(
        set(d) == {"schema", "image", "manifest", "manifest_sha256"}
        and d["schema"] == "PQBTC-MLDSA44-SOURCE-RUNTIME-1",
        "Descriptor schema",
    )
    m = d["manifest"]
    # source_runtime.canonical includes one LF. Event-chain canonical encoding
    # intentionally does not, so the shared canonical() helper needs this LF.
    require(
        m.get("schema") == "PQBTC-MLDSA44-SOURCE-BUILD-1"
        and hex64(d["manifest_sha256"])
        and sha(canonical(m) + b"\n") == d["manifest_sha256"]
        and row["manifest_sha256"] == d["manifest_sha256"],
        "Canonical source manifest checksum",
    )
    image = d["image"]
    architecture = row["architecture"]
    compiler = row["compiler"]
    require(
        row["id"] == subject + "/linux-" + architecture + "-" + compiler
        and row["source"] == expected,
        "Profile index identity",
    )
    require(
        {"head": m["source_head"], "tree": m["source_tree"]} == n["source"] == expected,
        "Native source binding",
    )
    require(
        m["architecture"] == n["architecture"] == architecture
        and m["compiler"] == n["compiler"] == compiler,
        "Compiler/architecture binding",
    )
    require(
        d["manifest_sha256"] == n["manifest_sha256"] == app["manifest_sha256"]
        and image == n["image"] == app["image"] == row["image"],
        "Image/manifest binding",
    )
    require(
        n["schema"] == "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1"
        and n["scope"] == "NATIVE_PLATFORM_QUALIFICATION_ONLY"
        and n["result"] == "PASS"
        and n["production_admitted"] is False
        and n["public_soak"] is False,
        "Native scope/outcome",
    )
    require(
        set(n["checks"]) == REQUIRED and all(v == "PASS" for v in n["checks"].values()),
        "All nine native gates",
    )
    require(n["emulated"] is False, "Emulation is not native qualification")
    validate_native_identity(
        architecture, n["architecture"], n["docker_vm_architecture"], m["architecture"]
    )
    validate_runtime(n["runtime"], image)
    require(
        n["identity_before"] == n["identity_after"]
        and n["identity_before"]["head"] == expected["head"]
        and n["identity_before"]["tree"] == expected["tree"],
        "Before/after native identity",
    )
    require(
        all(m["sha256"].get(k) == v for k, v in n["identity_before"]["sha256"].items())
        and {NODE, SIGNER} <= set(n["identity_before"]["sha256"]),
        "Qualified node/signer hash binding",
    )
    require(
        n["qualification_dependencies_sha256"]
        == m["qualification_dependencies_sha256"],
        "Dependency identity binding",
    )
    validate_dependency_inventory(n["qualification_dependencies_sha256"])
    require(
        n["cleanup"] in ("STOPPED_RETAINED", "REMOVED"), "Original native cleanup scope"
    )
    require(
        type(inventory) is dict and all(hex64(v) for v in inventory.values()),
        "Original inventory shape",
    )
    original_descriptor = paths.get("native_descriptor", paths["descriptor"])
    require(
        canonical(parse(raw[original_descriptor])) == canonical(d),
        "Native-original and outer descriptor full semantic identity",
    )
    for name, path in [
        ("runtime-descriptor.json", original_descriptor),
        ("report.json", paths["native"]),
        ("node-resources.json", paths["resource"]),
        ("public-consensus-controls.json", paths["consensus"]),
    ]:
        require(
            inventory.get(name) == sha(raw[path]),
            "Included original native inventory member: " + name,
        )
    validate_resource_report(resource)
    validate_consensus_report(consensus)
    require(
        resource["binary_sha256"] == consensus["binary_sha256"] == m["sha256"][NODE],
        "Resource/consensus actual node binding",
    )
    require(
        resource["fixture_library_sha256"] == consensus["fixture_library_sha256"],
        "Shared native fixture identity",
    )
    require(
        app["schema"] == "PQBTC-MLDSA44-PUBLIC-APP-FLOW-1"
        and app["scope"] == "PRIVATE_TWO_CONTAINER_APP_FLOW_NOT_PUBLIC_SOAK"
        and app["result"] == "PASS"
        and app["clean_source_qualified"] is True
        and app["cleanup_errors"] == [],
        "Private HTTP app outcome/scope",
    )
    require(
        {"head": app["source_head"], "tree": app["source_tree"]} == expected,
        "Private app source binding",
    )
    require(
        [e["name"] for e in app["events"]] == APP_EVENTS,
        "All 17 private HTTP events in order",
    )
    require(
        all(type(e["monotonic_ns"]) is int for e in app["events"])
        and [e["monotonic_ns"] for e in app["events"]]
        == sorted(e["monotonic_ns"] for e in app["events"]),
        "Private app monotonic clock",
    )
    repair = app["events"][4]
    rebroadcast = app["events"][6]
    orphan = app["events"][11]
    require(
        repair["transaction_peers"] == [1, 1]
        and repair["old_node_id"] not in repair["new_node_ids"]
        and finite(repair["elapsed_seconds"])
        and 0 <= repair["elapsed_seconds"] <= 60,
        "Unexpected disconnect repair proof",
    )
    require(
        rebroadcast["known_in_mempool"] is rebroadcast["rebroadcast"] is True
        and rebroadcast["reissued_payment"] is False
        and hex64(rebroadcast["txid"])
        and hex64(rebroadcast["raw_transaction_sha256"])
        and finite(rebroadcast["elapsed_seconds"])
        and 0 <= rebroadcast["elapsed_seconds"] <= 60,
        "Same-id rebroadcast proof",
    )
    require(
        orphan["preserved"] is True
        and orphan["network_active"] is False
        and hex64(orphan["original_sha256"]),
        "Conservative peer-policy recovery proof",
    )
    return {
        "id": row["id"],
        "image": image,
        "native_gates": 9,
        "private_http_events": 17,
        "raw_native_descriptor_sha256": sha(raw[original_descriptor]),
        "outer_descriptor_sha256": sha(raw[paths["descriptor"]]),
        "descriptor_raw_serialization_difference": raw[original_descriptor]
        != raw[paths["descriptor"]],
        "original_native_inventory_entries": len(inventory),
        "selected_inventory_payloads_verified": 4,
        "unselected_inventory_payloads_not_rehashed": len(inventory) - 4,
        "original_native_cleanup": n["cleanup"],
    }


def chain(raw):
    require(raw.endswith(b"\n"), "Incomplete event line")
    previous = "0" * 64
    last = -1
    rows = []
    bounds = {}
    for index, line in enumerate(raw.splitlines()):
        e = parse(line)
        public(e)
        require(
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
        require(
            type(e["sequence"]) is int
            and e["sequence"] == index
            and e["previous_sha256"] == previous,
            "Event sequence/previous hash",
        )
        require(
            type(e["monotonic_ns"]) is int and e["monotonic_ns"] >= last,
            "Reversed monotonic event clock",
        )
        require(
            sha(canonical({k: v for k, v in e.items() if k != "sha256"}))
            == e["sha256"],
            "Event digest",
        )
        stamp = datetime.datetime.fromisoformat(e["utc"])
        require(
            stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0,
            "Event UTC",
        )
        if e["kind"] in ("public_clock_started", "public_clock_completed"):
            require(e["kind"] not in bounds, "Duplicate clock boundary")
            bounds[e["kind"]] = {k: e[k] for k in ("utc", "monotonic_ns", "data")}
        previous, last = e["sha256"], e["monotonic_ns"]
        rows.append(e)
    return rows, {
        "count": len(rows),
        "last_sha256": previous,
        "clock_boundaries": bounds,
    }


def preflight(raw, index, profiles):
    base = "public-preflight01/"
    report, decl, inventory = [
        parse(raw[base + n])
        for n in ("report.json", "declaration.json", "evidence-sha256.json")
    ]
    require(
        report["result"] == "PREFLIGHT_PASS"
        and report["mode"] == decl["mode"] == "preflight",
        "Completed preflight outcome",
    )
    require(
        report["scope"] == decl["scope"] == SCOPE
        and report["production_admitted"] is decl["production_admitted"] is False,
        "Preflight prototype TEST scope",
    )
    runner = {**SOURCES["k"], "driver_sha256": DRIVER}
    require(
        report["host_runner_source"] == decl["host_runner_source"] == runner,
        "Preflight runner source binding",
    )
    require(
        decl["profile_sha256"] == PROFILE
        and report["configuration_sha256"] == decl["configuration_sha256"]
        and hex64(report["configuration_sha256"]),
        "Preflight profile/configuration hash binding",
    )
    require(
        decl["duration_seconds"] == 900
        and all(
            finite(report[k]) and report[k] >= 900
            for k in ("elapsed_monotonic_seconds", "elapsed_wall_seconds")
        ),
        "Actual dual 900s clock required",
    )
    require(
        set(inventory) == {"events.jsonl", "report.json", "declaration.json"},
        "Original preflight inventory allowlist",
    )
    compressed = raw[base + "events.jsonl.gz"]
    require(
        compressed[:4] == b"\x1f\x8b\x08\x00"
        and compressed[4:8] == b"\0" * 4
        and compressed[8] == 2,
        "Deterministic gzip header",
    )
    expected = index["preflight"]["original_events"]
    require(
        type(expected["bytes"]) is int and 0 < expected["bytes"] <= 8 * 1024**2,
        "Original event size bound",
    )
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as f:
        events = f.read(expected["bytes"] + 1)
        require(
            len(events) == expected["bytes"] and not f.read(1), "Bounded gzip closure"
        )
    require(
        sha(events) == expected["sha256"] == inventory["events.jsonl"],
        "Original uncompressed event bytes",
    )
    require(
        inventory["report.json"] == sha(raw[base + "report.json"])
        and inventory["declaration.json"]
        == sha(raw[base + "declaration.json"])
        == report["declaration_sha256"],
        "Original report/declaration hashes",
    )
    rows, event_chain = chain(events)
    require(
        event_chain == report["event_chain"] == index["preflight"]["event_chain"],
        "Complete event-chain binding",
    )
    require(
        event_chain["count"] == 2305
        and set(event_chain["clock_boundaries"])
        == {"public_clock_started", "public_clock_completed"},
        "Recorded 2305-event completed preflight",
    )
    bounds = event_chain["clock_boundaries"]
    start, end = bounds["public_clock_started"], bounds["public_clock_completed"]
    require(
        type(start["data"].get("duration_seconds")) is int
        and start["data"]["duration_seconds"] == 900,
        "Event-declared preflight duration must be 900",
    )
    mono = (end["monotonic_ns"] - start["monotonic_ns"]) / 1e9
    wall = (
        datetime.datetime.fromisoformat(end["utc"])
        - datetime.datetime.fromisoformat(start["utc"])
    ).total_seconds()
    require(
        mono >= 900
        and wall >= 900
        and report["event_clock_elapsed"]
        == {"monotonic_seconds": mono, "wall_seconds": wall},
        "Completed event clock >=900s",
    )
    phases = report["phases"]
    require(
        [x["name"] for x in phases] == FAULTS, "Every required phase must complete once"
    )
    require(
        [x["name"] for x in decl["faults"]] == FAULTS
        and [x["scheduled_elapsed_seconds"] for x in decl["faults"]] == FAULT_SECONDS
        and all(x["maximum_recovery_seconds"] == 300 for x in decl["faults"]),
        "Original declared fault schedule",
    )
    for phase, scheduled in zip(phases, FAULT_SECONDS):
        require(
            phase["result"] == "PASS"
            and scheduled <= phase["started_elapsed"] <= scheduled + 60
            and 0 <= phase["finished_elapsed"] - phase["started_elapsed"] <= 300,
            "Declared phase timing/recovery limit",
        )
        payment = phase["recovery_payment"]
        require(
            hex64(payment["txid"])
            and hex64(payment["block_hash"])
            and payment["recipient_in_mempool"] is True
            and payment["sender"] != payment["receiver"]
            and 0 <= payment["settle_seconds"] <= 60
            and phase["started_elapsed"]
            <= payment["started_elapsed"]
            <= payment["completed_elapsed"]
            <= phase["finished_elapsed"],
            "Fault recovery confirmed payment",
        )
    require(
        len({p["recovery_payment"]["txid"] for p in phases}) == 7,
        "Unique fault recovery payments",
    )
    counts = collections.Counter(e["kind"] for e in rows)
    payments = [e["data"] for e in rows if e["kind"] == "confirmed_payment"]
    require(
        len(payments) == len({p["txid"] for p in payments}) == 22
        and counts["action"] == counts["action_dispatched"] == 1116,
        "Recorded22unique payments/action pairing",
    )
    require(
        [e["data"] for e in rows if e["kind"] == "fault_completed"] == phases,
        "Phase report/event consistency",
    )
    slots = [e["data"] for e in rows if e["kind"] == "normal_slot"]
    require(
        slots == report["slots"]
        and len(slots) == 15
        and [r["slot"] for r in slots] == list(range(15)),
        "All15normal slots",
    )
    successes = [r for r in slots if r["success"] is True]
    misses = [r for r in slots if r["success"] is False]
    require(
        len(successes) == report["successful_normal_slots"] == 12
        and len(misses) == report["missed_slots"] == 3,
        "Recorded normal-slot outcomes",
    )
    require(
        all(
            r["slot"] * 60 <= r["payment_started_elapsed"] < (r["slot"] + 1) * 60
            and 0 <= r["settle_seconds"] <= 60
            for r in successes
        ),
        "Actual slot times/60s settlement",
    )
    latencies = sorted(r["settle_seconds"] for r in successes)
    require(
        report["p95_settle_seconds"]
        == latencies[math.ceil(0.95 * len(latencies)) - 1]
        <= 60,
        "Actual normal-slot p95",
    )
    for miss in misses:
        matching = [
            p
            for p in phases
            if p["name"] == miss["fault"]
            and miss["slot"] * 60 < p["finished_elapsed"]
            and (miss["slot"] + 1) * 60 > p["started_elapsed"]
        ]
        require(len(matching) == 1, "Miss attribution to declared fault window")
    require(
        report["final_recovered_spend"] is report["cleanup_ok"] is True,
        "Final recovered confirmed spend and cleanup",
    )
    for name in ("public_start", "public_end"):
        require(
            report[name]["result"] == "PASS"
            and report[name]["scope"]
            == "ANONYMOUS_PUBLIC_TLS_NATIVE_P2P_HANDSHAKE_ONLY",
            "Actual anonymous public TLS P2P probe",
        )
    for host in ("mac", "research"):
        c = report["cleanup"][host]
        stop = c["backend_stop_proofs"]["after_exit"]
        require(
            c["exit_code"] == 0
            and c["stderr_bytes"] == 0
            and stop["backend_stopped"] is True
            and stop["state"] == "STOPPED",
            "Both owned backends stopped",
        )
        for version, subject in [("a", "h"), ("b", "k")]:
            declared = next(x for x in decl["hosts"] if x["name"] == host)["versions"][
                version
            ]
            arch = "aarch64" if host == "mac" else "x86_64"
            p = profiles[subject + "/linux-" + arch + "-gcc"]
            descriptor = parse(raw[p["paths"]["descriptor"]])
            native = raw[p["paths"]["native"]]
            require(
                declared["descriptor_file_sha256"] == sha(raw[p["paths"]["descriptor"]])
                and declared["native_receipt_sha256"] == sha(native)
                and declared["image"] == descriptor["image"]
                and {"head": declared["source_head"], "tree": declared["source_tree"]}
                == SOURCES[subject]
                and declared["node_sha256"] == descriptor["manifest"]["sha256"][NODE]
                and declared["signer_sha256"]
                == descriptor["manifest"]["sha256"][SIGNER],
                "Preflight portable H/K qualification bindings",
            )
    completed = next(
        e["sequence"] for e in rows if e["kind"] == "public_clock_completed"
    )
    tail = [e for e in rows if e["sequence"] > completed]
    quarantine = [
        e
        for e in tail
        if e["kind"] == "action" and e["data"]["action"] == "quarantine_record"
    ]
    recover = [
        e for e in tail if e["kind"] == "action" and e["data"]["action"] == "recover"
    ]
    sends = [e for e in tail if e["kind"] == "action" and e["data"]["action"] == "send"]
    final_payments = [e for e in tail if e["kind"] == "confirmed_payment"]
    require(
        len(quarantine) == len(recover) == len(sends) == len(final_payments) == 1,
        "Final missing-record recovery and fresh payment sequence",
    )
    q = quarantine[0]["data"]["result"]
    rec = recover[0]["data"]["result"]["result"]
    sent = sends[0]["data"]["result"]["result"]
    payment = final_payments[0]["data"]
    require(
        q["selected_record_missing"] is True
        and q["independent_journal_preserved"] is True
        and rec["chain_snapshot_restored"] is False
        and rec["wallet_id"] == q["wallet_id"]
        and rec["next_receive"] >= q["next_receive"]
        and rec["next_change"] >= q["next_change"],
        "Final record recovery preserved identity/floors with independent journal; no both-record claim",
    )
    require(
        sent["broadcast"] is True
        and sent["txid"] == payment["txid"]
        and payment["recipient_in_mempool"] is True
        and hex64(payment["block_hash"]),
        "Final recovered wallet confirmed fresh spend",
    )
    require(
        rows[-1]["kind"] == "attempt_completed"
        and rows[-1]["data"] == {"cleanup_ok": True, "result": "PREFLIGHT_PASS"},
        "Sealed terminal preflight",
    )
    return {
        "events": 2305,
        "faults": 7,
        "confirmed_unique_payments": 22,
        "normal_successes": 12,
        "fault_misses": 3,
        "actual_monotonic_seconds": mono,
        "actual_wall_seconds": wall,
        "final_record_recovery_and_confirmed_spend": True,
        "both_backends_stopped": True,
        "24h_soak_credit_seconds": 0,
    }


def packet_files(root):
    actual = set()

    def unreadable(error):
        raise ValueError("Unreadable packet directory") from error

    for current, directories, files in os.walk(
        root, followlinks=False, onerror=unreadable
    ):
        for name in directories + files:
            path = Path(current) / name
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), "Any packet symlink entry refused")
            require(
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "Nonregular packet entry",
            )
            if stat.S_ISREG(info.st_mode):
                actual.add(path.relative_to(root).as_posix())
    return actual


def verify_packet(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "Unsafe packet root")
    actual = packet_files(root)
    hashes = {}
    for line in member(root, "sha256sums").read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(hex64(digest) and name not in hashes, "Checksum line")
        hashes[name] = digest
    require(actual == set(hashes) | {"sha256sums"}, "Missing or extra packet file")
    raw = {}
    for name, digest in hashes.items():
        raw[name] = member(root, name).read_bytes()
        require(sha(raw[name]) == digest, "Packet checksum mismatch: " + name)
        if name.endswith(".json"):
            public(parse(raw[name]))
    require(raw[".gitattributes"] == b"* -text\n", "Git byte preservation")
    index = parse(raw["source.json"])
    require(index["schema"] == "PQBTC-HK-SELECTED-PUBLIC-PACKET-1", "Index schema")
    require(
        index["sources"] == SOURCES
        and index["production_admitted"] is False
        and index["human_cryptographic_review_claimed"] is False
        and index["whole_application_constant_time_claimed"] is False
        and index["public_24h_soak_credit_seconds"] == 0,
        "Subject/scope boundaries",
    )
    require(
        index["H_qualified_profile_count"] == 3
        and index["K_qualified_profile_count"] == 4
        and index["H_arm_clang_qualification_claimed"] is False
        and index["live_soak_payloads_included"] is False
        and index["historical_pending_statuses_relabelled"] is False,
        "Profile counts and historical/live scope",
    )
    files = {row["path"]: row for row in index["files"]}
    require(
        set(files) == set(hashes) - {"source.json"}, "Index exact selected membership"
    )
    for name, row in files.items():
        require(
            row["bytes"] == len(raw[name]) and row["sha256"] == sha(raw[name]),
            "Index file hash/size",
        )
        if row["transform"] == "NONE":
            require(
                row["origin_sha256"] == sha(raw[name])
                and row["origin_bytes"] == len(raw[name]),
                "Byte-exact copy provenance",
            )
    profiles = {row["id"]: row for row in index["profiles"]}
    require(set(profiles) == PROFILE_IDS, "Exact H3/K4 profiles; no H ARM Clang claim")
    native = [native_profile(raw, row) for row in profiles.values()]
    implementation = parse(raw["context/implementation-byte-binding.json"])
    require(
        implementation["sources"] == SOURCES
        and implementation["selected_functional_file_count"] == 15
        and len(implementation["same_h_k_sha256"]) == 15
        and implementation["same_selected_functional_bytes"] is True
        and implementation["all_tracked_h_to_k_changes_under_docs"] is True
        and implementation["consensus_format_transition_claimed"] is False
        and implementation["behavioral_upgrade_claimed"] is False
        and all(hex64(x) for x in implementation["same_h_k_sha256"].values())
        and implementation["tracked_changed_paths"]
        and all(x.startswith("docs/") for x in implementation["tracked_changed_paths"]),
        "H/K selected15-byte identity/scope",
    )
    result = preflight(raw, index, profiles)
    return {
        "result": "VERIFIED_SELECTED_H3_K4_NATIVE_PRIVATE_HTTP_AND_900S_PREFLIGHT",
        "scope": "SELECTED_RECORDS_ONLY_NO_NATIVE_REEXECUTION_NO_24H_SOAK_RESULT",
        "native_profiles": native,
        "preflight": result,
        "production_admitted": False,
        "human_review_claimed": False,
        "public_24h_soak_credit_seconds": 0,
    }


if __name__ == "__main__":
    try:
        require(__debug__, "Optimized Python refused")
        root = (
            Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent
        )
        require(len(sys.argv) <= 2, "Usage: python3 -B verify.py [packet-root]")
        print(json.dumps(verify_packet(root), sort_keys=True))
    except Exception as error:
        print("VERIFICATION_FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
