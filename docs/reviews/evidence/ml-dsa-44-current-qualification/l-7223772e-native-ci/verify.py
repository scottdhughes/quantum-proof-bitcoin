#!/usr/bin/env python3
"""Portable selected L-native/private-app/CI DATA verifier. Stdlib only; no runtime/network."""
import collections
from decimal import Decimal, InvalidOperation
import hashlib,json,math,os,re,stat,sys
from pathlib import Path
SOURCES={"l":{"head":"7223772e76d2d0a0bb7fd1d35e0e16fba61918fd","tree":"33b36275b1da7f7fbc27fae00d519206b0f7c16f"}}
CI_SHA="682c1677fe0aaeef4ab89cb82bd7c853a7bd9c0c84c45741c752225552bcd0c6"
CLOSURE_SHA="c51a0c1a874d4451f29276a591e4e1bf833502f94d473a9c5f5451eaab79dea3"
PRIVATE={"password","passphrase","secret","ciphertext","operator_input","private_key","seed","wallet_seed","mnemonic","rpcpassword","rpcauth","access_token","refresh_token","cookie"}
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

def normalize_architecture(value):
    aliases = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
    require(type(value) is str and value in aliases, "Unsupported native architecture")
    return aliases[value]

def validate_native_identity(expected, container_architecture, vm_architecture, manifest_architecture):
    values = [normalize_architecture(value) for value in
              (expected, container_architecture, vm_architecture, manifest_architecture)]
    require(len(set(values)) == 1, "Requested, image, process and Docker VM native architecture must match; emulation is not qualification")
    return values[0]

def validate_runtime(runtime, expected_image):
    require(type(expected_image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image),
            "An exact source-built image identity is required")
    require(type(runtime) is dict and runtime.get("image") == expected_image,
            "Qualification image differs from the requested source image")
    require(runtime.get("ro") is True and runtime.get("network") == "none" and runtime.get("mounts") == [],
            "Qualification requires a read-only offline container without host mounts")
    require(runtime.get("memory") == 4 * 1024**3 and runtime.get("cpus") == 4_000_000_000 and runtime.get("pids") == 512,
            "Qualification CPU, memory or PID limits differ from the declared configuration")
    require(runtime.get("drop") == ["ALL"] and runtime.get("security") == ["no-new-privileges"] and
            runtime.get("tmpfs") == TMPFS, "Qualification isolation or temporary-state limits differ")

def validate_resource_report(value):
    require(type(value) is dict and value.get("result") == "PASS" and value.get("timing_class") == "release" and
            value.get("qualification_scope") == "RELEASE_RESOURCE_CONFIGURATION" and
            value.get("release_timing_pass") is True, "A complete release resource qualification is required")
    samples = value.get("samples")
    require(type(samples) is list and len(samples) == 30 and all(
        type(row) is dict and row.get("block_weight") == 4_000_000 and row.get("native_verifications") == 128 and
        type(row.get("wall_ns")) is int and row["wall_ns"] >= 0 and
        type(row.get("transaction_input_counts")) is list and row["transaction_input_counts"] and
        all(type(count) is int and count > 0 for count in row["transaction_input_counts"]) and
        sum(row["transaction_input_counts"]) == 128 and
        type(row.get("after")) is dict and type(row["after"].get("peak_rss_bytes")) is int and
        row["after"]["peak_rss_bytes"] > 0 for row in samples),
        "Thirty actual full-weight, 128-verification block observations are required")
    for field in ("block_hash", "wire_sha256"):
        require(all(type(row.get(field)) is str and re.fullmatch(r"[0-9a-f]{64}", row[field]) for row in samples) and
                len({row[field] for row in samples}) == len(samples), "Thirty distinct block and wire identities are required")
    p95 = sorted(row["wall_ns"] for row in samples)[math.ceil(0.95 * len(samples)) - 1]
    require(type(value.get("p95_wall_ns")) is int and 0 <= value["p95_wall_ns"] <= 2_000_000_000 and
            value["p95_wall_ns"] == p95 and type(value.get("node_peak_rss_bytes")) is int and
            max(row["after"]["peak_rss_bytes"] for row in samples) <= value["node_peak_rss_bytes"] <= 1_073_741_824,
            "Declared release wall-time or memory threshold was exceeded")
    pressure = value.get("pressure")
    require(type(pressure) is dict and type(pressure.get("evicted")) is int and pressure["evicted"] > 0,
            "Actual bounded mempool pressure/eviction evidence is required")
    mempool = pressure.get("mempool", {})
    try:
        fee_floor = Decimal(str(mempool["mempoolminfee"]))
        initial_floor = Decimal(str(pressure["initial_mempoolminfee"]))
    except (KeyError, InvalidOperation):
        raise ValueError("Actual mempool fee-floor observations are missing or malformed") from None
    require(type(mempool.get("usage")) is int and 0 < mempool["usage"] <= mempool.get("maxmempool", 0) == 32_000_000 and
            fee_floor.is_finite() and initial_floor.is_finite() and fee_floor > initial_floor >= 0,
            "The 32 MB pressure bound and rising fee floor were not established")

def validate_dependency_inventory(value):
    require(type(value) is dict and value and all(type(path) is str and
            re.fullmatch(r"dependencies/openssl/[A-Za-z0-9_./+-]+", path) and
            ".." not in Path(path).parts and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in value.items()), "Pinned qualification dependency inventory is invalid")
    require({"dependencies/openssl/bin/openssl", "dependencies/openssl/lib/libcrypto.a",
             "dependencies/openssl/source-archive.sha256"} <= set(value),
            "Required pinned qualification dependency identities are missing")

SCHEMA = "PQBTC-MLDSA44-PUBLIC-CONSENSUS-CONTROLS-1"

SCOPE = "ACTUAL_NODE_PUBLIC_PROFILE_ACCEPTED_SET_AND_REINDEX"

POSITIVE_CONTROLS = {"same_coin_valid_native_spend", "canonical_direct_byte_01",
                     "canonical_empty_push", "canonical_direct_80_bytes"}

CONTROL_NAMES = (
    "classical_H1_coinbase", "classical_OP_TRUE", "witness_v0", "witness_v1_rc2", "future_v3", "P2SH",
    "OP_RETURN_smallint_alias", "OP_RETURN_81bytes", "nonempty_scriptSig", "actual_wrong_network_signature",
    "same_coin_valid_native_spend", "canonical_direct_byte_01", "canonical_empty_push", "canonical_direct_80_bytes",
    "reindex-chainstate_full_history_and_native_rejection", "reindex_full_history_and_native_rejection",
)

def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None

def validate_consensus_report(value):
    require(type(value) is dict and value.get("schema") == SCHEMA and value.get("scope") == SCOPE and
            value.get("result") == "PASS" and digest(value.get("binary_sha256")) and
            value.get("owned_node_cleanup") == "STOPPED", "Public consensus control report is incomplete")
    observations = value.get("observations")
    require(type(observations) is list and len(observations) == len(CONTROL_NAMES) and
            all(type(row) is dict for row in observations), "All sixteen actual public consensus controls are required")
    rows = {row.get("control"): row for row in observations}
    require(set(rows) == set(CONTROL_NAMES), "Public consensus controls are missing, duplicated or unknown")
    baseline = value.get("state_before_reindex")
    require(type(baseline) is dict and digest(baseline.get("tip")) and type(baseline.get("height")) is int and
            type(baseline.get("utxo")) is dict and digest(baseline["utxo"].get("muhash")) and
            baseline["utxo"].get("height") == baseline["height"] and baseline["utxo"].get("bestblock") == baseline["tip"] and
            type(baseline["utxo"].get("txouts")) is int and "total_amount" in baseline["utxo"],
            "Full pre-reindex UTXO fingerprint is missing")
    for name, row in rows.items():
        admission = row.get("testmempoolaccept", {})
        if name in POSITIVE_CONTROLS:
            require(admission.get("allowed") is True and "submitblock" in row and row["submitblock"] is None,
                    "A canonical/native positive control did not pass: " + name)
        else:
            reason = "bad-mldsa44-prevout" if name == "nonempty_scriptSig" else "bad-mldsa44-output"
            if name == "actual_wrong_network_signature":
                require(admission.get("allowed") is False and "script-verify" in admission.get("reject-reason", "") and
                        type(row.get("submitblock")) is str and "script-verify" in row["submitblock"],
                        "The actual wrong-network signature was not rejected by both paths")
            else:
                require(row.get("submitblock") == reason and (name == "classical_H1_coinbase" or
                        (admission.get("allowed") is False and admission.get("reject-reason") == reason)),
                        "A forbidden public-profile shape was not rejected by both paths: " + name)
            require(row.get("tip_unchanged") is True, "Rejected control changed the valid tip: " + name)
        if name.startswith("reindex"):
            require(row.get("state") == baseline and digest(row.get("rejected_block_hash")),
                    "Reindex did not retain the complete valid state or a new rejected block identity")
    full = rows["reindex_full_history_and_native_rejection"]
    prior = rows["reindex-chainstate_full_history_and_native_rejection"]["rejected_block_hash"]
    require(full.get("revisited_stored_block_hash") == prior and digest(full.get("fresh_reindex_log_sha256")) and
            type(full.get("stored_rejection_log_line")) is str and
            "ConnectBlock " + prior + " failed, bad-mldsa44-output" in full["stored_rejection_log_line"],
            "Full reindex did not demonstrably reject the exact previously stored forbidden block")

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


def path_parts(name):
    require(type(name) is str and re.fullmatch(r"[A-Za-z0-9._/-]+",name) and not name.startswith("/") and all(x not in ("",".","..") for x in name.split("/")),"Unsafe packet member path")
    return name.split("/")

def root_fd(root):
    requested=Path(root)
    require(".." not in requested.parts,"Unsafe root path")
    p=requested.absolute()
    fd=os.open(p.anchor,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        return fd
    except BaseException:
        os.close(fd);raise

def safe_read(root,name):
    parts=path_parts(name);fd=root_fd(root)
    try:
        for part in parts[:-1]:
            require(part in os.listdir(fd),"Case-mismatched directory")
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        require(parts[-1] in os.listdir(fd),"Case-mismatched member")
        file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    finally:os.close(fd)
    try:
        info=os.fstat(file_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=16*1024**2,"Unsafe packet member")
        raw=b""
        while part:=os.read(file_fd,65536):raw+=part
        after=os.fstat(file_fd)
        require(len(raw)==info.st_size and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"Member changed during read")
        return raw
    finally:os.close(file_fd)

def packet_entries(root):
    files,dirs=set(),set()
    def walk(fd,prefix):
        for name in os.listdir(fd):
            rel=prefix+name;path_parts(rel);info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode),"Any packet symlink entry refused")
            if stat.S_ISDIR(info.st_mode):
                dirs.add(rel);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                try:walk(child,rel+"/")
                finally:os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,"Nonregular or hardlinked member")
                files.add(rel)
    fd=root_fd(root)
    try:walk(fd,"")
    finally:os.close(fd)
    return files,dirs

def checksum_map(raw):
    values={}
    for line in raw.decode("ascii").splitlines():
        digest,name=line.split("  ",1);path_parts(name)
        require(hex64(digest) and name not in values,"Checksum entry")
        values[name]=digest
    return values

def verify_profile(raw,row):
    result=native_profile(raw,row);p=row["paths"]
    n,m,r,a=[parse(raw[p[k]]) for k in ("native","descriptor","resource","app")];m=m["manifest"]
    require(len(n["identity_before"]["sha256"])==8 and len(m["sha256"])==18 and len(n["qualification_dependencies_sha256"])==152,"Exact identity/dependency counts")
    require(r["pressure"]["evicted"]==17,"Seventeen observed evictions")
    b=r["boundaries"]
    require(b["25_input_testmempoolaccept"]["allowed"] is True and b["26_input_testmempoolaccept"]["allowed"] is False and b["26_input_testmempoolaccept"]["reject-reason"]=="bad-txns-too-many-sigops" and b["128_input_block"]["native_verifications"]==128 and b["129_input_submitblock"]=="bad-blk-sigops" and b["template_native_verifications"]==128 and b["template_sigops"]==80000 and b["malformed_testmempoolaccept"]["allowed"] is False,"Native input/template boundary controls")
    e=a["events"];sends=[x for x in e if x["name"]=="confirmed_cross_container_send"]
    require(len(sends)==4 and len({x["txid"] for x in sends})==4 and all(hex64(x["txid"]) and hex64(x["block_hash"]) for x in sends) and e[6]["txid"]==sends[2]["txid"],"Known reannouncement refers to existing confirmed transaction")
    adverse=e[7];require(adverse["baseline_accepted"] is True and adverse["invalid_signature_allowed"] is False and adverse["wrong_network_refused"] is True and adverse["broadcast"] is False,"Actual adverse controls")
    f=a["final"];require(hex64(f["tip"]) and hex64(f["utxo_hash"]) and type(f["height"]) is int and f["height"]>0 and len(set(f["wallet_ids"]))==2 and f["wallet_ids"]==e[1]["wallet_ids"] and len(set(f["volume_ids"]))==2 and e[10]["volume_id"]==f["volume_ids"][0] and e[-1]["wallet_id"]==f["wallet_ids"][0],"Private app final wallet/volume/chain continuity")
    result.update(resource_samples=30,verifications_per_sample=128,dependency_identities=152,evictions=17,consensus_controls=16)
    return result

def verify_ci(raw):
    require(sha(raw["ci/all-CI-qualification.json"])==CI_SHA,"Pinned final L CI aggregate bytes")
    r=parse(raw["ci/all-CI-qualification.json"])
    require(r["schema"]=="PQBTC-EXACT-SOURCE-ALL-CI-QUALIFICATION-1" and r["result"]=="PASS" and {k:r["source"][k] for k in ("head","tree")}==SOURCES["l"],"Exact L CI source/result")
    runs=r["runs"];require(len(runs)==r["run_count"]==14,"Fourteen CI runs")
    jobs=[];run_ids=set()
    for entry in runs:
        run=entry["run"];rows=entry["latest_logical_jobs"]
        require(run["databaseId"] not in run_ids and run["headSha"]==SOURCES["l"]["head"] and run["status"]=="completed" and run["conclusion"]=="success","CI run source/outcome")
        run_ids.add(run["databaseId"])
        for job in rows:
            require(job["run_id"]==run["databaseId"] and ("head_sha" not in job or job["head_sha"]==SOURCES["l"]["head"]) and job["status"]=="completed" and job["conclusion"]=="success","Latest logical job source/outcome")
        jobs+=rows
    require(len(jobs)==len({j["id"] for j in jobs})==r["latest_logical_job_count"]==52,"Fifty-two unique latest logical jobs")
    matrix=next(x for x in runs if x["run"]["databaseId"]==43970927737)
    require(matrix["run"]["attempt"]==1 and len(matrix["latest_logical_jobs"])==r["matrix_latest_logical_jobs"]==22 and r["non_matrix_runs"]==13 and r["non_matrix_latest_logical_jobs"]==30,"Matrix/nonmatrix accounting")
    mh=r["matrix_history"];require(mh["executed_retries"]==0 and mh["capacity_cancellations"]==0 and len(mh["actual_mac_jobs"])==2 and all(j["head_sha"]==SOURCES["l"]["head"] and j["conclusion"]=="success" and j["runner_id"]>0 for j in mh["actual_mac_jobs"]),"Actual Mac executions and no matrix retries")
    h=r["availability_retry_history"]
    require(h["run_id"]==43970746110 and h["executed_failed_job_availability_retries"]==2 and h["final_attempt"]==3 and h["final_result"]=="PASS" and h["full_workflow_or_sibling_reruns"]==0 and h["separate_explicit_authorizations"]==2 and h["additional_retry_allowed"] is False and len(h["authorizations"])==len(h["executed_retry_receipts"])==2,"Exactly two scoped advisory availability retries")
    for attempt,key,diag in [(1,"original_attempt1","attempt1_diagnosis"),(2,"original_attempt2","attempt2_diagnosis")]:
        old=h[key];run=old["run"];d=h[diag]
        require(run["id"]==43970746110 and run["run_attempt"]==attempt and run["head_sha"]==SOURCES["l"]["head"] and run["conclusion"]=="failure" and d["classification"]=="GITHUB_UNAUTHENTICATED_CORE_API_RATE_LIMIT_EXHAUSTED" and d["http_status"]==403 and d["curl_exit_code"]==22 and d["request"]["authenticated"] is False,"Original anonymous quota failure retained")
    require(h["attempt3_success"]["result"]=="PASS_AFTER_TWO_SEPARATELY_AUTHORIZED_EXTERNAL_QUOTA_RETRIES" and h["attempt3_success"]["run"]["run_attempt"]==3 and h["attempt3_feed"]["curl_exit_code"]==0 and h["attempt3_feed"]["http_status"]==200 and h["attempt3_feed"]["request"]["authenticated"] is False,"Third-attempt anonymous feed recovery")
    require(len(r["retained_history_files"])==28,"All retained public CI history references")
    for name,entry in r["retained_history_files"].items():
        key="ci/"+name;require(key in raw and sha(raw[key])==entry["sha256"] and len(raw[key])==entry["bytes"],"Closed CI history payload: "+name)
    original=checksum_map(raw["ci/CI-EVIDENCE-SHA256SUMS"])
    require(len(original)==55 and {"ci/"+n for n in original}<=set(raw),"All55 selected public CI seal members local")
    for name,digest in original.items():require(sha(raw["ci/"+name])==digest,"Original CI55 seal member: "+name)
    require(r["public_soak_elapsed_seconds_credited_from_CI"]==r["prior_candidate_qualification_credit"]==0 and r["native_code_or_image_executed_by_CI_evidence_verifier"] is False and r["private_wallet_key_backup_cookie_env_or_credential_material_opened"] is False and r["manual_assembled_and_export"]["result"]=="PASS","CI boundaries")
    seal=parse(raw["ci/local-seal-verification.json"])
    require(seal["result"]=="PASS" and seal["exact_duplicate_report_sha256"]==CI_SHA and seal["public_files_scanned_for_credentials_and_signed_URLs"]==55 and seal["retained_history_hashes_reverified"]==28 and seal["public_soak_credit_seconds"]==0,"CI local seal scope")
    return {"runs":14,"latest_logical_jobs":52,"matrix_jobs":22,"nonmatrix_jobs":30,"advisory_original_quota_failures_retained":2,"advisory_scoped_availability_retries":2,"CI55_public_seal_members_verified":55,"retained_history_payloads_verified":28,"public_soak_credit_seconds":0}

def verify_packet(root):
    require(__debug__,"Optimized Python refused")
    actual,dirs=packet_entries(root);hashes=checksum_map(safe_read(root,"sha256sums"))
    require(actual==set(hashes)|{"sha256sums"},"Missing or extra packet file")
    expected_dirs={str(p) for name in actual for p in Path(name).parents if str(p)!="."}
    require(dirs==expected_dirs,"Missing or extra packet directory")
    raw={name:safe_read(root,name) for name in hashes}
    for name,digest in hashes.items():
        require(sha(raw[name])==digest,"Packet checksum mismatch: "+name)
        if name.endswith(".json"):public(parse(raw[name]))
    require(raw[".gitattributes"]==b"* -text\n","Git byte preservation")
    index=parse(raw["source.json"])
    require(index["schema"]=="PQBTC-L-NATIVE-CI-SELECTED-PUBLIC-PACKET-1" and index["sources"]==SOURCES and index["production_admitted"] is False and index["human_cryptographic_review_claimed"] is False and index["whole_application_constant_time_claimed"] is False and index["public_24h_soak_credit_seconds"]==0 and index["live_or_terminal_public_attempt_payloads_included"] is False,"Exact subject and scope boundaries")
    files={row["path"]:row for row in index["files"]};require(len(files)==len(index["files"]) and set(files)==set(hashes)-{"source.json"},"Index exact selected membership")
    for name,row in files.items():
        require(row["bytes"]==len(raw[name]) and row["sha256"]==sha(raw[name]),"Index file hash/size")
        if row["transform"]=="NONE":require(row["origin_sha256"]==sha(raw[name]) and row["origin_bytes"]==len(raw[name]),"Byte-exact original provenance")
    profiles={row["id"]:row for row in index["profiles"]};require(set(profiles)=={"l/linux-"+a+"-"+c for a in ("aarch64","x86_64") for c in ("gcc","clang")},"Exact four L profiles")
    native=[verify_profile(raw,row) for row in profiles.values()]
    require(sha(raw["context/root-four-profile-reverification.json"])==CLOSURE_SHA,"Pinned root four-profile closure")
    closure=parse(raw["context/root-four-profile-reverification.json"])
    require(closure["result"]=="PASS" and {k:closure["source"][k] for k in ("head","tree")}==SOURCES["l"] and len(closure["profiles"])==4 and closure["native_code_executed"] is False and closure["runtime_or_network_operations"] is False and closure["public_soak"] is False and closure["elapsed_public_soak_credit_seconds"]==0,"Root closure source/scope")
    closure_profiles={p["profile"]:p for p in closure["profiles"]}
    for row in profiles.values():
        recorded=closure_profiles[row["architecture"]+"-"+row["compiler"]];paths=row["paths"]
        require(recorded["image"]==row["image"] and recorded["manifest_sha256"]==row["manifest_sha256"] and recorded["outer_descriptor"]["sha256"]==sha(raw[paths["descriptor"]]),"Root closure descriptor binding")
        require(recorded["native_inventory"]["sha256"]==sha(raw[paths["inventory"]]) and recorded["public_app"]["sha256"]==sha(raw[paths["app"]]),"Root closure inventory/app binding")
        for name,key in [("report.json","native"),("runtime-descriptor.json","native_descriptor"),("node-resources.json","resource"),("public-consensus-controls.json","consensus")]:
            require(recorded["native_inventory"]["verified_selected_payloads"][name]["sha256"]==sha(raw[paths[key]]),"Root closure selected payload binding")
    ci=verify_ci(raw)
    return {"result":"VERIFIED_SELECTED_L4_NATIVE_PRIVATE_HTTP_AND_CI","scope":"DATA_ONLY_SELECTED_RECORDS_NO_NATIVE_REEXECUTION_NO_PUBLIC_CLOCK_CREDIT","native_profiles":native,"CI":ci,"production_admitted":False,"human_review_claimed":False,"public_24h_soak_credit_seconds":0,"files_verified":len(hashes),"all_original_native_inventory_payloads_closed":False,"CI55_selected_public_seal_closed":True}

if __name__=="__main__":
    try:
        require(__debug__,"Optimized Python refused")
        require(len(sys.argv)<=2,"Usage: python3 -I -B verify.py [packet-root]")
        root=Path(sys.argv[1]) if len(sys.argv)==2 else Path(__file__).absolute().parent
        print(json.dumps(verify_packet(root),sort_keys=True))
    except Exception as error:
        print("VERIFICATION_FAILED: "+str(error),file=sys.stderr);sys.exit(1)
