#!/usr/bin/env python3
"""Mutate disposable packet copies only; never edit the selected originals."""

import hashlib
import gzip
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def refreshed_test_metadata(root):
    # A semantic negative control must get beyond checksums: rebuild the copied
    # report inventory and copied index/checksums after the intentional forgery.
    # This function is used ONLY inside TemporaryDirectory mutant copies.
    base = root / "public-preflight01"
    inventory = json.loads((base / "evidence-sha256.json").read_bytes())
    for name in ("report.json", "declaration.json"):
        inventory[name] = sha((base / name).read_bytes())
    events = gzip.decompress((base / "events.jsonl.gz").read_bytes())
    inventory["events.jsonl"] = sha(events)
    (base / "evidence-sha256.json").write_text(
        json.dumps(inventory, sort_keys=True, indent=2) + "\n"
    )
    index = json.loads((root / "source.json").read_bytes())
    index["preflight"]["original_events"] = {
        "bytes": len(events),
        "sha256": sha(events),
    }
    index["preflight"]["event_chain"] = json.loads((base / "report.json").read_bytes())[
        "event_chain"
    ]
    for profile in index["profiles"]:
        paths = profile["paths"]
        path = root / paths["inventory"]
        native_inventory = json.loads(path.read_bytes())
        native_inventory["runtime-descriptor.json"] = sha(
            (root / paths.get("native_descriptor", paths["descriptor"])).read_bytes()
        )
        path.write_text(json.dumps(native_inventory, sort_keys=True, indent=2) + "\n")
    for row in index["files"]:
        raw = (root / row["path"]).read_bytes()
        row["bytes"] = len(raw)
        row["sha256"] = sha(raw)
        if row["transform"] == "NONE":
            row["origin_bytes"] = len(raw)
            row["origin_sha256"] = sha(raw)
        elif row["path"] == "public-preflight01/events.jsonl.gz":
            row["origin_bytes"] = len(events)
            row["origin_sha256"] = sha(events)
    (root / "source.json").write_text(
        json.dumps(index, sort_keys=True, indent=2) + "\n"
    )
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "sha256sums")
    (root / "sha256sums").write_text(
        "".join(
            sha(p.read_bytes()) + "  " + p.relative_to(root).as_posix() + "\n"
            for p in files
        )
    )


def invoke(root):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(root / "verify.py"), str(root)],
        capture_output=True,
        text=True,
        timeout=20,
        cwd="/",
    )


def controls(root):
    positive = invoke(root)
    if positive.returncode:
        raise ValueError("Positive packet verification failed: " + positive.stderr)
    original = {
        p.relative_to(root).as_posix(): sha(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }
    outcomes = []
    for name, expected in [
        ("tamper", "Packet checksum mismatch"),
        ("shortclock", "Actual dual 900s clock required"),
        ("wrongsource", "Preflight runner source binding"),
        ("missingphase", "Every required phase must complete once"),
        ("manifestchecksum", "Canonical source manifest checksum"),
        ("eventduration", "Event-declared preflight duration must be 900"),
        ("directorysymlink", "Any packet symlink entry refused"),
    ]:
        with tempfile.TemporaryDirectory(prefix="public-packet-negative-") as temporary:
            target = Path(temporary) / "packet"
            shutil.copytree(root, target, symlinks=True)
            report = target / "public-preflight01/report.json"
            if name == "directorysymlink":
                external = Path(temporary) / "external-public-fixture"
                external.mkdir()
                marker = external / "public-marker.txt"
                marker.write_bytes(b"PUBLIC_FIXTURE_NOT_PRIVATE_DATA")
                link = target / "unindexed-directory"
                link.symlink_to(external, target_is_directory=True)
                # Defense-in-depth copy behavior is checked with public data:
                # preserve the link itself, never copy its external contents.
                guarded_copy = Path(temporary) / "symlink-preserving-copy"
                shutil.copytree(target, guarded_copy, symlinks=True)
                if not (guarded_copy / "unindexed-directory").is_symlink():
                    raise ValueError("Disposable copy followed directory symlink")
                if any(p.name == marker.name for p in guarded_copy.rglob("*")):
                    raise ValueError("External public marker traversed")
            elif name == "tamper":
                path = (
                    target / "native-k/linux-aarch64-gcc/public-profile-app/report.json"
                )
                path.write_bytes(path.read_bytes() + b" ")
            elif name == "manifestchecksum":
                path = target / "native-k/linux-aarch64-clang/runtime-descriptor.json"
                value = json.loads(path.read_bytes())
                value["manifest"]["PUBLIC_METADATA_ONLY"] = "ISOLATED_NEGATIVE_FIXTURE"
                # Deliberately retain the stale manifest_sha256 and rehash all
                # copied raw-descriptor inventory/index/checksum envelopes.
                path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
                refreshed_test_metadata(target)
            elif name == "eventduration":
                path = target / "public-preflight01/events.jsonl.gz"
                rows = [
                    json.loads(line)
                    for line in gzip.decompress(path.read_bytes()).splitlines()
                ]
                previous = "0" * 64
                boundaries = {}
                for row in rows:
                    if row["kind"] == "public_clock_started":
                        row["data"]["duration_seconds"] = 899
                    row["previous_sha256"] = previous
                    unsigned = {k: v for k, v in row.items() if k != "sha256"}
                    row["sha256"] = sha(
                        json.dumps(
                            unsigned,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        ).encode()
                    )
                    previous = row["sha256"]
                    if row["kind"] in (
                        "public_clock_started",
                        "public_clock_completed",
                    ):
                        boundaries[row["kind"]] = {
                            k: row[k] for k in ("utc", "monotonic_ns", "data")
                        }
                events = b"".join(
                    json.dumps(
                        row, sort_keys=True, separators=(",", ":"), allow_nan=False
                    ).encode()
                    + b"\n"
                    for row in rows
                )
                compressed = io.BytesIO()
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0
                ) as handle:
                    handle.write(events)
                path.write_bytes(compressed.getvalue())
                value = json.loads(report.read_bytes())
                value["event_chain"] = {
                    "count": len(rows),
                    "last_sha256": previous,
                    "clock_boundaries": boundaries,
                }
                report.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
                refreshed_test_metadata(target)
            else:
                value = json.loads(report.read_bytes())
                if name == "shortclock":
                    value["elapsed_monotonic_seconds"] = 899.0
                    value["elapsed_wall_seconds"] = 899.0
                elif name == "wrongsource":
                    value["host_runner_source"]["head"] = (
                        "52f26f31e2d8fcf52459f9cb2e9159564395f74a"
                    )
                else:
                    value["phases"] = value["phases"][:-1]
                report.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
                refreshed_test_metadata(target)
            result = invoke(target)
            if result.returncode != 1 or expected not in result.stderr:
                raise ValueError(
                    "Negative control did not reject for its intended gate: "
                    + name
                    + " "
                    + result.stderr
                )
            outcomes.append(
                {
                    "control": name,
                    "result": "REJECTED_AS_REQUIRED",
                    "gate": expected,
                    "mutated_original_packet": False,
                    "rehashed_mutant_metadata": name
                    not in ("tamper", "directorysymlink"),
                    "external_marker_followed": False,
                }
            )
    after = {
        p.relative_to(root).as_posix(): sha(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }
    if after != original:
        raise ValueError("Original packet changed during negative controls")
    return {
        "result": "PASS_SEVEN_ISOLATED_PUBLIC_PACKET_NEGATIVE_CONTROLS",
        "positive_result": json.loads(positive.stdout)["result"],
        "controls": outcomes,
        "original_packet_unchanged": True,
        "native_execution_network_or_Research": False,
    }


if __name__ == "__main__":
    try:
        root = (
            Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent
        )
        if len(sys.argv) > 2:
            raise ValueError("Usage: python3 -B negative-controls.py [packet-root]")
        print(json.dumps(controls(root), sort_keys=True))
    except Exception as error:
        print("NEGATIVE_CONTROLS_FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
