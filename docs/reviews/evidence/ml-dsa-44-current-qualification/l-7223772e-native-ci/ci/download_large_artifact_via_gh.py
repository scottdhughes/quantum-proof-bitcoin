#!/usr/bin/env python3
"""Download an authorized Actions artifact as a bounded gh API byte stream."""

import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

if not __debug__:
    raise SystemExit("Optimized Python refused")

OUTPUT = Path(__file__).resolve().parent / "artifact-14280600594.zip"
EXPECTED_BYTES = 538848243
EXPECTED_SHA256 = "891925e956ecc78fe6806fd21e6fb4a7eea3a111d1841d3978c155921c75c6d9"
ENDPOINT = "repos/scottdhughes/quantum-proof-bitcoin/actions/artifacts/14280600594/zip"
PART = OUTPUT.with_name(OUTPUT.name + ".part")
process = None
try:
    if OUTPUT.exists() or OUTPUT.is_symlink() or PART.exists() or PART.is_symlink():
        raise ValueError("New destination required")
    fd = os.open(PART, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    checksum, count, start = hashlib.sha256(), 0, time.monotonic()
    process = subprocess.Popen(["env", "-u", "GH_DEBUG", "gh", "api", ENDPOINT],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    with os.fdopen(fd, "wb") as output:
        while True:
            remaining = 900 - (time.monotonic() - start)
            if remaining <= 0:
                raise TimeoutError("Total download bound")
            ready, _, _ = select.select([process.stdout], [], [], min(60, remaining))
            if not ready:
                raise TimeoutError("Idle download bound")
            block = os.read(process.stdout.fileno(), 1024**2)
            if not block:
                break
            count += len(block)
            if count > EXPECTED_BYTES:
                raise ValueError("Artifact byte bound")
            checksum.update(block)
            output.write(block)
    if process.wait(timeout=30) != 0:
        raise RuntimeError("GitHub CLI download failed")
    if count != EXPECTED_BYTES or checksum.hexdigest() != EXPECTED_SHA256:
        raise ValueError("Downloaded artifact identity mismatch")
    os.link(PART, OUTPUT)
    PART.unlink()
    receipt = {"schema": "PQBTC-L-LARGE-ACTIONS-ARTIFACT-DOWNLOAD-1",
               "result": "PASS", "source_head": "7223772e76d2d0a0bb7fd1d35e0e16fba61918fd",
               "run_id": 43970911876, "attempt": 1, "artifact_id": 14280600594,
               "bytes": count, "sha256": checksum.hexdigest(),
               "connector_limit_bytes": 536870912,
               "connector_rejection": "Artifact exceeds max size",
               "fallback": "Bounded gh API raw ZIP byte stream; authenticated redirect handled internally by CLI",
               "signed_capability_URL_observed_or_persisted": False,
               "credential_values_read_or_printed": False,
               "archive_entries_opened": False,
               "path": str(OUTPUT)}
    with (OUTPUT.parent / "large-artifact-download-verification.json").open("x") as out:
        json.dump(receipt, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps(receipt, sort_keys=True))
except Exception as error:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if PART.exists() and not PART.is_symlink():
        PART.unlink()
    print("ARTIFACT_DOWNLOAD_FAILED: " + type(error).__name__, file=sys.stderr)
    raise SystemExit(1)
