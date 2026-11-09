#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Build and test a clean-checkout node/signer/console in a fresh Docker namespace.

Only public disposable fixtures are created. Native code runs in the source-built
Linux image. The host executes Python HTTP/process orchestration, never a node or
signer binary. Failed runtime state is retained for diagnosis.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def validate_namespace(container):
    require(type(container) is str and re.fullmatch(r"pqbtc-ci-[a-z0-9][a-z0-9_.-]{0,70}", container),
            "Use a unique pqbtc-ci-* namespace; existing user wallets cannot be targeted")
    return container + "-data-v1"


def require_fresh_namespace(container):
    volume = validate_namespace(container)
    for command, label in ((["docker", "container", "inspect", container], "container"),
                           (["docker", "volume", "inspect", volume], "volume")):
        result = subprocess.run(command, capture_output=True, timeout=20)
        require(result.returncode != 0, "CI " + label + " already exists; choose a new namespace")
    return volume


def checkout_identity(repo, expected_head=None):
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True,encoding="utf8").strip()
    tree = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True,encoding="utf8").strip()
    dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"])
    require(not dirty, "Assembled CI requires a clean checkout, including untracked files")
    require(expected_head is None or head == expected_head, "Checkout HEAD does not match the requested source")
    return {"head": head, "tree": tree}


def require_descriptor_source(value, head, compiler):
    require(type(value) is dict and value.get("schema") == "PQBTC-MLDSA44-SOURCE-RUNTIME-1", "Invalid source runtime descriptor")
    require(type(value.get("image")) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["image"]), "Runtime image ID is not exact")
    require(type(value.get("manifest_sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]),
            "Runtime manifest hash is missing")
    manifest = value.get("manifest")
    require(type(manifest) is dict and manifest.get("source_head") == head and manifest.get("compiler") == compiler,
            "Runtime descriptor does not match the checkout/compiler being tested")
    checks = manifest.get("checks", {})
    require(all(checks.get(name) == "PASS" for name in ("native_integration", "signer", "mldsa44_node_tests")),
            "Required native build/test evidence did not pass")


def validate_native_evidence(raw, manifest):
    require(type(raw) is bytes and len(raw) <= 64 * 1024 * 1024, "Native evidence archive exceeds its bound")
    expected = manifest.get("evidence_sha256")
    require(type(expected) is dict and expected and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+", name)
            and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) for name, digest in expected.items()),
            "Native evidence inventory is invalid")
    observed = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for item in archive:
            if item.isdir() and item.name in (".", "./"):
                continue
            name = item.name.removeprefix("./")
            require(item.isfile() and name in expected and name not in observed and 0 <= item.size <= 16 * 1024 * 1024,
                    "Native evidence member is unexpected, repeated or unsafe")
            handle = archive.extractfile(item)
            require(handle is not None, "Native evidence member is unavailable")
            with handle:
                data = handle.read(16 * 1024 * 1024 + 1)
            require(len(data) == item.size and hashlib.sha256(data).hexdigest() == expected[name],
                    "Native evidence hash does not match the build manifest")
            observed.add(name)
    require(observed == set(expected), "Native evidence archive is incomplete")


def require_state(value, baseline):
    require(value.get("phase") == "running" and value.get("ready") is True, "Assembled runtime is not ready")
    wallet, expected = value.get("wallet", {}), baseline["wallet"]
    require(wallet.get("wallet_id") == expected["wallet_id"], "Restart changed the wallet identity")
    require(wallet.get("spendable_sats") == expected["spendable_sats"], "Restart changed the confirmed balance")
    for field in ("next_receive", "next_change"):
        require(type(wallet.get(field)) is int and wallet[field] >= expected[field], "Restart lowered an address counter")
    nodes, old_nodes = value.get("nodes", []), baseline["nodes"]
    require(len(nodes) == 2 and len(old_nodes) == 2, "Exactly two real nodes are required")
    for field in ("tip", "utxo_hash", "height"):
        expected_value = old_nodes[0].get(field)
        require(expected_value is not None and all(node.get(field) == expected_value for node in nodes),
                "Node " + field + " differs from the confirmed baseline")
    require(bool(nodes[0].get("utxo_hash")), "Full UTXO comparison was not supplied")


def finish_report(output, report, events, *, candidate_pass, cleanup=None):
    try:
        if candidate_pass and cleanup is not None:
            cleanup()
        report["result"] = "PASS" if candidate_pass else "FAIL"
    except Exception as error:
        report["result"] = "FAIL"
        report["cleanup_error"] = str(error)
        raise
    finally:
        report["events"] = events
        write_json(output / "report.json", report)


class Console:
    def __init__(self, port, event):
        self.url = "http://127.0.0.1:" + str(port)
        self.event = event

    def status(self):
        with urlopen(self.url + "/api/status", timeout=30) as response:
            body = json.load(response)
        require(body.get("ok") is True, "Console did not return actual status")
        return body["data"]

    def wait(self, process):
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            require(process.poll() is None, "Console process exited; inspect assembled.log")
            try:
                return self.status()
            except (OSError, URLError, ValueError):
                time.sleep(0.25)
        raise ValueError("Timed out waiting for the assembled console")

    def action(self, name, params=None):
        with urlopen(self.url, timeout=15) as response:
            html = response.read(131072).decode()
        match = re.search(r'name="console-token"\s+content="([A-Za-z0-9_-]+)"', html)
        require(match is not None, "Console token is unavailable")
        payload = {"action": name, "params": params or {}, "request_id": uuid.uuid4().hex}
        request = Request(self.url + "/api/action", data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json", "Origin": self.url,
                                   "X-Console-Token": match[1]})
        try:
            with urlopen(request, timeout=240) as response:
                body = json.load(response)
        except HTTPError as error:
            with error:
                detail = error.read(4096).decode("utf8", "replace")
            raise ValueError("Console action " + name + " failed: " + detail) from error
        require(body.get("ok") is True, "Console action failed: " + name)
        self.event(name, result=body["data"].get("result"))
        return body["data"]


def main(argv=None):
    require(__debug__, "Optimized Python is not permitted for assembled CI evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--descriptor", type=Path, help="use a new source-built image descriptor instead of building again")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--container", default=None)
    parser.add_argument("--port", type=int, default=8844)
    parser.add_argument("--expect-head")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--keep-runtime", action="store_true", help="retain successful disposable state for inspection")
    args = parser.parse_args(argv)
    repo, output = ROOT.resolve(), args.output_dir.resolve()
    source = checkout_identity(repo, args.expect_head)
    require(output != repo and repo not in output.parents, "Evidence directory must be outside the source checkout")
    require(not output.exists() and not output.is_symlink(), "Choose a new evidence directory")
    require(1 <= args.port <= 65535, "Invalid local port")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", args.port))
    container = args.container or "pqbtc-ci-" + args.compiler + "-" + uuid.uuid4().hex[:12]
    volume = require_fresh_namespace(container)
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": 1, "scope": "CLEAN_CHECKOUT_ASSEMBLED_SYSTEM", "result": "FAIL", "source": source,
              "compiler": args.compiler, "container": container, "volume": volume}
    events, process, candidate_pass = [], None, False
    log = (output / "assembled.log").open("x", encoding="utf8")

    def event(name, **details):
        print(name, flush=True)
        events.append({"step": name, "time": time.time(), **details})

    def command(values, timeout=300):
        event("command", argv=list(map(str, values)))
        result = subprocess.run(list(map(str, values)), stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        require(result.returncode == 0, "Command failed; inspect assembled.log: " + str(values))

    descriptor_path = output / "runtime-descriptor.json"
    state = output / "state"

    def app_command(autostart=False):
        values = [sys.executable, str(HERE / "app.py"), "--no-browser", "--compiler", args.compiler,
                  "--runtime-descriptor", str(descriptor_path), "--container", container,
                  "--state-dir", str(state), "--port", str(args.port)]
        return values if autostart else [*values, "--no-autostart"]

    def launch():
        event("launch_source_built_app")
        return subprocess.Popen(app_command(), stdout=log, stderr=subprocess.STDOUT)

    def stop_host():
        nonlocal process
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            require(process.wait(timeout=90) == 0, "Host app did not stop cleanly")
            process = None

    def cleanup():
        command(["docker", "rm", "--force", container], timeout=60)
        command(["docker", "volume", "rm", volume], timeout=60)
        event("owned_runtime_removed")

    try:
        if args.descriptor:
            descriptor = json.loads(args.descriptor.read_text())
        else:
            spec = importlib.util.spec_from_file_location("assembled_source_build", HERE / "source_build.py")
            builder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(builder)
            descriptor = builder.build_image(repo, compiler=args.compiler, no_cache=args.no_cache,
                                             progress=lambda message: event("build_progress", message=message))
        require_descriptor_source(descriptor, source["head"], args.compiler)
        require(descriptor["manifest"].get("source_tree") == source["tree"], "Runtime source tree does not match this checkout")
        write_json(descriptor_path, descriptor)
        report["runtime_descriptor"] = descriptor
        exported = subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                                   "--security-opt", "no-new-privileges", "--user", "1001:1000", "--cpus", "4", "--memory", "4294967296",
                                   descriptor["image"], "tar", "-C", "/opt/pqbtc-runtime/evidence", "-cf", "-", "."],
                                  capture_output=True, timeout=120)
        require(exported.returncode == 0, "Could not export public native build/test evidence")
        validate_native_evidence(exported.stdout, descriptor["manifest"])
        (output / "native-evidence.tar").write_bytes(exported.stdout)
        event("native_build_evidence_verified")
        console = Console(args.port, event)
        process = launch()
        first = console.wait(process)
        require(first["phase"] == "stopped" and first["wallet"].get("wallet_id") is None,
                "First install unexpectedly inherited a wallet")
        event("fresh_install_has_no_wallet")
        command([sys.executable, HERE / "test_end_to_end.py", "--url", console.url,
                 "--output", output / "flow.json"], timeout=600)
        flow = json.loads((output / "flow.json").read_text())
        require(flow.get("result") == "PASS", "Real HTTP spend/recovery flow did not pass")
        baseline = flow["final_status"]
        require_state(console.action("start")["status"], baseline)
        issued = console.action("receive")["result"]
        baseline = console.status()
        console.action("stop")
        stop_host()
        command(["docker", "stop", "--timeout", "30", container], timeout=60)
        old_container = subprocess.check_output(["docker", "inspect", "--format", "{{.Id}}", container], text=True,encoding="utf8").strip()
        command(["docker", "rm", container], timeout=60)
        process = launch()
        console.wait(process)
        resumed = console.action("start")["status"]
        require_state(resumed, baseline)
        new_container = subprocess.check_output(["docker", "inspect", "--format", "{{.Id}}", container], text=True,encoding="utf8").strip()
        require(old_container != new_container, "Container recreation was not exercised")
        event("host_and_container_recreation_pass", old_container_id=old_container, new_container_id=new_container)
        command(["docker", "kill", container], timeout=60)
        command(["docker", "rm", container], timeout=60)
        command(app_command(autostart=True), timeout=300)
        require_state(console.status(), baseline)
        destination = console.action("receive")["result"]
        require(destination["index"] > issued["index"], "Forced recreation reused an issued address")
        event("forced_container_recreation_pass")
        sent = console.action("send", {"address": destination["address"], "amount_sats": 100000, "fee_sats": 1000})["result"]
        console.action("mine", {"blocks": 1})
        final = console.status()
        require(final["wallet"]["wallet_id"] == baseline["wallet"]["wallet_id"] and
                final["wallet"]["spendable_sats"] == baseline["wallet"]["spendable_sats"] - 1000,
                "Post-recreation spend did not preserve wallet/balance")
        require_state(final, final)
        console.action("stop")
        stop_host()
        require(checkout_identity(repo, source["head"]) == source, "Source changed during assembled tests")
        report.update(final_status=final, post_recreation_txid=sent["txid"], flow_result=flow["result"])
        candidate_pass = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            stop_host()
        except Exception as error:
            candidate_pass = False
            report["host_cleanup_error"] = str(error)
        try:
            finish_report(output, report, events, candidate_pass=candidate_pass,
                          cleanup=None if args.keep_runtime else cleanup)
        finally:
            log.close()
    require(report["result"] == "PASS", "Assembled run or host cleanup failed")
    print("CLEAN_CHECKOUT_ASSEMBLED_SYSTEM_PASS", flush=True)


if __name__ == "__main__":
    main()
