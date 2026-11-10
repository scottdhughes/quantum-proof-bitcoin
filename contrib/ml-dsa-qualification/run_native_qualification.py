#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Qualify an exact source-built native Linux image in a fresh offline container.

Only public disposable fixtures are used. This host runs Python orchestration;
all native code executes in the isolated Linux image. The result is platform
qualification, never production admission or evidence of an elapsed public soak.
"""
import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = "/tmp/mldsa-demo-source"
BUILD = "/tmp/mldsa-demo-build"
OPENSSL = "/opt/pqbtc-runtime/dependencies/openssl"
TMPFS = {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write("\n")


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


def inspect_runtime(container):
    template = ('{"image":{{json .Image}},"ro":{{json .HostConfig.ReadonlyRootfs}},'
                '"network":{{json .HostConfig.NetworkMode}},"memory":{{json .HostConfig.Memory}},'
                '"cpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},'
                '"drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
                '"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}')
    return json.loads(subprocess.check_output(["docker", "inspect", "--format", template, container], timeout=30))


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


def validate_component_report(value, head, architecture, sanitized):
    require(type(value) is dict and value.get("result") == "PASS" and value.get("sanitized") is sanitized,
            "Native component result or instrumentation class is incomplete")
    require(normalize_architecture(value.get("architecture")) == architecture,
            "Native component architecture differs from the qualified process")
    identity = {"commit": head, "worktree": "clean"}
    require(value.get("runtime_before") == identity and value.get("runtime_after") == identity,
            "Native component source identity was not clean and stable")


def finish_report(output, report, *, candidate_pass, cleanup=None):
    try:
        if cleanup is not None:
            cleanup()
        report["result"] = "PASS" if candidate_pass else "FAIL"
    except BaseException as error:
        report["result"] = "FAIL"
        report["cleanup_error"] = str(error)
        raise
    finally:
        write_json(output / "report.json", report)


def main(argv=None):
    require(__debug__, "Optimized Python is not permitted for qualification evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path, help="reuse an exact source image instead of building again")
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--expect-head", required=True)
    parser.add_argument("--expect-architecture", choices=("x86_64", "amd64", "aarch64", "arm64"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--container", default="pqbtc-native-" + uuid.uuid4().hex[:16])
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--keep-runtime", action="store_true", help="retain the stopped disposable container for diagnosis")
    args = parser.parse_args(argv)
    require(re.fullmatch(r"[0-9a-f]{40}", args.expect_head), "Expected source must be a full commit SHA")
    require(re.fullmatch(r"pqbtc-native-[a-z0-9][a-z0-9_.-]{0,70}", args.container),
            "Use a fresh pqbtc-native-* namespace; existing user wallets cannot be targeted")
    console = ROOT / "contrib/ml-dsa-console"
    source_build = load(console / "source_build.py", "qualification_source_build")
    source_runtime = load(console / "source_runtime.py", "qualification_source_runtime")
    assembled = load(console / "run_assembled_ci.py", "qualification_assembled_helpers")
    source = assembled.checkout_identity(ROOT, args.expect_head)
    output = args.output_dir.resolve()
    require(output != ROOT and ROOT not in output.parents and not output.exists() and not output.is_symlink(),
            "Choose a new evidence directory outside the checkout")
    require(subprocess.run(["docker", "container", "inspect", args.container], capture_output=True, timeout=30).returncode != 0,
            "Qualification container already exists; choose a new namespace")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1", "result": "FAIL",
              "scope": "NATIVE_PLATFORM_QUALIFICATION_ONLY", "production_admitted": False,
              "public_soak": False, "source": source, "compiler": args.compiler,
              "container": args.container, "checks": {},
              "instrumentation_scope": {"contract_backend_and_signer": "normal plus ASan/UBSan",
                                         "key_lifecycle": "normal plus ASan/UBSan with entropy/fault controls",
                                         "node": "release build; resource timings exclude fixture generation",
                                         "openssl": "pinned static library; not instrumented by this run"}}
    started, candidate_pass = False, False
    transcript = (output / "commands.jsonl").open("x", encoding="utf8")
    command_serial = 0

    def command(values, *, user=None, timeout=120, data=None, name=None):
        nonlocal command_serial
        command_serial += 1
        diagnostic_name = name or f"command-{command_serial:03d}"
        values = list(map(str, values))
        if user is not None:
            values = ["docker", "exec", "-i", "--user", user,
                      "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "OPENSSL_CONF=/dev/null",
                      "--env", "OPENSSL_MODULES=/nonexistent", "--env", "GIT_CONFIG_COUNT=1",
                      "--env", "GIT_CONFIG_KEY_0=safe.directory", "--env", "GIT_CONFIG_VALUE_0=" + SOURCE,
                      args.container, *values]
        entry = {"argv": values, "started_unix": time.time()}
        try:
            result = subprocess.run(values, input=data, capture_output=True, timeout=timeout)
        except BaseException as error:
            entry.update({"error": str(error), "finished_unix": time.time()})
            transcript.write(json.dumps(entry) + "\n")
            transcript.flush()
            raise
        entry.update({"returncode": result.returncode, "finished_unix": time.time(),
                      "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                      "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        transcript.write(json.dumps(entry) + "\n")
        transcript.flush()
        (output / (diagnostic_name + ".stdout")).write_bytes(result.stdout)
        (output / (diagnostic_name + ".stderr")).write_bytes(result.stderr)
        require(result.returncode == 0, "Qualification command failed; inspect " + str(output / diagnostic_name))
        return result.stdout

    def source_identity():
        script = ("import hashlib,json,pathlib,subprocess,sys; p=pathlib.Path(sys.argv[1]);"
                  "g=['git','-c','safe.directory='+str(p),'-C',str(p)];"
                  "head=subprocess.check_output(g+['rev-parse','HEAD'],text=True).strip();"
                  "tree=subprocess.check_output(g+['rev-parse','HEAD^{tree}'],text=True).strip();"
                  "dirty=subprocess.check_output(g+['status','--porcelain=v1','--untracked-files=all']);"
                  "assert not dirty; paths=[pathlib.Path(x) for x in sys.argv[2:]];"
                  "print(json.dumps({'head':head,'tree':tree,'sha256':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths}}))")
        return json.loads(command(["python3", "-c", script, SOURCE,
                                   BUILD + "/bin/pqbtcd", BUILD + "/bin/pqbtc-cli", BUILD + "/bin/pqbtc-mldsa-client",
                                   BUILD + "/bin/test_pqbtc", "/tmp/demo-signer-bin/pilot-signer",
                                   SOURCE + "/contrib/ml-dsa-qualification/run_native_qualification.py",
                                   SOURCE + "/contrib/ml-dsa-qualification/run_spend_restore.py",
                                   SOURCE + "/contrib/ml-dsa-qualification/public_consensus_controls.py"], user="1001:1000"))

    def cleanup():
        if started:
            command(["docker", "stop", "--time", "30", args.container], timeout=45, name="cleanup-stop")
            if not args.keep_runtime:
                command(["docker", "rm", args.container], timeout=30, name="cleanup-remove")
            report["cleanup"] = "STOPPED_RETAINED" if args.keep_runtime else "REMOVED"

    def collect_partial_evidence():
        # Read only declared public-fixture diagnostics. Never archive the
        # signer custody directories or replace a primary failure with a skip.
        paths = (("/tmp/mldsa-resource-fixture-qualification/resource-results.json", "partial-node-resources.json"),
                 ("/tmp/mldsa-resource-fixture-qualification/node/process.log", "partial-resource-node.log"),
                 ("/tmp/mldsa-public-consensus-qualification/public-consensus-results.json", "partial-public-consensus.json"),
                 ("/tmp/mldsa-public-consensus-qualification/node/process.log", "partial-public-consensus-node.log"),
                 ("/tmp/mldsa-public-consensus-qualification/node/mldsa44-test-v1/debug.log", "partial-public-consensus-debug.log"),
                 ("/tmp/qualification-key-lifecycle/key-lifecycle-report.json", "partial-key-lifecycle.json"))
        if started and not candidate_pass:
            for path, name in paths:
                values = ["docker", "exec", "--user", "1000:1000" if "/qualification-key-lifecycle/" in path else "1001:1000",
                          args.container, "cat", path]
                result = subprocess.run(values, capture_output=True, timeout=30)
                transcript.write(json.dumps({"argv": values, "returncode": result.returncode,
                                             "diagnostic_collection": True}) + "\n")
                if result.returncode == 0:
                    (output / name).write_bytes(result.stdout)
            transcript.flush()

    try:
        descriptor = (source_runtime.load_descriptor(args.descriptor) if args.descriptor else
                      source_build.build_image(ROOT, args.compiler, no_cache=args.no_cache))
        descriptor = source_runtime.validate_descriptor(descriptor)
        assembled.require_descriptor_source(descriptor, source["head"], args.compiler)
        require(descriptor["manifest"]["source_tree"] == source["tree"], "Source image tree differs from the checkout")
        write_json(output / "runtime-descriptor.json", descriptor)
        image = descriptor["image"]
        report["image"] = image
        report["manifest_sha256"] = descriptor["manifest_sha256"]
        actual_manifest = command(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                                   "--security-opt", "no-new-privileges", image, "cat", "/opt/pqbtc-runtime/manifest.json"])
        require(hashlib.sha256(actual_manifest).hexdigest() == descriptor["manifest_sha256"],
                "Actual source image manifest differs from its descriptor")
        command(["docker", "run", "--detach", "--name", args.container, "--network", "none", "--read-only",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "4g",
                 "--pids-limit", "512", "--ulimit", "memlock=8388608:8388608", "--tmpfs", "/tmp:" + TMPFS["/tmp"],
                 image, "sleep", "infinity"], timeout=60)
        started = True
        runtime = inspect_runtime(args.container)
        validate_runtime(runtime, image)
        report["runtime"] = runtime
        # These public source/binary copies need their bytes and modes, not the
        # build UIDs. CAP_CHOWN stays absent throughout qualification.
        command(["cp", "-a", "--no-preserve=ownership", "/opt/pqbtc-runtime/seed/.", "/tmp/"],
                user="0:0", timeout=180, name="hydrate-public-seed")
        command(["chmod", "1777", "/tmp"], user="0:0")
        container_arch = command(["uname", "-m"], user="1001:1000").decode().strip()
        vm_arch = command(["docker", "info", "--format", "{{.Architecture}}"]).decode().strip()
        architecture = validate_native_identity(args.expect_architecture, container_arch, vm_arch,
                                                descriptor["manifest"]["architecture"])
        report["architecture"] = architecture
        report["docker_vm_architecture"] = vm_arch
        report["emulated"] = False
        before = source_identity()
        require((before["head"], before["tree"]) == (source["head"], source["tree"]),
                "Contained checkout differs from the requested exact source")
        for relative in ("run_native_qualification.py", "run_spend_restore.py", "public_consensus_controls.py"):
            require(before["sha256"][SOURCE + "/contrib/ml-dsa-qualification/" + relative] ==
                    hashlib.sha256((HERE / relative).read_bytes()).hexdigest(), "Host/contained qualification code differs")
        for path, digest in before["sha256"].items():
            if path in descriptor["manifest"]["sha256"]:
                require(digest == descriptor["manifest"]["sha256"][path], "Built binary differs from its source receipt")
        report["identity_before"] = before

        dependencies = descriptor["manifest"].get("qualification_dependencies_sha256")
        validate_dependency_inventory(dependencies)
        dependency_script = ("import hashlib,json,pathlib,sys; base=pathlib.Path('/opt/pqbtc-runtime');"
                             "expected=json.load(sys.stdin); actual={name:hashlib.sha256((base/name).read_bytes()).hexdigest() "
                             "for name in expected}; assert actual==expected; print(json.dumps(actual,sort_keys=True))")
        observed_dependencies = json.loads(command(["python3", "-c", dependency_script], user="1000:1000",
                                                   data=json.dumps(dependencies).encode(), name="qualification-dependencies"))
        report["qualification_dependencies_sha256"] = observed_dependencies

        cc, cxx = args.compiler, "g++" if args.compiler == "gcc" else "clang++"
        for sanitized in (False, True):
            mode = "asan-ubsan" if sanitized else "normal"
            for component, script in (("integration", "ml-dsa-integration/run_native_tests.py"),
                                      ("signer", "ml-dsa-signer/run_signer_tests.py")):
                flags = ["--cc", cc, "--cxx", cxx, "--expect-head", source["head"]]
                if sanitized:
                    flags.append("--sanitize")
                if component == "signer":
                    flags += ["--openssl-prefix", OPENSSL, "--build-dir", "/tmp/qualification-signer-" + mode]
                name = component + "-" + mode
                raw = command(["python3", SOURCE + "/contrib/" + script, *flags],
                              user="1000:1000", timeout=900, name=name)
                value = json.loads(raw)
                validate_component_report(value, source["head"], architecture, sanitized)
                write_json(output / (name + ".json"), value)
                report["checks"][name] = "PASS"

        lifecycle_dir = "/tmp/qualification-key-lifecycle"
        command(["python3", SOURCE + "/contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py", "--cc", cc,
                 "--expect-commit", source["head"], "--output-dir", lifecycle_dir],
                user="1000:1000", timeout=900, name="key-lifecycle")
        lifecycle = json.loads(command(["cat", lifecycle_dir + "/key-lifecycle-report.json"], user="1000:1000"))
        require(lifecycle.get("result") == "PASS" and lifecycle.get("trust") == "EXACT_CLEAN_CHECKOUT" and
                lifecycle.get("runtime") == {"commit": source["head"], "worktree": "clean"} and
                normalize_architecture(lifecycle.get("platform", {}).get("machine")) == architecture,
                "Exact-source native lifecycle qualification did not complete")
        archive = command(["tar", "-C", lifecycle_dir, "-cf", "-", "."], user="1000:1000", timeout=60)
        (output / "key-lifecycle-evidence.tar").write_bytes(archive)
        write_json(output / "key-lifecycle.json", lifecycle)
        report["checks"]["key-lifecycle-normal-and-sanitized"] = "PASS"

        command([BUILD + "/bin/test_pqbtc", "--run_test=mldsa44_node_tests,mldsa44_public_tests,mldsa44_resource_tests",
                 "--report_level=short"], user="1001:1000", timeout=300, name="node-unit")
        report["checks"]["node-profile-and-resource-units"] = "PASS"
        command([sys.executable, HERE / "run_spend_restore.py", "--container", args.container,
                 "--expect-head", source["head"], "--expect-image", image,
                 "--expect-architecture", architecture], timeout=900, name="node-spend-restore")
        spend_raw = (output / "node-spend-restore.stdout").read_bytes()
        require(spend_raw.endswith(b"MLDSA_CURRENT_SOURCE_SPEND_RESTORE_TERMINAL_EXIT_0\n"),
                "Actual spend/old-record restore did not reach its terminal result")
        report["checks"]["actual-node-spend-old-record-restore"] = "PASS"

        consensus_dir = "/tmp/mldsa-public-consensus-qualification"
        command(["python3", SOURCE + "/contrib/ml-dsa-qualification/public_consensus_controls.py",
                 "--binary", BUILD + "/bin/pqbtcd", "--cc", cc, "--work-dir", consensus_dir],
                user="1001:1000", timeout=300, name="public-consensus-controls")
        consensus = json.loads(command(["cat", consensus_dir + "/public-consensus-results.json"], user="1001:1000"))
        consensus_driver = load(HERE / "public_consensus_controls.py", "qualification_public_consensus")
        consensus_driver.validate_report(consensus)
        require(consensus.get("binary_sha256") == before["sha256"][BUILD + "/bin/pqbtcd"],
                "Public consensus controls tested a different node binary")
        write_json(output / "public-consensus-controls.json", consensus)
        diagnostics = consensus.get("diagnostic_sha256")
        require(type(diagnostics) is dict and diagnostics and all(type(name) is str and
                re.fullmatch(r"[A-Za-z0-9_./-]+\.log", name) and ".." not in Path(name).parts and
                not name.startswith("/") and consensus_driver.digest(digest) for name, digest in diagnostics.items()),
                "Public consensus diagnostic inventory is unsafe or incomplete")
        for name, digest in diagnostics.items():
            raw = command(["cat", consensus_dir + "/" + name], user="1001:1000")
            require(hashlib.sha256(raw).hexdigest() == digest, "Public consensus diagnostic hash differs")
            target = output / "public-consensus-diagnostics" / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
        report["checks"]["actual-public-accepted-set-and-both-reindex-paths"] = "PASS"

        resource_dir = "/tmp/mldsa-resource-fixture-qualification"
        command(["python3", SOURCE + "/test/functional/feature_mldsa44_resources.py", "--binary", BUILD + "/bin/pqbtcd",
                 "--cc", cc, "--samples", "30", "--timing-class", "release", "--work-dir", resource_dir],
                user="1001:1000", timeout=1200, name="node-resources")
        resource = json.loads(command(["cat", resource_dir + "/resource-results.json"], user="1001:1000"))
        validate_resource_report(resource)
        require(resource.get("binary_sha256") == before["sha256"][BUILD + "/bin/pqbtcd"],
                "Resource workload tested a different node binary")
        write_json(output / "node-resources.json", resource)
        report["checks"]["actual-node-30-full-blocks-and-mempool-pressure"] = "PASS"

        after = source_identity()
        require(before == after, "Source or native binaries changed during qualification")
        require(assembled.checkout_identity(ROOT, args.expect_head) == source, "Host source changed during qualification")
        validate_runtime(inspect_runtime(args.container), image)
        report["identity_after"] = after
        candidate_pass = True
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            try:
                collect_partial_evidence()
            except (OSError, subprocess.SubprocessError) as error:
                report["diagnostic_collection_error"] = str(error)
                candidate_pass = False
            finish_report(output, report, candidate_pass=candidate_pass, cleanup=cleanup)
        finally:
            transcript.close()
            hashes = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(output.rglob("*")) if p.is_file()}
            write_json(output / "evidence-sha256.json", hashes)
    require(report["result"] == "PASS", "Qualification report is FAIL; inspect retained evidence")
    print("Native platform qualification PASS: " + str(output / "report.json"), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Native qualification failed: " + str(error)) from error
