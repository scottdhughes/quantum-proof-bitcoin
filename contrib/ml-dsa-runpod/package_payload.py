#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Export a qualified native build as a pinned, credential-free Runpod payload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile


VERSIONS = {
    "a3": ("a4777f3beabc0f1d67e4c340dff1bca522446d3f", "270db235c95ccf367fae9add30aa48244a4ab6a0"),
    "c": ("872da133db255e2188f74ebc5164ecbca620ee6e", "09adc01686c11ad83ac275e881af02b77d12b963"),
}
GATES = {
    "integration-normal", "integration-asan-ubsan", "signer-normal", "signer-asan-ubsan",
    "key-lifecycle-normal-and-sanitized", "node-profile-and-resource-units",
    "actual-node-spend-old-record-restore", "actual-public-accepted-set-and-both-reindex-paths",
    "actual-node-30-full-blocks-and-mempool-pressure",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    with Path(path).open("x", encoding="utf8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


def validate_provenance(version, descriptor, report, manifest_bytes, *, expected_architecture="x86_64"):
    require(version in VERSIONS, "Unknown pinned payload version")
    head, tree = VERSIONS[version]
    require(type(descriptor) is dict and descriptor.get("schema") == "PQBTC-MLDSA44-SOURCE-RUNTIME-1",
            "Invalid build descriptor")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor.get("image", "")), "Invalid build image")
    manifest = json.loads(manifest_bytes)
    require(descriptor.get("manifest") == manifest and descriptor.get("manifest_sha256") ==
            hashlib.sha256(manifest_bytes).hexdigest(), "Build manifest differs")
    require(manifest.get("source_head") == head and manifest.get("source_tree") == tree,
            "Payload source differs from frozen version")
    require(expected_architecture in ("x86_64", "aarch64"), "Unsupported native architecture")
    normalize = {"amd64": "x86_64", "arm64": "aarch64"}
    require(normalize.get(manifest.get("architecture"), manifest.get("architecture")) == expected_architecture and
            manifest.get("compiler") == "gcc", "Payload native architecture or compiler differs")
    require(type(report) is dict and report.get("schema") == "PQBTC-MLDSA44-NATIVE-QUALIFICATION-1" and
            report.get("result") == "PASS" and
            report.get("checks") == dict.fromkeys(GATES, "PASS"), "All nine native gates must pass")
    # Report identity field names are defined by the existing frozen qualifier.
    require(report.get("source") == {"head": head, "tree": tree} and
            report.get("image") == descriptor["image"], "Qualification source or image differs")
    before = report.get("identity_before")
    require(report.get("architecture") == expected_architecture and report.get("emulated") is False and
            type(before) is dict and before.get("head") == head and before.get("tree") == tree and
            type(before.get("sha256")) is dict and before["sha256"] and
            before == report.get("identity_after"),
            "Qualification native identity differs")
    critical = {"/tmp/mldsa-demo-build/bin/pqbtcd", "/tmp/mldsa-demo-build/bin/pqbtc-mldsa-client",
                "/tmp/demo-signer-bin/pilot-signer"}
    require(critical <= set(before["sha256"]) and report.get("compiler") == "gcc" and
            report.get("public_soak") is False and report.get("production_admitted") is False,
            "Qualification critical native identity or scope differs")
    require(report.get("cleanup") == "REMOVED" and report.get("manifest_sha256") == descriptor["manifest_sha256"] and
            all(manifest["sha256"].get(path) == expected for path, expected in before["sha256"].items()),
            "Qualification cleanup or binary hashes differ")
    return manifest


def extract_regular(archive, destination):
    """Accept only a flat regular-file/directory closure from the build image."""
    destination = Path(destination)
    seen, total = set(), 0
    with tarfile.open(archive) as source:
        for member in source:
            path = Path(member.name)
            require(member.name not in seen and not path.is_absolute() and ".." not in path.parts,
                    "Unsafe or duplicate payload archive path")
            seen.add(member.name)
            require(len(seen) <= 20000, "Payload archive has too many members")
            require(path.parts and path.parts[0] in ("seed", "manifest.json"), "Unexpected image export member")
            require(member.isdir() or member.isfile(), "Payload links and special files are refused")
            target = destination / path
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            else:
                require(member.size <= 256 * 1024 * 1024, "Payload member is too large")
                total += member.size
                require(total <= 2 * 1024 * 1024 * 1024, "Payload archive exceeds its total bound")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                stream = source.extractfile(member)
                require(stream is not None, "Payload member cannot be read")
                with target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                os.chmod(target, 0o555 if member.mode & 0o111 else 0o444)


def package(version, runtime, build_descriptor, report_path, output, *, expected_architecture="x86_64"):
    runtime, output = Path(runtime), Path(output)
    require(not output.exists() and not output.is_symlink(), "Output already exists")
    descriptor = json.loads(Path(build_descriptor).read_text())
    report = json.loads(Path(report_path).read_text())
    raw = (runtime / "manifest.json").read_bytes()
    manifest = validate_provenance(version, descriptor, report, raw, expected_architecture=expected_architecture)
    seed = runtime / "seed"
    require(seed.is_dir() and not seed.is_symlink(), "Payload seed is missing")
    files = {}
    for path in sorted(seed.rglob("*")):
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "Payload symlinks and special files are refused")
        if stat.S_ISREG(mode):
            files[str(path.relative_to(runtime))] = digest(path)
    require(files, "Empty payload refused")
    for original, expected in manifest["sha256"].items():
        require(original.startswith("/tmp/"), "Unexpected original build path")
        require(files.get("seed/" + original.removeprefix("/tmp/")) == expected,
                "Critical payload file differs from build manifest")
    payload = {"schema": "PQBTC-RUNPOD-PAYLOAD-1", "version": version,
               "source_head": manifest["source_head"], "source_tree": manifest["source_tree"],
               "manifest_sha256": descriptor["manifest_sha256"], "files": files}
    output.mkdir(mode=0o755, parents=True)
    version_dir = output / version
    version_dir.mkdir(mode=0o755)
    shutil.copytree(seed, version_dir / "seed")
    (version_dir / "manifest.json").write_bytes(raw)
    write_json(version_dir / "descriptor.json", payload)
    write_json(version_dir / "build-descriptor.json", descriptor)
    write_json(version_dir / "native-qualification.json", report)
    # Deployment is an immutable code payload. Custody/state is never exported.
    for path in version_dir.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o555 if path.stat().st_mode & 0o111 else 0o444)
    archive = output / (version + "-payload.tar.gz")
    with tarfile.open(archive, "w:gz", compresslevel=3) as tar:
        for path in [version_dir, *sorted(version_dir.rglob("*"))]:
            info = tar.gettarinfo(str(path), str(path.relative_to(output)))
            require(info.isdir() or info.isfile(), "Unexpected archive file type")
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = 0o555 if info.isdir() or info.mode & 0o111 else 0o444
            if info.isfile():
                with path.open("rb") as stream:
                    tar.addfile(info, stream)
            else:
                tar.addfile(info)
    write_json(output / "payload-receipt.json", {"schema": "PQBTC-RUNPOD-PAYLOAD-EXPORT-1",
               "version": version, "source_head": manifest["source_head"], "source_tree": manifest["source_tree"],
               "archive": archive.name, "archive_sha256": digest(archive),
               "descriptor_sha256": digest(version_dir / "descriptor.json"), "files": len(files),
               "build_image": descriptor["image"], "native_qualification": "PASS",
               "scope": "QUALIFIED_BUILD_PAYLOAD_NOT_RUNPOD_DEPLOYMENT_QUALIFICATION"})
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=VERSIONS, required=True)
    parser.add_argument("--build-descriptor", type=Path, required=True)
    parser.add_argument("--qualification-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    descriptor = json.loads(args.build_descriptor.read_text())
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor.get("image", "")), "Invalid build image")
    with tempfile.TemporaryDirectory(prefix="pqbtc-runpod-export-") as directory:
        temporary = Path(directory)
        with (temporary / "runtime.tar").open("xb") as out, (temporary / "export.stderr").open("xb") as err:
            result = subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                                     "--security-opt", "no-new-privileges", descriptor["image"], "tar", "--dereference", "--hard-dereference",
                                     "-C", "/opt/pqbtc-runtime", "-cf", "-", "seed", "manifest.json"],
                                    stdout=out, stderr=err, timeout=240)
            require(result.returncode == 0, "Build payload export failed; no deployment payload emitted")
        runtime = temporary / "runtime"
        runtime.mkdir()
        extract_regular(temporary / "runtime.tar", runtime)
        package(args.version, runtime, args.build_descriptor, args.qualification_report, args.output)
    print("Qualified native payload exported: " + str(args.output))


if __name__ == "__main__":
    main()
