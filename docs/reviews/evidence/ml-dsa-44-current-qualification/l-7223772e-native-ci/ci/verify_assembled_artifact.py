#!/usr/bin/env python3
"""Read only selected public qualification reports from a verified Actions ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def pairs(values):
    result = {}
    for key, value in values:
        need(key not in result, "Duplicate JSON member")
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


SELECTED = ("report.json", "runtime-descriptor.json", "native-qualification/report.json",
            "public-profile-app/report.json")


def verify(args):
    need(args.zip.is_file() and not args.zip.is_symlink(), "Regular ZIP required")
    need(0 < args.zip_bytes <= 8 * 1024**3 and args.zip.stat().st_size == args.zip_bytes,
         "Artifact ZIP size mismatch")
    need(re.fullmatch(r"[0-9a-f]{64}", args.zip_sha256) and digest(args.zip) == args.zip_sha256,
         "Artifact ZIP SHA mismatch")
    need(not args.output.exists() and not args.output.is_symlink(), "New report destination required")
    raw, values = {}, {}
    with zipfile.ZipFile(args.zip) as archive:
        infos = archive.infolist()
        need(len(infos) <= 10000, "Too many ZIP members")
        names = set()
        for member in infos:
            path = PurePosixPath(member.filename)
            need(member.filename not in names and not path.is_absolute() and ".." not in path.parts and
                 "\\" not in member.filename and not stat.S_ISLNK(member.external_attr >> 16),
                 "Unsafe or duplicate ZIP member")
            names.add(member.filename)
        need(set(SELECTED) <= names, "Required public reports absent")
        for name in SELECTED:
            member = archive.getinfo(name)
            need(not member.is_dir() and 0 < member.file_size <= 8 * 1024**2,
                 "Report size or type refused")
            raw[name] = archive.read(member)
            need(len(raw[name]) == member.file_size, "Truncated public report")
            values[name] = parsed(raw[name])
    assembled, descriptor = values["report.json"], values["runtime-descriptor.json"]
    native, app = values["native-qualification/report.json"], values["public-profile-app/report.json"]
    source = {"head": args.head, "tree": args.tree}
    manifest = descriptor["manifest"]
    image = descriptor["image"]
    need(descriptor["schema"] == "PQBTC-MLDSA44-SOURCE-RUNTIME-1" and
         re.fullmatch(r"sha256:[0-9a-f]{64}", image), "Source descriptor refused")
    need(manifest["source_head"] == args.head and manifest["source_tree"] == args.tree and
         manifest["compiler"] == args.compiler and manifest["architecture"] in ("x86_64", "amd64"),
         "Descriptor source/compiler/architecture mismatch")
    need(assembled["result"] == "PASS" and assembled["source"] == source and
         assembled["compiler"] == args.compiler and assembled["runtime_descriptor"] == descriptor and
         assembled["flow_result"] == "PASS", "Assembled app qualification missing or mismatched")
    need(native["result"] == "PASS" and native["source"] == source and
         native["compiler"] == args.compiler and native["image"] == image and
         native["manifest_sha256"] == descriptor["manifest_sha256"] and
         native["architecture"] in ("x86_64", "amd64") and native["emulated"] is False and
         native["cleanup"] == "REMOVED" and native["production_admitted"] is False,
         "Native qualification missing or mismatched")
    need(len(native["checks"]) == 9 and all(result == "PASS" for result in native["checks"].values()),
         "Nine native gates must pass")
    for name in ("identity_before", "identity_after"):
        identity = native[name]
        need(identity["head"] == args.head and identity["tree"] == args.tree and
             all(manifest["sha256"].get(path) == checksum for path, checksum in identity["sha256"].items()),
             "Native source/binary identity changed")
    need(native["identity_before"] == native["identity_after"], "Native before/after identity differs")
    need(app["result"] == "PASS" and app["source_head"] == args.head and app["source_tree"] == args.tree and
         app["image"] == image and app["manifest_sha256"] == descriptor["manifest_sha256"] and
         app["clean_source_qualified"] is True and app["cleanup_errors"] == [],
         "Public-profile app flow missing or mismatched")
    args.output.mkdir(mode=0o700, parents=True)
    for name, content in raw.items():
        path = args.output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    receipt = {"schema": "PQBTC-ASSEMBLED-PUBLIC-REPORTS-VERIFICATION-1", "result": "PASS",
               "run_id": args.run_id, "artifact_id": args.artifact_id, "compiler": args.compiler,
               "source": source, "image": image, "zip_sha256": args.zip_sha256, "zip_bytes": args.zip_bytes,
               "reports": {name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                           for name, content in raw.items()},
               "native_binary_sha256": native["identity_before"]["sha256"],
               "native_code_loaded_or_executed": False,
               "scope": "EXACT_SOURCE_LINUX_X86_64_QUALIFICATION_AND_PRIVATE_APP_FLOW_NOT_PUBLIC_SOAK"}
    with (args.output / "verified-reports.json").open("x", encoding="utf8") as handle:
        json.dump(receipt, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--zip-bytes", type=int, required=True)
    parser.add_argument("--zip-sha256", required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--compiler", choices=("gcc", "clang"), required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    verify(parser.parse_args())
