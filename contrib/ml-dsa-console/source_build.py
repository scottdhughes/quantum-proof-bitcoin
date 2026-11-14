#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Build the experimental Linux runtime from an exact clean source checkout.

Only tracked source objects enter the Docker context. Its generated shallow Git
metadata contains no user configuration, credentials, remotes, or prior history.
Native compilation and tests execute inside Linux, never on the host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
DESCRIPTOR_SCHEMA = "PQBTC-MLDSA44-SOURCE-RUNTIME-1"
MANIFEST_SCHEMA = "PQBTC-MLDSA44-SOURCE-BUILD-1"


class BuildError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise BuildError(message)


def git(repo, *args, data=None):
    result = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True)
    require(result.returncode == 0, "Source Git operation failed: " + result.stderr[:500].decode("utf8", "replace"))
    return result.stdout


def allowed_source(name):
    parts = PurePosixPath(name).parts
    require(parts and not PurePosixPath(name).is_absolute() and all(part not in ("..", ".git") for part in parts),
            "Unsafe tracked source path")
    denied = {"credentials", "credentials.json", "id_rsa", "id_ed25519", "id_dsa", "wallet.dat", ".ssh"}
    require(not any(part.lower() in denied or part.lower() == ".env" or part.lower().startswith(".env.")
                    for part in parts), "Refusing sensitive named path in source export")


def bounded_source_symlinks(links):
    """Resolve tracked link chains logically, without consulting outside files."""
    for name in links:
        pending, resolved, hops = list(PurePosixPath(name).parts), [], 0
        while pending:
            part, pending = pending[0], pending[1:]
            if part == ".":
                continue
            if part == "..":
                require(resolved, "Escaping source symlink refused")
                resolved.pop()
                continue
            candidate = "/".join([*resolved, part])
            if candidate in links:
                hops += 1
                target = links[candidate]
                require(hops <= 40 and len(target.encode("utf8")) <= 4096 and "\0" not in target and
                        not PurePosixPath(target).is_absolute(), "External or cyclic source symlink refused")
                pending = [*PurePosixPath(target).parts, *pending]
            else:
                resolved.append(part)


def normalize_export_permissions(destination, modes):
    """Make only the new public checkout readable; never follow source links."""
    def walk(directory, relative):
        os.fchmod(directory, 0o755)
        with os.scandir(directory) as entries:
            for entry in entries:
                name = relative / entry.name
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    require(modes.get(name.as_posix()) == "120000", "Unexpected source export symlink")
                    continue
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if stat.S_ISDIR(info.st_mode):
                    flags |= os.O_DIRECTORY
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Unexpected source export file type")
                fd = os.open(entry.name, flags, dir_fd=directory)
                try:
                    actual = os.fstat(fd)
                    require((actual.st_dev, actual.st_ino, actual.st_mode) == (info.st_dev, info.st_ino, info.st_mode),
                            "Source export entry changed during permission normalization")
                    if stat.S_ISDIR(actual.st_mode):
                        walk(fd, name)
                    else:
                        tracked = modes.get(name.as_posix())
                        require(name.parts[0] == ".git" or tracked in ("100644", "100755"), "Unexpected source export member")
                        os.fchmod(fd, 0o755 if tracked == "100755" else 0o644)
                finally:
                    os.close(fd)
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(directory, PurePosixPath())
    finally:
        os.close(directory)


def stage_source(repo, destination):
    """Export HEAD and only its reachable tree into a new self-contained checkout."""
    repo, destination = Path(repo).resolve(), Path(destination)
    require(not destination.exists() and not destination.is_symlink(), "Source export destination already exists")
    require(not git(repo, "status", "--porcelain=v1", "--untracked-files=all"),
            "Source build requires a clean committed checkout; retain local work and build a separate clean snapshot")
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", head) and re.fullmatch(r"[0-9a-f]{40}", tree), "Unsupported source object identity")
    entries = git(repo, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0")
    modes, links = {}, {}
    for entry in entries:
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        name = raw_name.decode("utf8")
        allowed_source(name)
        require(kind == "blob" and mode in ("100644", "100755", "120000"),
                "Submodules or unsupported source modes must be materialized explicitly")
        modes[name] = mode
        if mode == "120000":
            target = git(repo, "cat-file", "blob", object_id).decode("utf8")
            links[name] = target
    bounded_source_symlinks(links)
    destination.mkdir(mode=0o755, parents=True)
    # checkout-index copies only tracked objects and does not read unrelated
    # ignored files. The cleanliness check above establishes index == HEAD.
    git(repo, "checkout-index", "--all", "--force", "--prefix=" + str(destination.resolve()) + "/")
    objects = {head, tree}
    objects.update(git(repo, "ls-tree", "-rt", "--format=%(objectname)", "HEAD").decode().splitlines())
    pack = git(repo, "pack-objects", "--stdout", data=("\n".join(sorted(objects)) + "\n").encode())
    metadata = destination / ".git"
    (metadata / "objects").mkdir(parents=True)
    (metadata / "refs/heads").mkdir(parents=True)
    (metadata / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = true\n")
    (metadata / "HEAD").write_text("ref: refs/heads/source\n")
    (metadata / "refs/heads/source").write_text(head + "\n")
    (metadata / "shallow").write_text(head + "\n")
    git(destination, "index-pack", "--stdin", data=pack)
    git(destination, "reset", "--mixed", "HEAD")
    require(not git(destination, "status", "--porcelain=v1", "--untracked-files=all"), "Source export is not an exact clean checkout")
    # Apply explicit Git executable modes after the last generated-index write.
    # The surrounding Docker context stays private and the caller's umask is
    # untouched; ignored files were never exported or visited.
    normalize_export_permissions(destination, modes)
    return {"source_head": head, "source_tree": tree,
            "source_epoch": int(git(repo, "show", "-s", "--format=%ct", "HEAD"))}


def build_image(repo, compiler="gcc", image_tag=None, no_cache=False, progress=print):
    require(compiler in ("gcc", "clang"), "Choose gcc or clang")
    if image_tag is not None:
        require(type(image_tag) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.:/-]{0,180}", image_tag), "Invalid local image tag")
    with tempfile.TemporaryDirectory(prefix="pqbtc-source-build-") as temporary:
        context = Path(temporary)
        identity = stage_source(repo, context / "source")
        # Compile the recipe from the same frozen export as the source. A live
        # checkout edit after export must not escape the attested source head.
        recipe = context / "source/contrib/ml-dsa-console/container"
        require(recipe.is_dir(), "The checked-out source has no runtime build recipe")
        shutil.copyfile(recipe / "Dockerfile", context / "Dockerfile")
        shutil.copyfile(recipe / "build_native.sh", context / "build_native.sh")
        (context / ".dockerignore").write_text("*\n!source/\n!source/**\n!Dockerfile\n!build_native.sh\n")
        tag = image_tag or "pqbtc-source:" + identity["source_head"][:16] + "-" + compiler
        command = ["docker", "build", "--progress", "plain", "--ulimit", "memlock=8388608:8388608", "--tag", tag,
                   "--build-arg", "COMPILER=" + compiler, "--build-arg", "EXPECTED_HEAD=" + identity["source_head"],
                   "--build-arg", "EXPECTED_TREE=" + identity["source_tree"],
                   "--build-arg", "SOURCE_DATE_EPOCH=" + str(identity["source_epoch"])]
        if no_cache:
            command += ["--no-cache", "--pull"]
        command.append(str(context))
        progress("Building fresh Linux " + compiler + " runtime from " + identity["source_head"] + "…")
        try:
            result = subprocess.run(command, timeout=3600)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BuildError("Contained source build failed or exceeded one hour") from error
        require(result.returncode == 0, "Contained source build failed; inspect the Docker build output")
    image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", tag], text=True,encoding="utf8", timeout=30).strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "Docker returned an invalid image identity")
    raw = subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                                   "--security-opt", "no-new-privileges", image, "cat", "/opt/pqbtc-runtime/manifest.json"], timeout=30)
    require(len(raw) <= 1024 * 1024, "Source build manifest exceeds its size bound")
    manifest = json.loads(raw)
    require(manifest.get("schema") == MANIFEST_SCHEMA and manifest.get("source_head") == identity["source_head"] and
            manifest.get("source_tree") == identity["source_tree"] and manifest.get("compiler") == compiler,
            "Built runtime manifest does not match the requested source/compiler")
    return {"schema": DESCRIPTOR_SCHEMA, "image": image, "manifest": manifest,
            "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=HERE.parents[1])
    parser.add_argument("--compiler", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--image-tag")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink(), "Choose a new build descriptor output")
    descriptor = build_image(args.repo, args.compiler, args.image_tag, args.no_cache)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(descriptor, handle, sort_keys=True, indent=2)
        handle.write("\n")
    print("Fresh source runtime descriptor: " + str(args.output), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Source runtime build failed: " + str(error)) from error
