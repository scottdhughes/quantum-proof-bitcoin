#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained native signer qualification. PUBLIC fixtures only; no host execution."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
       "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0",
       "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:symbolize=0", "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": "/nonexistent"}
ARCHIVE_SHA = "a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98"
OUTPUT_LIMIT = 2 * 1024 * 1024

def run(command, timeout=180):
    """Bound one command's output and lifetime; stderr is always failure."""
    argv = [str(x) for x in command]
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    process = None
    owned = True
    failure = None
    with selectors.DefaultSelector() as selector:
        try:
            process = subprocess.Popen(argv, env=ENV, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            for name in output:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() and failure is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    buffer = output[key.data]
                    buffer.extend(block[:OUTPUT_LIMIT - len(buffer)])
                    if len(buffer) >= OUTPUT_LIMIT:
                        failure = key.data + " output limit"
                    elif key.data == "stderr":
                        failure = "stderr"
                    if failure is not None:
                        break
            # WNOWAIT retains the direct child's PID/session ownership until
            # cleanup. Do not poll/reap it before signalling its process group.
            while failure is None:
                try:
                    exited = os.waitid(os.P_PID, process.pid,
                                       os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    owned = False
                    failure = "command ownership lost"
                    break
                if exited is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                time.sleep(min(remaining, 0.01))
        finally:
            if process is not None:
                try:
                    if owned:
                        # start_new_session made this unreaped child the group
                        # leader. Stop same-group heirs even on normal exit.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.wait(timeout=5)
                finally:
                    for name in output:
                        stream = getattr(process, name)
                        if stream is not None and not stream.closed:
                            stream.close()
    if failure is not None or process.returncode:
        stdout = output["stdout"].decode("utf-8", "replace")
        stderr = output["stderr"].decode("utf-8", "replace")
        raise RuntimeError(f"command failed ({failure or 'nonzero exit'}) exit={process.returncode}: {command}\n{stdout}\n{stderr}")
    # Preserve subprocess text=True's strict UTF8 and universal-newline behavior.
    return output["stdout"].decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", choices=("gcc", "clang"), required=True)
    parser.add_argument("--cxx", choices=("g++", "clang++"), required=True)
    parser.add_argument("--openssl-prefix", type=Path, required=True)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--expect-head")
    parser.add_argument("--build-dir", type=Path, help="exclusive new retained build directory for different-UID service tests")
    args = parser.parse_args()
    if platform.system() != "Linux" or (args.cc, args.cxx) not in [("gcc", "g++"), ("clang", "clang++")]:
        raise RuntimeError("contained Linux matched compiler pair required")
    cc, cxx = shutil.which(args.cc), shutil.which(args.cxx)
    if not cc or not cxx: raise RuntimeError("required compiler absent, not a passing skip")
    prefix = args.openssl_prefix.resolve()
    if (prefix / "source-archive.sha256").read_text() != ARCHIVE_SHA + "\n":
        raise RuntimeError("OpenSSL source marker mismatch")
    crypto_before = {"static_libcrypto": sha(prefix / "lib/libcrypto.a"), "cli": sha(prefix / "bin/openssl")}
    version = run([prefix / "bin/openssl", "version"]).strip()
    if not version.startswith("OpenSSL 3.6.5 "): raise RuntimeError("wrong OpenSSL dependency")
    spec = importlib.util.spec_from_file_location("signer_frozen_source", ROOT / "contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py")
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    before = reader.runtime_identity(args.expect_head)
    frozen = reader.validate_sources(ROOT); frozen_hashes = reader.source_hashes()
    sources = ["src/crypto/mldsa44/verify.c", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c", "src/crypto/sha256.cpp",
               "src/crypto/mldsa44/contract.cpp", "src/crypto/mldsa44/signer/wallet_crypto.cpp",
               "src/crypto/mldsa44/signer/wallet.cpp", "src/crypto/mldsa44/signer/ipc.cpp", "src/crypto/mldsa44/signer/session.cpp",
               "src/crypto/mldsa44/signer/transport.cpp", "src/crypto/mldsa44/signer/client.cpp", "src/crypto/mldsa44/signer/service.cpp",
               "contrib/ml-dsa-signer/wallet_smoke.cpp", "contrib/ml-dsa-signer/ipc_smoke.cpp",
               "contrib/ml-dsa-signer/signer_main.cpp", "contrib/ml-dsa-signer/client_smoke.cpp", "contrib/ml-dsa-signer/schedule_smoke.cpp"]
    all_owned = [path for path in (ROOT / "src/crypto/mldsa44").rglob("*") if path.is_file()]
    all_owned += [path for path in (ROOT / "contrib/ml-dsa-signer").rglob("*") if path.is_file() and "__pycache__" not in path.parts]
    source_before = {str(path.relative_to(ROOT)): sha(path) for path in all_owned}
    flags = ["-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-fno-lto", "-fvisibility=hidden"]
    if args.sanitize: flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    commands = []; dependencies = {}
    if args.build_dir:
        args.build_dir.mkdir(mode=0o755)
        workspace = contextlib.nullcontext(str(args.build_dir))
    else:
        workspace = tempfile.TemporaryDirectory(prefix="mldsa-signer-native-")
    with workspace as temporary:
        build = Path(temporary); objects = []; roles = {}
        for i, source in enumerate(sources):
            output = build / f"{i}.o"; depfile = build / f"{i}.d"; objects.append(output)
            extra = ["-DDISABLE_OPTIMIZED_SHA256", "-Wno-unused-parameter"] if source == "src/crypto/sha256.cpp" else []
            command = [cc if source.endswith(".c") else cxx, "-std=c11" if source.endswith(".c") else "-std=c++20", *flags,
                       "-I", ROOT / "src", "-I", ROOT / "src/crypto/mldsa44", "-I", ROOT / "contrib/ml-dsa-engineering", "-I", prefix / "include", *extra,
                       "-pthread", "-MMD", "-MF", depfile, "-c", ROOT / source, "-o", output]
            commands.append([str(x) for x in command]); run(command)
            roles[Path(source).stem] = output
            for raw in shlex.split(depfile.read_text().partition(":")[2].replace("\\\n", " ")):
                path = Path(raw).resolve()
                name = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else "openssl/" + str(path.relative_to(prefix))
                dependencies[name] = sha(path)
        native = {}; executable_paths = []
        common_names = ["verify", "key_lifecycle", "sha256", "contract", "wallet_crypto", "wallet", "ipc", "session"]
        for name in ("wallet", "ipc", "schedule"):
            binary = build / (name + "-smoke"); executable_paths.append(binary)
            extra = [roles["transport"], "-Wl,--wrap=pqbtc_mldsa44_key_sign_hedged"] if name == "schedule" else ["-Wl,--wrap=fsync"]
            command = [cxx, *flags, "-pthread", *[roles[x] for x in common_names], roles[name + "_smoke"], *extra, prefix / "lib/libcrypto.a", "-ldl", "-o", binary]
            commands.append([str(x) for x in command]); run(command)
            native[name] = json.loads(run([binary, build / (name + "-state")]))
            if native[name].get("result") != "PASS": raise RuntimeError("incomplete native observations: " + name)
        if native["wallet"].get("record_bytes") != 167 or native["ipc"].get("signatures_verified") != 2:
            raise RuntimeError("incomplete wallet/IPC observations")
        sys.path.insert(0, str(ROOT / "contrib/ml-dsa-production-contract"))
        import ipc_v1
        wire = bytes.fromhex(native["ipc"]["sign_request_hex"])
        identity, transaction, paths = ipc_v1.decode_sign_request(wire)
        if ipc_v1.encode_sign_request(identity, transaction, paths) != wire:
            raise RuntimeError("native/Python IPC body join mismatch")
        symbols = run(["nm", "-a", objects[6]])
        import re
        if re.search(r"Wallet|Secret|key_sign|key_import|OPENSSL|EVP_|runtime_init|RandomBytes", symbols):
            raise RuntimeError("private machinery in public IPC codec")
        service_paths = {}
        for name, names, libraries in [
            ("pilot-signer", [*common_names, "transport", "service", "signer_main"], [prefix / "lib/libcrypto.a", "-ldl"]),
            ("public-client", ["verify", "sha256", "contract", "ipc", "transport", "client", "client_smoke"], [])]:
            binary = build / name; executable_paths.append(binary)
            command = [cxx, *flags, "-pthread", *[roles[x] for x in names], *libraries, "-o", binary]
            commands.append([str(x) for x in command]); run(command); service_paths[name] = str(binary)
            if name == "public-client":
                client_symbols = run(["nm", "-a", binary])
                if re.search(r"Wallet|Secret|key_sign|key_import|OPENSSL|EVP_|runtime_init|RandomBytes", client_symbols):
                    raise RuntimeError("private dependency in node-side client")
        executables = {}
        for executable in executable_paths:
            dynamic = run(["readelf", "-d", executable])
            if "libcrypto.so" in dynamic or "libssl.so" in dynamic: raise RuntimeError("dynamic system crypto fallback: " + executable.name)
            elf = run(["readelf", "-h", executable])
            if "ELF64" not in elf: raise RuntimeError("unexpected ELF class: " + executable.name)
            executables[executable.name] = {"sha256":sha(executable),"elf":elf,"dynamic":dynamic}
        pilot_version = run([service_paths["pilot-signer"],"--valueless-pilot","--crypto-version"]).strip()
        if pilot_version != native["wallet"]["runtime"] or not pilot_version.startswith("OpenSSL 3.6.5 "):
            raise RuntimeError("actual signer crypto version mismatch")
        binaries = {path.name: sha(path) for path in [*objects, *executable_paths]}
    after = reader.runtime_identity(args.expect_head)
    if before != after or frozen != reader.validate_sources(ROOT) or frozen_hashes != reader.source_hashes():
        raise RuntimeError("frozen inputs/runtime changed")
    if source_before != {str(path.relative_to(ROOT)): sha(path) for path in all_owned}:
        raise RuntimeError("owned inputs changed")
    if crypto_before != {"static_libcrypto": sha(prefix / "lib/libcrypto.a"), "cli": sha(prefix / "bin/openssl")}:
        raise RuntimeError("dependency changed")
    print(json.dumps({"result": "PASS", "scope": "EXPERIMENTAL_NATIVE_WALLET_AND_IPC_CODEC", "node_linked": False,
        "production_admitted": False, "architecture": platform.machine(), "compiler": run([cc, "--version"]).splitlines()[0],
        "sanitized": args.sanitize, "native": native, "python_ipc_join": "PASS", "public_codec_symbol_audit": "PASS", "runtime_before": before, "runtime_after": after,
        "openssl": {**crypto_before, "version": version, "source_archive_sha256": ARCHIVE_SHA,
                    "library_instrumented_by_this_run": False, "build_origin": "reused pinned contained build; not independent binary attestation"},
        "source_hashes": source_before, "frozen_source_hashes": frozen_hashes, "capsule": frozen,
        "compiler_dependencies": dependencies, "binaries": binaries, "executables": executables,"pilot_crypto_version":pilot_version,
        "commands": commands, "environment": ENV, "service_binaries": service_paths,
        "build_retained": bool(args.build_dir), "public_client_symbol_audit": "PASS"}, sort_keys=True))

if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(str(error), file=sys.stderr); sys.exit(1)
