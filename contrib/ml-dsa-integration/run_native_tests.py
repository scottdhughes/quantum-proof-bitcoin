#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Contained Linux native integration proof, public fixture data only."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
RUN_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           # The bounded image lacks LLVM symbolizer; retain raw addresses.
           "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0",
           "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:symbolize=0"}


def run(command):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=RUN_ENV, capture_output=True, text=True, timeout=120)
    if result.returncode or result.stderr:
        raise RuntimeError(f"command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_networks(native, model, pk, tx, artifact):
    if set(native["networks"]) != {"main", "test", "regtest"}:
        raise RuntimeError("network result set")
    for entry in artifact["networks"]:
        name = entry["name"]
        expected = bytes(entry["message_start"]) + bytes.fromhex(entry["genesis_hash"])[::-1]
        observed = native["networks"][name]
        if (observed["binding"] != expected.hex() or model.binding(name) != expected
                or observed["program"] != model.key_commitment(name, pk).hex()
                or observed["message"] != model.signing_message(name, tx, 0).hex()):
            raise RuntimeError("native/model/genesis join: " + name)


def validate_verifier_imports(nm_output, *, compiler, sanitized, elf_symbols=""):
    if (type(nm_output) is not str or type(elf_symbols) is not str
            or compiler not in ("gcc", "clang") or type(sanitized) is not bool):
        raise RuntimeError("invalid verifier import audit input")
    rows = [line.split() for line in nm_output.splitlines()]
    if any(len(row) != 2 or row[0] not in ("U", "w", "v") for row in rows):
        raise RuntimeError("malformed verifier import")
    imports = [row[1] for row in rows]
    if len(imports) != len(set(imports)):
        raise RuntimeError("duplicate verifier import")
    anchors = {"__start_asan_globals", "__stop_asan_globals"}
    present = anchors.intersection(imports)
    if present:
        if (compiler != "clang" or not sanitized or present != anchors
                or any(row[0] != "w" for row in rows if row[1] in anchors)):
            raise RuntimeError("unqualified sanitizer global anchor pair")
        # Clang's ELF ASan globals registration uses paired weak hidden
        # undefined section anchors, not private verifier dependencies.
        for name in anchors:
            symbols = [line.split() for line in elf_symbols.splitlines()
                       if line.split() and line.split()[-1] == name]
            if len(symbols) != 1:
                raise RuntimeError("missing or duplicate sanitizer global anchor: " + name)
            row = symbols[0]
            if (len(row) != 8 or re.fullmatch(r"[1-9][0-9]*:", row[0]) is None
                    or re.fullmatch(r"[0-9a-fA-F]+", row[1]) is None
                    or int(row[1], 16) != 0 or row[2] != "0"
                    or row[3:7] != ["NOTYPE", "WEAK", "HIDDEN", "UND"]):
                raise RuntimeError("unqualified sanitizer global anchor metadata: " + name)
    allowed = {"memcpy", "memmove", "memset", "__stack_chk_fail", "_GLOBAL_OFFSET_TABLE_"}
    for name in imports:
        if (name not in allowed and name not in present
                and not (sanitized and name.startswith(("__asan_", "__ubsan_")))):
            raise RuntimeError("unexpected verifier import: " + name)
    return imports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", choices=("gcc", "clang"), required=True)
    parser.add_argument("--cxx", choices=("g++", "clang++"), required=True)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--expect-head")
    args = parser.parse_args()
    if platform.system() != "Linux" or (args.cc, args.cxx) not in [("gcc", "g++"), ("clang", "clang++")]:
        raise RuntimeError("supported contained Linux compiler pair required")
    cc, cxx, nm = (shutil.which(name) for name in (args.cc, args.cxx, "nm"))
    if not all((cc, cxx, nm)):
        raise RuntimeError("required compiler/tool absent, not a passing skip")
    # Reuse the unchanged source reader, not old native qualification results.
    source_reader = load(ROOT / "contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py", "key_source_reader")
    before = source_reader.runtime_identity(args.expect_head)
    frozen_sources = source_reader.validate_sources(ROOT)
    frozen_source_inputs = source_reader.source_hashes()
    model = load(ROOT / "contrib/ml-dsa-production-contract/protocol_v1.py", "contract_model_v1")
    common = ["-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-fno-lto", "-fvisibility=hidden", "-fPIC"]
    if args.sanitize:
        common += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-sanitize-recover=all"]
    source_paths = [
        "src/crypto/mldsa44/verify.h", "src/crypto/mldsa44/verify_config.h", "src/crypto/mldsa44/verify.c",
        "src/crypto/mldsa44/contract.h", "src/crypto/mldsa44/contract.cpp", "src/crypto/sha256.cpp",
        "src/crypto/sha256.h", "src/crypto/common.h", "src/compat/endian.h", "src/compat/byteswap.h",
        "contrib/ml-dsa-integration/native_smoke.cpp",
        "contrib/ml-dsa-integration/run_native_tests.py", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c",
        "contrib/ml-dsa-production-contract/protocol_v1.py", "contrib/genesis/generated_constants.json",
        "ci/test/test_ml_dsa_native_integration.py"]
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    with tempfile.TemporaryDirectory(prefix="mldsa-native-integration-") as directory:
        build = Path(directory)
        commands = []
        dependency_paths = set()
        def compile_file(compiler, standard, source, output, extra=()):
            command = [compiler, standard, *common, "-I", ROOT / "src", "-I", ROOT / "src/crypto/mldsa44",
                       "-I", ROOT / "contrib/ml-dsa-engineering", *extra,
                       "-MMD", "-MF", build / (output + ".d"),
                       "-c", ROOT / source, "-o", build / output]
            commands.append([str(x) for x in command])
            run(command)
            raw = (build / (output + ".d")).read_text().partition(":")[2].replace("\\\n", " ")
            for entry in shlex.split(raw):
                dependency_paths.add(Path(entry).resolve().relative_to(ROOT))
        compile_file(cc, "-std=c11", "src/crypto/mldsa44/verify.c", "verify.o")
        symbols = run([nm, "-a", build / "verify.o"])
        if re.search(r"(?i)(signature_internal|keypair|randombytes|getentropy|getrandom|pthread|fork|mlock|prctl|syscall|madvise|unpack_sk|polyeta|sign_signature)", symbols):
            raise RuntimeError("private/entropy/lifecycle machinery found in verifier object")
        imports = validate_verifier_imports(run([nm, "-u", build / "verify.o"]),
                                           compiler=args.cc, sanitized=args.sanitize,
                                           elf_symbols=run(["readelf", "-sW", build / "verify.o"]))
        api_probes = {}
        header = ROOT / "contrib/ml-dsa-engineering/vendor/mldsa-native/mldsa/mldsa_native.h"
        for suffix in ("signature", "keypair", "signature_extmu"):
            name = "pqbtc_mldsa44_node_upstream_" + suffix
            source = build / (suffix + "-absent.c")
            source.write_text('#define MLD_CONFIG_FILE "verify_config.h"\n#include "' + str(header) + '"\nvoid* probe=(void*)&' + name + ';\n')
            command = [cc, "-std=c11", "-Werror", "-I", ROOT / "src/crypto/mldsa44", "-c", source, "-o", build / (suffix + ".o")]
            observed = subprocess.run([str(x) for x in command], env=RUN_ENV, cwd=ROOT, capture_output=True, text=True, timeout=120)
            if observed.returncode == 0 or observed.stdout or not re.search(r"(" + name + r".*undeclared|undeclared.*" + name + r")", observed.stderr):
                raise RuntimeError("private API absence probe not qualified: " + name + observed.stderr)
            api_probes[name] = {"returncode": observed.returncode, "diagnostic": observed.stderr,
                                "command": [str(x) for x in command]}
        # Object globals include a HIDDEN public-data CT barrier. Audit actual
        # dynamic exports, not nm's visibility-blind list of object globals.
        shared_runtime = ["-shared-libasan"] if args.sanitize and args.cc == "clang" else []
        command = [cc, *common, *shared_runtime, "-shared", "-Wl,--no-undefined", build / "verify.o", "-o", build / "verify.so"]
        commands.append([str(x) for x in command])
        run(command)
        exports = [line.split()[-1] for line in run([nm, "-D", "--defined-only", build / "verify.so"]).splitlines()]
        if exports != ["pqbtc_mldsa44_node_verify"]:
            raise RuntimeError("unexpected verifier exports: " + repr(exports))
        compile_file(cc, "-std=c11", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c", "signer.o", ("-pthread",))
        compile_file(cxx, "-std=c++20", "src/crypto/sha256.cpp", "sha.o",
                     ("-DDISABLE_OPTIMIZED_SHA256", "-Wno-unused-parameter"))
        compile_file(cxx, "-std=c++20", "src/crypto/mldsa44/contract.cpp", "contract.o")
        compile_file(cxx, "-std=c++20", "contrib/ml-dsa-integration/native_smoke.cpp", "smoke.o")
        command = [cxx, *common, "-pthread", *[build / f for f in ("verify.o", "signer.o", "sha.o", "contract.o", "smoke.o")], "-o", build / "native-smoke"]
        commands.append([str(x) for x in command])
        run(command)
        native = json.loads(run([build / "native-smoke"]))
        sanitizer_controls = {}
        if args.sanitize:
            controls = [("address", "#include <stdlib.h>\nint main(int argc,char**argv){(void)argv;volatile int i=argc;volatile int*a=(volatile int*)malloc(sizeof(int));a[0]=1;a[i]=2;free((void*)a);return 0;}\n", "heap-buffer-overflow", "undefined"),
                        ("undefined", "#include <limits.h>\nint main(void){volatile int x=INT_MAX;return x+1;}\n", "signed integer overflow", "address")]
            for name, text, expected, disable in controls:
                source = build / (name + "-control.c"); source.write_text(text)
                command = [cc, "-std=c11", *common, "-fno-sanitize=" + disable, source, "-o", build / (name + "-control")]
                commands.append([str(x) for x in command]); run(command)
                observed = subprocess.run([str(build / (name + "-control"))], env=RUN_ENV, capture_output=True, text=True, timeout=30)
                if observed.returncode == 0 or observed.stdout or expected not in observed.stderr or "WARNING" in observed.stderr:
                    raise RuntimeError(f"sanitizer positive control not qualified: {name}, exit={observed.returncode}\n{observed.stdout}\n{observed.stderr}")
                sanitizer_controls[name] = {"returncode": observed.returncode, "diagnostic": observed.stderr}
        binary_hashes = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                         for name in ("verify.o", "verify.so", "signer.o", "sha.o", "contract.o", "smoke.o", "native-smoke")}
        dependency_hashes = {str(path): hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                             for path in sorted(dependency_paths)}
        elf = run(["readelf", "-h", build / "native-smoke"])
    pk = bytes.fromhex(native["public_key"])
    program = model.key_commitment("regtest", pk)
    script = (b"\x52\x20" + program).hex()
    tx = {"version": 2, "inputs": [{"prev_txid": bytes(range(32))[::-1].hex(), "prev_index": 3, "sequence": 4294967294,
                                   "amount": 100000, "script_pubkey": script}],
          "outputs": [{"amount": 99000, "script_pubkey": script}], "lock_time": 7}
    if (native["program"] != program.hex() or native["message"] != model.signing_message("regtest", tx, 0).hex()
            or native["unsigned"] != model.encode_unsigned(tx).hex()):
        raise RuntimeError("C++/Python contract join mismatch")
    validate_networks(native, model, pk, tx, json.loads((ROOT / "contrib/genesis/generated_constants.json").read_text()))
    second = dict(tx["inputs"][0], prev_index=4)
    multi = {"version": 2, "inputs": [tx["inputs"][0], second],
             "outputs": [{"amount": 98000, "script_pubkey": script}, {"amount": 1000, "script_pubkey": "6a" * 300}], "lock_time": 7}
    if native["multi_message"] != model.signing_message("regtest", multi, 1).hex() or native["multi_wire"] != model.encode_unsigned(multi).hex():
        raise RuntimeError("multi-input/output contract join mismatch")
    if source_hashes != {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}:
        raise RuntimeError("runtime source changed")
    if dependency_hashes != {str(path): hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                             for path in sorted(dependency_paths)}:
        raise RuntimeError("compiler-discovered source changed")
    after = source_reader.runtime_identity(args.expect_head)
    if (before != after or frozen_sources != source_reader.validate_sources(ROOT)
            or frozen_source_inputs != source_reader.source_hashes()):
        raise RuntimeError("runtime identity or frozen source changed")
    print(json.dumps({"result": "PASS", "scope": "NATIVE_CONTRACT_INTEGRATION_ONLY", "node_linked": False,
                      "production_admitted": False, "architecture": platform.machine(),
                      "compiler": run([cc, "--version"]).splitlines()[0],
                      "cxx": run([cxx, "--version"]).splitlines()[0], "sanitized": args.sanitize,
                      "negative_checks": native["negative_checks"], "verifier_exports": exports,
                      "verifier_symbol_audit": "PASS", "python_contract_join": "PASS", "network_artifact_join": "PASS",
                      "verifier_imports": imports, "private_api_absence_probes": api_probes,
                      "sanitizer_environment": RUN_ENV, "sanitizer_positive_controls": sanitizer_controls,
                      "runtime_before": before, "runtime_after": after, "elf": elf,
                      "binary_hashes": binary_hashes, "frozen_source_hashes": frozen_sources,
                      "frozen_source_input_hashes": frozen_source_inputs,
                      "compiler_dependency_hashes": dependency_hashes,
                      "source_hashes": source_hashes, "commands": commands}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
