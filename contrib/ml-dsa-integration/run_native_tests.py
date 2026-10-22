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
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def run(command):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True, text=True, timeout=120)
    if result.returncode or result.stderr:
        raise RuntimeError(f"command failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    model = load(ROOT / "contrib/ml-dsa-production-contract/protocol_v1.py", "contract_model_v1")
    common = ["-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-fno-lto", "-fvisibility=hidden", "-fPIC"]
    if args.sanitize:
        common += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    source_paths = [
        "src/crypto/mldsa44/verify.h", "src/crypto/mldsa44/verify_config.h", "src/crypto/mldsa44/verify.c",
        "src/crypto/mldsa44/contract.h", "src/crypto/mldsa44/contract.cpp", "src/crypto/sha256.cpp",
        "src/crypto/sha256.h", "src/crypto/common.h", "src/compat/endian.h", "src/compat/byteswap.h",
        "contrib/ml-dsa-integration/native_smoke.cpp",
        "contrib/ml-dsa-integration/run_native_tests.py", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c",
        "contrib/ml-dsa-production-contract/protocol_v1.py", "contrib/genesis/generated_constants.json"]
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    with tempfile.TemporaryDirectory(prefix="mldsa-native-integration-") as directory:
        build = Path(directory)
        commands = []
        def compile_file(compiler, standard, source, output, extra=()):
            command = [compiler, standard, *common, "-I", ROOT / "src", "-I", ROOT / "src/crypto/mldsa44",
                       "-I", ROOT / "contrib/ml-dsa-engineering", *extra,
                       "-c", ROOT / source, "-o", build / output]
            commands.append([str(x) for x in command])
            run(command)
        compile_file(cc, "-std=c11", "src/crypto/mldsa44/verify.c", "verify.o")
        symbols = run([nm, "-a", build / "verify.o"])
        if re.search(r"(?i)(signature_internal|keypair|randombytes|getentropy|pthread|fork|mlock|prctl)", symbols):
            raise RuntimeError("private/entropy/lifecycle machinery found in verifier object")
        # Object globals include a HIDDEN public-data CT barrier. Audit actual
        # dynamic exports, not nm's visibility-blind list of object globals.
        command = [cc, *common, "-shared", "-Wl,--no-undefined", build / "verify.o", "-o", build / "verify.so"]
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
        binary_hashes = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                         for name in ("verify.o", "verify.so", "signer.o", "sha.o", "contract.o", "smoke.o", "native-smoke")}
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
    if source_hashes != {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}:
        raise RuntimeError("runtime source changed")
    after = source_reader.runtime_identity(args.expect_head)
    if before != after or frozen_sources != source_reader.validate_sources(ROOT):
        raise RuntimeError("runtime identity or frozen source changed")
    print(json.dumps({"result": "PASS", "scope": "NATIVE_CONTRACT_INTEGRATION_ONLY", "node_linked": False,
                      "production_admitted": False, "architecture": platform.machine(),
                      "compiler": run([cc, "--version"]).splitlines()[0],
                      "cxx": run([cxx, "--version"]).splitlines()[0], "sanitized": args.sanitize,
                      "negative_checks": native["negative_checks"], "verifier_exports": exports,
                      "verifier_symbol_audit": "PASS", "python_contract_join": "PASS",
                      "runtime_before": before, "runtime_after": after, "elf": elf,
                      "binary_hashes": binary_hashes, "frozen_source_hashes": frozen_sources,
                      "source_hashes": source_hashes, "commands": commands}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
