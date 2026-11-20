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
    return native_process.checked(command, cwd=ROOT, env=RUN_ENV, timeout=120)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROCESS_HELPER = ROOT / "contrib/ml-dsa-qualification/native_process.py"
native_process = load(PROCESS_HELPER, "integration_native_process")


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


def validate_verifier_exports(nm_output, *, compiler, sanitized, elf_dynamic_symbols, elf_sections):
    """Join complete ELF tables to nm; only the verifier is a public export."""
    if (type(nm_output) is not str or type(elf_dynamic_symbols) is not str
            or type(elf_sections) is not str or type(compiler) is not str
            or compiler not in ("gcc", "clang") or type(sanitized) is not bool):
        raise RuntimeError("invalid verifier export audit input")
    hex_value = r"[0-9a-fA-F]{1,16}"
    nm_symbols = {}
    for line in nm_output.splitlines():
        row = line.split()
        if (len(row) != 3 or re.fullmatch(hex_value, row[0]) is None
                or row[1] not in ("T", "D") or row[2] in nm_symbols):
            raise RuntimeError("malformed or duplicate verifier export")
        nm_symbols[row[2]] = (int(row[0], 16), row[1])

    lines = [line.strip() for line in elf_dynamic_symbols.splitlines() if line.strip()]
    header = re.fullmatch(r"Symbol table '\.dynsym' contains ([1-9][0-9]*) entries:", lines[0]) if lines else None
    if (header is None or len(lines) < 2
            or lines[1].split() != ["Num:", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"]
            or len(lines) != int(header[1]) + 2):
        raise RuntimeError("complete single verifier .dynsym table required")
    symbols = {}
    defined = {}
    local_sections = {}
    for index, line in enumerate(lines[2:]):
        row = line.split()
        if (len(row) not in (7, 8, 9) or row[0] != str(index) + ":"
                or re.fullmatch(hex_value, row[1]) is None
                or re.fullmatch(r"[0-9]+", row[2]) is None
                or row[3] not in ("NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS", "IFUNC")
                or row[4] not in ("LOCAL", "GLOBAL", "WEAK", "UNIQUE")
                or row[5] not in ("DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED")
                or re.fullmatch(r"(?:UND|ABS|COM|[1-9][0-9]*)", row[6]) is None):
            raise RuntimeError("malformed verifier dynamic symbol")
        if index == 0:
            if (len(row) != 7 or int(row[1], 16) != 0 or int(row[2]) != 0
                    or row[3:] != ["NOTYPE", "LOCAL", "DEFAULT", "UND"]):
                raise RuntimeError("invalid verifier null dynamic symbol")
            continue
        if (len(row) < 8 or row[7] in symbols
                or (len(row) == 9 and (row[6] != "UND" or "@" not in row[7]
                                       or re.fullmatch(r"\([1-9][0-9]*\)", row[8]) is None))):
            raise RuntimeError("missing or duplicate verifier dynamic name")
        symbols[row[7]] = (int(row[1], 16), int(row[2]), *row[3:7])
        if row[6] != "UND":
            if row[3:5] == ["SECTION", "LOCAL"]:
                # GNU binutils 2.40 on aarch64 retains these two local ELF
                # section descriptors in .dynsym. They are not nm -D exports.
                # Join their exact metadata to the complete section table below
                # rather than broadening the public function/object allowlist.
                if (row[7] not in (".init", ".data") or row[5] != "DEFAULT"
                        or int(row[2]) != 0 or not row[6].isdigit()):
                    raise RuntimeError("unqualified local verifier section symbol")
                local_sections[row[7]] = symbols[row[7]]
            else:
                defined[row[7]] = symbols[row[7]]
    if set(nm_symbols) != set(defined):
        raise RuntimeError("verifier nm/dynsym definition mismatch")

    lines = [line.strip() for line in elf_sections.splitlines() if line.strip()]
    header = re.fullmatch(r"There are ([1-9][0-9]*) section headers, starting at offset 0x[0-9a-fA-F]+:", lines[0]) if lines else None
    if (header is None or len(lines) < 4 or lines[1] != "Section Headers:"
            or lines[2].split() != ["[Nr]", "Name", "Type", "Address", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al"]
            or lines.count("Key to Flags:") != 1):
        raise RuntimeError("complete verifier section table required")
    section_rows = lines[3:lines.index("Key to Flags:")]
    flag_lines = lines[lines.index("Key to Flags:") + 1:]
    if (len(section_rows) != int(header[1]) or not flag_lines
            or any(re.fullmatch(r"(?:[A-Za-z] \([^()]+\),?\s*)+", line) is None for line in flag_lines)):
        raise RuntimeError("incomplete verifier section table")
    sections = {}
    section_names = set()
    for index, line in enumerate(section_rows):
        match = re.fullmatch(r"\[\s*([0-9]+)\]\s+(.*)", line)
        if match is None or match[1] != str(index):
            raise RuntimeError("malformed or duplicate verifier section index")
        row = match[2].split()
        if index == 0 and len(row) == 8 and row[0] == "NULL":
            row.insert(0, "")
        if len(row) == 9:
            row.insert(6, "")
        if (len(row) != 10 or row[0] in section_names
                or any(re.fullmatch(hex_value, value) is None for value in row[2:6])
                or re.fullmatch(r"[A-Za-z]*", row[6]) is None
                or any(re.fullmatch(r"[0-9]+", value) is None for value in row[7:])
                or int(row[7]) >= int(header[1])):
            raise RuntimeError("malformed verifier section")
        if index == 0 and (row[:2] != ["", "NULL"] or any(int(value, 16) for value in row[2:6])
                           or row[6] or any(int(value) for value in row[7:])):
            raise RuntimeError("invalid verifier null section")
        section_names.add(row[0])
        sections[str(index)] = (row[0], row[1], int(row[2], 16), int(row[4], 16), row[6], int(row[9]))
    for name, symbol in local_sections.items():
        value, size, kind, binding, visibility, section = symbol
        expected_flags = "AX" if name == ".init" else "WA"
        observed = sections.get(section)
        if (observed is None or observed[0:2] != (name, "PROGBITS")
                or observed[2] != value or observed[3] <= 0 or observed[4] != expected_flags):
            raise RuntimeError("local verifier section symbol does not match ELF section")
    api = "pqbtc_mldsa44_node_verify"
    anchors = {"__start_asan_globals", "__stop_asan_globals"}
    present = anchors.intersection(defined)
    if set(defined) != {api} | present:
        raise RuntimeError("unexpected verifier dynamic definition")
    if api not in defined:
        raise RuntimeError("missing public verifier export")
    value, size, kind, binding, visibility, section = defined[api]
    text = sections.get(section)
    if ((kind, binding, visibility) != ("FUNC", "GLOBAL", "DEFAULT")
            or nm_symbols[api] != (value, "T") or size <= 0 or text is None
            or text[0:2] != (".text", "PROGBITS") or text[4] != "AX"
            or not (text[2] <= value < value + size <= text[2] + text[3])):
        raise RuntimeError("unqualified public verifier export")
    if present:
        if compiler != "clang" or not sanitized or present != anchors:
            raise RuntimeError("unqualified linked sanitizer anchor pair")
        start, stop = (defined[name] for name in ("__start_asan_globals", "__stop_asan_globals"))
        for name in anchors:
            value, size, kind, binding, visibility, section = defined[name]
            if ((size, kind, binding, visibility) != (0, "NOTYPE", "GLOBAL", "HIDDEN")
                    or nm_symbols[name] != (value, "D")):
                raise RuntimeError("unqualified linked sanitizer anchor metadata: " + name)
        data = sections.get(start[5])
        if (start[5] != stop[5] or data is None or data[0:2] != ("asan_globals", "PROGBITS")
                or data[3] <= 0 or data[4] not in ("WA", "WAL") or data[5] != 16
                or data[2] % data[5] or data[3] % data[5]
                or start[0] != data[2] or stop[0] != data[2] + data[3]):
            raise RuntimeError("unqualified sanitizer globals section bounds")
    return [api]


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
    executable_link_flags = native_process.sanitizer_executable_link_flags(args.cc, args.sanitize)
    source_paths = [
        "src/crypto/mldsa44/verify.h", "src/crypto/mldsa44/verify_config.h", "src/crypto/mldsa44/verify.c",
        "src/crypto/mldsa44/contract.h", "src/crypto/mldsa44/contract.cpp", "src/crypto/sha256.cpp",
        "src/crypto/sha256.h", "src/crypto/common.h", "src/compat/endian.h", "src/compat/byteswap.h",
        "contrib/ml-dsa-integration/native_smoke.cpp",
        "contrib/ml-dsa-integration/run_native_tests.py", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c",
        "contrib/ml-dsa-production-contract/protocol_v1.py", "contrib/genesis/generated_constants.json",
        "ci/test/test_ml_dsa_native_integration.py", "contrib/ml-dsa-qualification/native_process.py"]
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    with tempfile.TemporaryDirectory(prefix="mldsa-native-integration-") as directory:
        build = Path(directory)
        commands = []
        dependency_paths = set()
        def compile_file(compiler, standard, source, output, extra=()):
            command = [compiler, standard, *common, "-I", ROOT, "-I", ROOT / "src", "-I", ROOT / "src/crypto/mldsa44",
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
            observed = native_process.capture(command, env=RUN_ENV, cwd=ROOT, timeout=120)
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
        export_audit = {"nm_defined": run([nm, "-D", "--defined-only", build / "verify.so"]),
                        "elf_dynamic_symbols": run(["readelf", "--dyn-syms", "-W", build / "verify.so"]),
                        "elf_sections": run(["readelf", "-SW", build / "verify.so"])}
        exports = validate_verifier_exports(export_audit["nm_defined"], compiler=args.cc, sanitized=args.sanitize,
                                            elf_dynamic_symbols=export_audit["elf_dynamic_symbols"],
                                            elf_sections=export_audit["elf_sections"])
        compile_file(cc, "-std=c11", "contrib/ml-dsa-key-lifecycle/key_lifecycle.c", "signer.o", ("-pthread",))
        compile_file(cxx, "-std=c++20", "src/crypto/sha256.cpp", "sha.o",
                     ("-DDISABLE_OPTIMIZED_SHA256", "-Wno-unused-parameter"))
        compile_file(cxx, "-std=c++20", "src/crypto/mldsa44/contract.cpp", "contract.o")
        compile_file(cxx, "-std=c++20", "contrib/ml-dsa-integration/native_smoke.cpp", "smoke.o")
        command = [cxx, *common, *executable_link_flags, "-pthread", *[build / f for f in ("verify.o", "signer.o", "sha.o", "contract.o", "smoke.o")], "-o", build / "native-smoke"]
        commands.append([str(x) for x in command])
        run(command)
        native = json.loads(run([build / "native-smoke"]))
        sanitizer_controls = {}
        if args.sanitize:
            controls = [("address", "#include <stdlib.h>\nint main(int argc,char**argv){(void)argv;volatile int i=argc;volatile int*a=(volatile int*)malloc(sizeof(int));a[0]=1;a[i]=2;free((void*)a);return 0;}\n", "heap-buffer-overflow", "undefined"),
                        ("undefined", "#include <limits.h>\nint main(void){volatile int x=INT_MAX;return x+1;}\n", "signed integer overflow", "address")]
            for name, text, expected, disable in controls:
                source = build / (name + "-control.c")
                source.write_text(text)
                command = [cc, "-std=c11", *common, *executable_link_flags, "-fno-sanitize=" + disable, source, "-o", build / (name + "-control")]
                commands.append([str(x) for x in command])
                run(command)
                control_elf = run(["readelf", "-h", build / (name + "-control")])
                control_layout = native_process.executable_layout(control_elf, executable_link_flags)
                observed = native_process.capture([build / (name + "-control")], env=RUN_ENV, timeout=30)
                if observed.returncode == 0 or observed.stdout or expected not in observed.stderr or "WARNING" in observed.stderr:
                    raise RuntimeError(f"sanitizer positive control not qualified: {name}, exit={observed.returncode}\n{observed.stdout}\n{observed.stderr}")
                sanitizer_controls[name] = {"returncode": observed.returncode, "diagnostic": observed.stderr,
                                            "executable_layout": control_layout}
        binary_hashes = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                         for name in ("verify.o", "verify.so", "signer.o", "sha.o", "contract.o", "smoke.o", "native-smoke")}
        dependency_hashes = {str(path): hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                             for path in sorted(dependency_paths)}
        elf = run(["readelf", "-h", build / "native-smoke"])
        layout = native_process.executable_layout(elf, executable_link_flags)
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
                      "verifier_imports": imports, "verifier_export_audit": export_audit,
                      "private_api_absence_probes": api_probes,
                      "sanitizer_environment": RUN_ENV, "sanitizer_positive_controls": sanitizer_controls,
                      "runtime_before": before, "runtime_after": after, "elf": elf, "executable_layout": layout,
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
