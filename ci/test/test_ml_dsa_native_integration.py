#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Native integration check; full suite execution belongs in contained Linux."""

import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-integration/run_native_tests.py"


class NativeIntegrationTests(unittest.TestCase):
    def test_all_network_binding_joins_reject_tampered_data(self):
        spec = importlib.util.spec_from_file_location("native_network_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        model = runner.load(ROOT / "contrib/ml-dsa-production-contract/protocol_v1.py", "network_test_model")
        artifact = json.loads((ROOT / "contrib/genesis/generated_constants.json").read_text())
        pk = bytes(1312)
        program = model.key_commitment("regtest", pk)
        script = (b"\x52\x20" + program).hex()
        tx = {"version": 2, "inputs": [{"prev_txid": "01" * 32, "prev_index": 0,
              "sequence": 4294967294, "amount": 100000, "script_pubkey": script}],
              "outputs": [{"amount": 99000, "script_pubkey": script}], "lock_time": 0}
        native = {"networks": {entry["name"]: {
            "binding": (bytes(entry["message_start"]) + bytes.fromhex(entry["genesis_hash"])[::-1]).hex(),
            "program": model.key_commitment(entry["name"], pk).hex(),
            "message": model.signing_message(entry["name"], tx, 0).hex()} for entry in artifact["networks"]}}
        runner.validate_networks(native, model, pk, tx, artifact)
        for network in ("main", "test", "regtest"):
            for field in ("binding", "program", "message"):
                changed = json.loads(json.dumps(native))
                original = changed["networks"][network][field]
                changed["networks"][network][field] = ("01" if original[:2] == "00" else "00") + original[2:]
                with self.subTest(network=network, field=field), self.assertRaises(RuntimeError):
                    runner.validate_networks(changed, model, pk, tx, artifact)

    def test_inherited_sanitizer_log_redirection_is_overridden(self):
        spec = importlib.util.spec_from_file_location("native_environment_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        previous = os.environ.get("ASAN_OPTIONS")
        try:
            os.environ["ASAN_OPTIONS"] = "log_path=/tmp/not-a-proof:detect_leaks=0"
            observed = runner.run([sys.executable, "-c", "import os; print(os.getenv('ASAN_OPTIONS'))"])
            self.assertEqual(observed.strip(), "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0")
        finally:
            if previous is None:
                os.environ.pop("ASAN_OPTIONS", None)
            else:
                os.environ["ASAN_OPTIONS"] = previous

    def test_success_exit_with_diagnostic_is_not_a_pass(self):
        spec = importlib.util.spec_from_file_location("native_integration_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with self.assertRaises(RuntimeError):
            runner.run([sys.executable, "-c", "import sys; print('runtime diagnostic', file=sys.stderr)"])

    def test_verifier_import_audit_allows_only_typed_clang_asan_anchor_pair(self):
        spec = importlib.util.spec_from_file_location("native_import_audit_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        audit = getattr(runner, "validate_verifier_imports", None)
        self.assertTrue(callable(audit), "pure verifier import audit is absent")
        ordinary = "                 U memcpy\n                 U memset\n"
        sanitized = ordinary + "                 U __asan_init\n                 U __ubsan_handle_add_overflow_abort\n"
        anchors = "                 w __start_asan_globals\n                 w __stop_asan_globals\n"
        elf = ("    74: 0000000000000000     0 NOTYPE  WEAK   HIDDEN   UND __start_asan_globals\n"
               "    75: 0000000000000000     0 NOTYPE  WEAK   HIDDEN   UND __stop_asan_globals\n")
        for compiler in ("gcc", "clang"):
            for sanitize in (False, True):
                with self.subTest(ordinary=compiler, sanitized=sanitize):
                    self.assertEqual(audit(ordinary, compiler=compiler, sanitized=sanitize),
                                     ["memcpy", "memset"])
            self.assertEqual(audit(sanitized, compiler=compiler, sanitized=True),
                             ["memcpy", "memset", "__asan_init", "__ubsan_handle_add_overflow_abort"])
        self.assertEqual(audit(sanitized + anchors, compiler="clang", sanitized=True, elf_symbols=elf),
                         ["memcpy", "memset", "__asan_init", "__ubsan_handle_add_overflow_abort",
                          "__start_asan_globals", "__stop_asan_globals"])
        # Public Clang 20 diagnostic fixture, independent of an evidence packet.
        actual_nm = (
            "                 U __asan_init\n"
            "                 U __asan_memcpy\n"
            "                 U __asan_memset\n"
            "                 U __asan_option_detect_stack_use_after_return\n"
            "                 U __asan_register_elf_globals\n"
            "                 U __asan_report_load1\n"
            "                 U __asan_report_load4\n"
            "                 U __asan_report_load8\n"
            "                 U __asan_report_store1\n"
            "                 U __asan_report_store4\n"
            "                 U __asan_report_store8\n"
            "                 U __asan_set_shadow_00\n"
            "                 U __asan_set_shadow_f5\n"
            "                 U __asan_set_shadow_f8\n"
            "                 U __asan_stack_free_9\n"
            "                 U __asan_stack_malloc_3\n"
            "                 U __asan_stack_malloc_9\n"
            "                 U __asan_unregister_elf_globals\n"
            "                 U __asan_version_mismatch_check_v8\n"
            "                 w __start_asan_globals\n"
            "                 w __stop_asan_globals\n"
            "                 U __ubsan_handle_add_overflow_abort\n"
            "                 U __ubsan_handle_mul_overflow_abort\n"
            "                 U __ubsan_handle_negate_overflow_abort\n"
            "                 U __ubsan_handle_out_of_bounds_abort\n"
            "                 U __ubsan_handle_pointer_overflow_abort\n"
            "                 U __ubsan_handle_shift_out_of_bounds_abort\n"
            "                 U __ubsan_handle_sub_overflow_abort\n"
            "                 U __ubsan_handle_type_mismatch_v1_abort\n")
        self.assertEqual(audit(actual_nm, compiler="clang", sanitized=True, elf_symbols=elf), [
            "__asan_init", "__asan_memcpy", "__asan_memset", "__asan_option_detect_stack_use_after_return",
            "__asan_register_elf_globals", "__asan_report_load1", "__asan_report_load4", "__asan_report_load8",
            "__asan_report_store1", "__asan_report_store4", "__asan_report_store8", "__asan_set_shadow_00",
            "__asan_set_shadow_f5", "__asan_set_shadow_f8", "__asan_stack_free_9", "__asan_stack_malloc_3",
            "__asan_stack_malloc_9", "__asan_unregister_elf_globals", "__asan_version_mismatch_check_v8",
            "__start_asan_globals", "__stop_asan_globals", "__ubsan_handle_add_overflow_abort",
            "__ubsan_handle_mul_overflow_abort", "__ubsan_handle_negate_overflow_abort",
            "__ubsan_handle_out_of_bounds_abort", "__ubsan_handle_pointer_overflow_abort",
            "__ubsan_handle_shift_out_of_bounds_abort", "__ubsan_handle_sub_overflow_abort",
            "__ubsan_handle_type_mismatch_v1_abort"])
        adverse = [
            ("normal mode", ordinary + anchors, elf, "clang", False),
            ("GCC normal", ordinary + anchors, elf, "gcc", False),
            ("GCC sanitized", sanitized + anchors, elf, "gcc", True),
            ("one-sided pair", sanitized + anchors.splitlines(keepends=True)[0], elf, "clang", True),
            ("strong import", sanitized + anchors.replace("w __start_", "U __start_"), elf, "clang", True),
            ("weak object import", sanitized + anchors.replace("w __stop_", "v __stop_"), elf, "clang", True),
            ("defined import", sanitized + anchors.replace("w __stop_", "T __stop_"), elf, "clang", True),
            ("duplicate import", sanitized + anchors + anchors.splitlines(keepends=True)[0], elf, "clang", True),
            ("malformed import", sanitized + anchors + "malformed\n", elf, "clang", True),
            ("extra import fields", sanitized + anchors + " U unexpected extra\n", elf, "clang", True),
            ("suffixed anchor", sanitized + anchors.replace("__start_asan_globals", "__start_asan_globals_extra"), elf, "clang", True),
            ("arbitrary start", sanitized + " U __start_private\n", elf, "clang", True),
            ("arbitrary stop", sanitized + " U __stop_private\n", elf, "clang", True),
            ("paired plus arbitrary start", sanitized + anchors + " U __start_private\n", elf, "clang", True),
            ("paired plus arbitrary stop", sanitized + anchors + " U __stop_private\n", elf, "clang", True),
            ("missing ELF", sanitized + anchors, "", "clang", True),
            ("missing ELF pair", sanitized + anchors, elf.splitlines(keepends=True)[0], "clang", True),
            ("duplicate ELF", sanitized + anchors, elf + elf.splitlines(keepends=True)[0], "clang", True),
            ("strong ELF", sanitized + anchors, elf.replace("WEAK", "GLOBAL"), "clang", True),
            ("non-hidden ELF", sanitized + anchors, elf.replace("HIDDEN", "DEFAULT"), "clang", True),
            ("defined ELF", sanitized + anchors, elf.replace("UND", "24"), "clang", True),
            ("wrong ELF type", sanitized + anchors, elf.replace("NOTYPE", "OBJECT"), "clang", True),
            ("nonzero ELF value", sanitized + anchors, elf.replace("0000000000000000", "0000000000000001"), "clang", True),
            ("nonzero ELF size", sanitized + anchors, elf.replace("     0 NOTYPE", "     8 NOTYPE"), "clang", True),
            ("malformed ELF", sanitized + anchors, elf.replace("74:", "not-an-index"), "clang", True),
            ("non-string nm", None, elf, "clang", True),
            ("bytes nm", b" U memcpy\n", elf, "clang", True),
            ("non-string ELF", sanitized + anchors, None, "clang", True),
            ("non-boolean sanitizer integer", sanitized + anchors, elf, "clang", 1),
            ("non-boolean sanitizer string", sanitized + anchors, elf, "clang", "true"),
            ("unknown compiler", sanitized + anchors, elf, "cc", True),
        ]
        start_row, stop_row = elf.splitlines(keepends=True)
        for label, old, changed in (
                ("value", "0000000000000000", "0000000000000001"),
                ("size", "     0 NOTYPE", "     8 NOTYPE"),
                ("type", "NOTYPE", "OBJECT"),
                ("binding", "WEAK", "GLOBAL"),
                ("visibility", "HIDDEN", "DEFAULT"),
                ("definition", "UND", "24")):
            adverse.append(("stop-only " + label, sanitized + anchors,
                            start_row + stop_row.replace(old, changed), "clang", True))
        for compiler in ("gcc", "clang"):
            for name in ("__asan_init", "__ubsan_handle_add_overflow_abort"):
                adverse.append(("normal runtime " + compiler + " " + name,
                                ordinary + " U " + name + "\n", elf, compiler, False))
        for name in ("getrandom", "pthread_create", "pqbtc_mldsa44_key_sign", "keypair"):
            adverse.append((name, sanitized + " U " + name + "\n", elf, "clang", True))
        for label, imports, metadata, compiler, sanitize in adverse:
            with self.subTest(rejected=label), self.assertRaises(RuntimeError):
                audit(imports, compiler=compiler, sanitized=sanitize, elf_symbols=metadata)

    def test_verifier_export_audit_requires_typed_section_joined_clang_asan_pair(self):
        spec = importlib.util.spec_from_file_location("native_export_audit_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        audit = getattr(runner, "validate_verifier_exports", None)
        self.assertTrue(callable(audit), "pure verifier export audit is absent")
        api = "pqbtc_mldsa44_node_verify"
        ordinary_nm = "0000000000001120 T pqbtc_mldsa44_node_verify\n"
        ordinary_elf = """Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000001120 12328 FUNC    GLOBAL DEFAULT    1 pqbtc_mldsa44_node_verify
"""
        ordinary_sections = """There are 2 section headers, starting at offset 0x5000:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000001060 001060 00427a 00  AX  0   0 16
Key to Flags:
  W (write), A (alloc), X (execute)
"""
        # Public Clang 20 / GNU ld 2.40 linked fixture, including every dynamic
        # symbol and section row. This is data, not a native qualification claim.
        actual_nm = ("000000000000fc30 D __start_asan_globals\n"
                     "000000000000fd30 D __stop_asan_globals\n"
                     "0000000000004638 T pqbtc_mldsa44_node_verify\n")
        actual_elf = """Symbol table '.dynsym' contains 42 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_register_elf_globals
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_load8
     3: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __asan_report_load2
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_load4
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_set_shadow_f8
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_stack_free_9
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __sanitizer_internal_memcpy
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __sanitizer_internal_memset
    10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __sanitizer_internal_memmove
    11: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __asan_report_store16
    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_set_shadow_00
    13: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __asan_report_store2
    14: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_sub_overflow_abort
    15: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_store4
    16: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_store8
    17: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_pointer_overflow_abort
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_type_mismatch_v1_abort
    19: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    20: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_load1
    21: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_add_overflow_abort
    22: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_set_shadow_f5
    23: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_stack_malloc_3
    24: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_stack_malloc_9
    25: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __asan_report_load16
    26: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_init
    27: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_out_of_bounds_abort
    28: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_negate_overflow_abort
    29: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_report_store1
    30: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_shift_out_of_bounds_abort
    31: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_version_mismatch_check_v8
    32: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_memcpy
    33: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_unregister_elf_globals
    34: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    35: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __ubsan_handle_mul_overflow_abort
    36: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
    37: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND __asan_option_detect_stack_use_after_return
    38: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __asan_memset
    39: 000000000000fc30     0 NOTYPE  GLOBAL HIDDEN    23 __start_asan_globals
    40: 000000000000fd30     0 NOTYPE  GLOBAL HIDDEN    23 __stop_asan_globals
    41: 0000000000004638 11294 FUNC    GLOBAL DEFAULT   12 pqbtc_mldsa44_node_verify
"""
        actual_sections = """There are 38 section headers, starting at offset 0x22970:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.build-id NOTE            0000000000000238 000238 000024 00   A  0   0  4
  [ 2] .gnu.hash         GNU_HASH        0000000000000260 000260 000030 00   A  3   0  8
  [ 3] .dynsym           DYNSYM          0000000000000290 000290 0003f0 18   A  4   1  8
  [ 4] .dynstr           STRTAB          0000000000000680 000680 00044c 00   A  0   0  1
  [ 5] .gnu.version      VERSYM          0000000000000acc 000acc 000054 02   A  3   0  2
  [ 6] .gnu.version_r    VERNEED         0000000000000b20 000b20 000020 00   A  4   1  8
  [ 7] .rela.dyn         RELA            0000000000000b40 000b40 001380 18   A  3   0  8
  [ 8] .rela.plt         RELA            0000000000001ec0 001ec0 0002d0 18  AI  3  21  8
  [ 9] .init             PROGBITS        0000000000003000 003000 000017 00  AX  0   0  4
  [10] .plt              PROGBITS        0000000000003020 003020 0001f0 10  AX  0   0 16
  [11] .plt.got          PROGBITS        0000000000003210 003210 000008 08  AX  0   0  8
  [12] .text             PROGBITS        0000000000003220 003220 007250 00  AX  0   0 16
  [13] .fini             PROGBITS        000000000000a470 00a470 000009 00  AX  0   0  4
  [14] .rodata           PROGBITS        000000000000b000 00b000 0010a0 00   A  0   0 32
  [15] .eh_frame_hdr     PROGBITS        000000000000c0a0 00c0a0 0004ec 00   A  0   0  4
  [16] .eh_frame         PROGBITS        000000000000c590 00c590 000d9c 00   A  0   0  8
  [17] .init_array       INIT_ARRAY      000000000000edb8 00ddb8 000010 08  WA  0   0  8
  [18] .fini_array       FINI_ARRAY      000000000000edc8 00ddc8 000010 08  WA  0   0  8
  [19] .dynamic          DYNAMIC         000000000000edd8 00ddd8 0001e0 10  WA  4   0  8
  [20] .got              PROGBITS        000000000000efb8 00dfb8 000030 08  WA  0   0  8
  [21] .got.plt          PROGBITS        000000000000efe8 00dfe8 000108 08  WA  0   0  8
  [22] .data             PROGBITS        000000000000f0f0 00e0f0 000b40 00  WA  0   0 16
  [23] asan_globals      PROGBITS        000000000000fc30 00ec30 000100 00 WAL 24   0 16
  [24] .bss              NOBITS          000000000000fd40 00ed30 000050 00  WA  0   0 32
  [25] .comment          PROGBITS        0000000000000000 00ed30 00007d 01  MS  0   0  1
  [26] .debug_info       PROGBITS        0000000000000000 00edad 002a12 00      0   0  1
  [27] .debug_abbrev     PROGBITS        0000000000000000 0117bf 000403 00      0   0  1
  [28] .debug_line       PROGBITS        0000000000000000 011bc2 0022b3 00      0   0  1
  [29] .debug_str        PROGBITS        0000000000000000 013e75 0010ad 01  MS  0   0  1
  [30] .debug_addr       PROGBITS        0000000000000000 014f22 000300 00      0   0  1
  [31] .debug_line_str   PROGBITS        0000000000000000 015222 0002ad 01  MS  0   0  1
  [32] .debug_loclists   PROGBITS        0000000000000000 0154cf 007689 00      0   0  1
  [33] .debug_rnglists   PROGBITS        0000000000000000 01cb58 000625 00      0   0  1
  [34] .debug_str_offsets PROGBITS        0000000000000000 01d17d 0004d8 00      0   0  1
  [35] .symtab           SYMTAB          0000000000000000 01d658 002838 18     36 388  8
  [36] .strtab           STRTAB          0000000000000000 01fe90 002960 00      0   0  1
  [37] .shstrtab         STRTAB          0000000000000000 0227f0 00017e 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
"""
        for compiler in ("gcc", "clang"):
            for sanitized in (False, True):
                with self.subTest(accepted=compiler, sanitized=sanitized):
                    self.assertEqual(audit(ordinary_nm, compiler=compiler, sanitized=sanitized,
                                           elf_dynamic_symbols=ordinary_elf,
                                           elf_sections=ordinary_sections), [api])
        self.assertEqual(audit(actual_nm, compiler="clang", sanitized=True,
                               elf_dynamic_symbols=actual_elf, elf_sections=actual_sections), [api])
        self.assertEqual(audit(actual_nm, compiler="clang", sanitized=True,
                               elf_dynamic_symbols=actual_elf,
                               elf_sections=actual_sections.replace("00 WAL 24", "00  WA 24")), [api])
        start_nm, stop_nm, api_nm = actual_nm.splitlines(keepends=True)
        start_elf, stop_elf, api_elf = actual_elf.splitlines(keepends=True)[-3:]
        asan_section = next(line for line in actual_sections.splitlines(keepends=True) if "[23]" in line)
        adverse = [
            ("Clang normal anchors", actual_nm, actual_elf, actual_sections, "clang", False),
            ("GCC sanitized anchors", actual_nm, actual_elf, actual_sections, "gcc", True),
            ("GCC normal anchors", actual_nm, actual_elf, actual_sections, "gcc", False),
            ("one-sided nm", stop_nm + api_nm, actual_elf, actual_sections, "clang", True),
            ("joined one-sided pair", start_nm + api_nm,
             actual_elf.replace(stop_elf, "").replace("42 entries", "41 entries").replace("41:", "40:"),
             actual_sections, "clang", True),
            ("no nm anchors", api_nm, actual_elf, actual_sections, "clang", True),
            ("nm-only anchors", actual_nm, ordinary_elf, ordinary_sections, "clang", True),
            ("duplicate nm", actual_nm + start_nm, actual_elf, actual_sections, "clang", True),
            ("malformed nm", actual_nm + "malformed\n", actual_elf, actual_sections, "clang", True),
            ("extra nm fields", actual_nm.replace(" D ", " extra D "), actual_elf, actual_sections, "clang", True),
            ("nm API address", actual_nm.replace("4638 T", "4639 T"), actual_elf, actual_sections, "clang", True),
            ("nm anchor address", actual_nm.replace("fc30 D", "fc31 D"), actual_elf, actual_sections, "clang", True),
            ("nm API data", actual_nm.replace(" T ", " D "), actual_elf, actual_sections, "clang", True),
            ("nm weak anchor", actual_nm.replace(" D ", " V "), actual_elf, actual_sections, "clang", True),
            ("nm text anchor", actual_nm.replace(" D ", " T "), actual_elf, actual_sections, "clang", True),
            ("nm negative address", actual_nm.replace("000000000000fc30", "-fc30"), actual_elf, actual_sections, "clang", True),
            ("missing dynsym", actual_nm, "", actual_sections, "clang", True),
            ("wrong table", actual_nm, actual_elf.replace(".dynsym", ".symtab"), actual_sections, "clang", True),
            ("multiple tables", actual_nm, actual_elf + ordinary_elf, actual_sections, "clang", True),
            ("truncated table", actual_nm, actual_elf.replace(api_elf, ""), actual_sections, "clang", True),
            ("understated count", actual_nm, actual_elf.replace("42 entries", "41 entries"), actual_sections, "clang", True),
            ("overstated count", actual_nm, actual_elf.replace("42 entries", "43 entries"), actual_sections, "clang", True),
            ("duplicate row index", actual_nm, actual_elf.replace("40:", "39:"), actual_sections, "clang", True),
            ("duplicate symbol", actual_nm, actual_elf.replace("__stop_asan_globals", "__start_asan_globals"), actual_sections, "clang", True),
            ("one-sided ELF", actual_nm, actual_elf.replace(stop_elf, "").replace("42 entries", "41 entries"), actual_sections, "clang", True),
            ("malformed ELF row", actual_nm, actual_elf.replace("40:", "not-index:"), actual_sections, "clang", True),
            ("ELF extra field", actual_nm, actual_elf.replace(api_elf, api_elf.rstrip() + " extra\n"), actual_sections, "clang", True),
            ("unexpected ELF text", actual_nm, actual_elf + "ignored diagnostic\n", actual_sections, "clang", True),
            ("missing symbol columns", actual_nm, actual_elf.replace("   Num:", "   Missing:"), actual_sections, "clang", True),
            ("invalid null symbol", actual_nm, actual_elf.replace("0 NOTYPE  LOCAL", "1 NOTYPE  LOCAL"), actual_sections, "clang", True),
            ("missing sections", actual_nm, actual_elf, "", "clang", True),
            ("section count mismatch", actual_nm, actual_elf, actual_sections.replace("38 section", "37 section"), "clang", True),
            ("duplicate section index", actual_nm, actual_elf, actual_sections.replace("[24]", "[23]"), "clang", True),
            ("truncated sections", actual_nm, actual_elf, actual_sections.replace(asan_section, ""), "clang", True),
            ("duplicate section name", actual_nm, actual_elf, actual_sections.replace(".comment", "asan_globals"), "clang", True),
            ("extra section after footer", actual_nm, actual_elf, actual_sections + asan_section, "clang", True),
            ("invalid null section", actual_nm, actual_elf, actual_sections.replace("NULL            0000000000000000", "NULL            0000000000000001"), "clang", True),
            ("missing API", start_nm + stop_nm, actual_elf.replace(api_elf, ""), actual_sections, "clang", True),
            ("API undefined", actual_nm, actual_elf.replace(api_elf, api_elf.replace("12 pqbtc", "UND pqbtc")), actual_sections, "clang", True),
            ("API nontext section", actual_nm, actual_elf.replace(api_elf, api_elf.replace("12 pqbtc", "23 pqbtc")), actual_sections, "clang", True),
            ("API zero size", actual_nm, actual_elf.replace("11294 FUNC", "0 FUNC"), actual_sections, "clang", True),
            ("API outside text", actual_nm, actual_elf.replace("11294 FUNC", "999999 FUNC"), actual_sections, "clang", True),
            ("API text nonexec", actual_nm, actual_elf, actual_sections.replace("007250 00  AX", "007250 00   A"), "clang", True),
            ("API text writable", actual_nm, actual_elf, actual_sections.replace("007250 00  AX", "007250 00 WAX"), "clang", True),
            ("API text renamed", actual_nm, actual_elf, actual_sections.replace(".text", ".code"), "clang", True),
            ("API text NOBITS", actual_nm, actual_elf,
             actual_sections.replace(".text             PROGBITS", ".text             NOBITS"), "clang", True),
            ("joined misaligned bounds", actual_nm.replace("fc30", "fc31").replace("fd30", "fd31"),
             actual_elf.replace("fc30", "fc31").replace("fd30", "fd31"),
             actual_sections.replace("000000000000fc30", "000000000000fc31"), "clang", True),
        ]
        for label, old, changed in (
                ("binding", "GLOBAL", "WEAK"), ("visibility", "HIDDEN", "DEFAULT"),
                ("protected", "HIDDEN", "PROTECTED"), ("type", "NOTYPE", "OBJECT"),
                ("size", "     0 NOTYPE", "     8 NOTYPE"),
                ("index", "23 __", "24 __"), ("undefined", "23 __", "UND __"),
                ("absolute", "23 __", "ABS __")):
            for name, row in (("start", start_elf), ("stop", stop_elf)):
                adverse.append((name + " " + label, actual_nm, actual_elf.replace(row, row.replace(old, changed)),
                                actual_sections, "clang", True))
        for label, old, changed in (
                ("API hidden", "DEFAULT", "HIDDEN"), ("API protected", "DEFAULT", "PROTECTED"),
                ("API weak", "GLOBAL", "WEAK"), ("API object", "FUNC", "OBJECT")):
            adverse.append((label, actual_nm, actual_elf.replace(api_elf, api_elf.replace(old, changed)),
                            actual_sections, "clang", True))
        for label, old, changed in (
                ("wrong section name", "asan_globals", "asan_private"),
                ("section NOBITS", "PROGBITS", "NOBITS"),
                ("zero section", "000100", "000000"),
                ("executable section", "WAL", "WAXL"),
                ("nonalloc section", "WAL", "WL"),
                ("readonly section", "WAL", "AL"),
                ("unknown flags", "WAL", "WALx"),
                ("bad alignment", " 0 16", " 0  8"),
                ("zero alignment", " 0 16", " 0  0"),
                ("bad section start", "000000000000fc30", "000000000000fc20"),
                ("bad section end", "000100", "000110"),
                ("misaligned section", "000000000000fc30", "000000000000fc31")):
            adverse.append((label, actual_nm, actual_elf,
                            actual_sections.replace(asan_section, asan_section.replace(old, changed)), "clang", True))
        for name in ("__start_asan_globals_extra", "__stop_asan_globals_extra", "__start_private",
                     "__stop_private", "pqbtc_mldsa44_node_upstream_keypair", "private_hidden"):
            # Even exact nm/ELF joins and HIDDEN visibility cannot excuse a
            # defined private export or an arbitrary section-anchor spelling.
            adverse.append((name, actual_nm + "000000000000fc30 D " + name + "\n",
                            actual_elf.replace("42 entries", "43 entries")
                            + "42: 000000000000fc30 0 NOTYPE GLOBAL HIDDEN 23 " + name + "\n",
                            actual_sections, "clang", True))
        for visibility in ("DEFAULT", "PROTECTED", "HIDDEN"):
            adverse.append(("private FUNC GLOBAL " + visibility,
                            actual_nm + "0000000000004638 T private_signer\n",
                            actual_elf.replace("42 entries", "43 entries")
                            + "42: 0000000000004638 16 FUNC GLOBAL " + visibility + " 12 private_signer\n",
                            actual_sections, "clang", True))
        for label, nm, symbols, sections, compiler, sanitized in (
                ("non-string nm", None, actual_elf, actual_sections, "clang", True),
                ("bytes nm", actual_nm.encode(), actual_elf, actual_sections, "clang", True),
                ("non-string ELF", actual_nm, None, actual_sections, "clang", True),
                ("non-string sections", actual_nm, actual_elf, None, "clang", True),
                ("integer sanitized", actual_nm, actual_elf, actual_sections, "clang", 1),
                ("string sanitized", actual_nm, actual_elf, actual_sections, "clang", "true"),
                ("unknown compiler", actual_nm, actual_elf, actual_sections, "cc", True),
                ("non-string compiler", actual_nm, actual_elf, actual_sections, ["clang"], True)):
            adverse.append((label, nm, symbols, sections, compiler, sanitized))
        for label, nm, symbols, sections, compiler, sanitized in adverse:
            with self.subTest(rejected=label), self.assertRaises(RuntimeError):
                audit(nm, compiler=compiler, sanitized=sanitized,
                      elf_dynamic_symbols=symbols, elf_sections=sections)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Native compiler matrix requires contained Linux")
    def test_real_guarded_signer_and_public_transaction_verifier(self):
        for cc, cxx in [("gcc", "g++"), ("clang", "clang++")]:
            for sanitized in (False, True):
                with self.subTest(cc=cc, sanitized=sanitized):
                    command = [sys.executable, str(RUNNER), "--cc", cc, "--cxx", cxx]
                    if sanitized:
                        command.append("--sanitize")
                    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report["result"], "PASS")
                    self.assertEqual(report["verifier_exports"], ["pqbtc_mldsa44_node_verify"])
                    self.assertGreaterEqual(report["negative_checks"], 15)
                    self.assertEqual(report["python_contract_join"], "PASS")
                    self.assertEqual(report.get("network_artifact_join"), "PASS")
                    dependencies = report.get("compiler_dependency_hashes", {})
                    for required in ("contrib/ml-dsa-key-lifecycle/key_runtime.c",
                                     "contrib/ml-dsa-key-lifecycle/key_lifecycle.h",
                                     "contrib/ml-dsa-engineering/vendor/mldsa-native/mldsa/mldsa_native.h"):
                        self.assertIn(required, dependencies)
                    self.assertEqual(report["node_linked"], False)
                    # Four source-bound public audit receipts in full-suite
                    # stdout; not a product API or the signer fixture report.
                    export_audit = report["verifier_export_audit"]
                    self.assertEqual(set(export_audit), {"nm_defined", "elf_dynamic_symbols", "elf_sections"})
                    self.assertTrue(all(type(value) is str and 0 < len(value) <= 65536
                                        for value in export_audit.values()))
                    print(json.dumps({"classification": "SOURCE_BOUND_VERIFIER_EXPORT_AUDIT",
                                      "cc": cc, "sanitized": sanitized,
                                      "verifier_exports": report["verifier_exports"],
                                      "verifier_export_audit": export_audit,
                                      "source_hashes": report["source_hashes"],
                                      "binary_hashes": report["binary_hashes"]}, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
