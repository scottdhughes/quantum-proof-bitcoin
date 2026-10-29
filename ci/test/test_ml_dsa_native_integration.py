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


if __name__ == "__main__":
    unittest.main()
