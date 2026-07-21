#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
DRIVER = ENGINEERING_DIR / "run_differential_verifier_fuzz.py"
FUZZ_SOURCE = ENGINEERING_DIR / "pqbtc_mldsa44_verify_fuzz.c"
OPENSSL_BRIDGE = ENGINEERING_DIR / "pqbtc_mldsa44_openssl_verify.c"
LIBCRUX_BRIDGE = ENGINEERING_DIR / "pqbtc_mldsa44_libcrux_verify.rs"
REPLAY_SOURCE = ENGINEERING_DIR / "pqbtc_mldsa44_differential_replay.c"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-review-reproduction.yml"
ADMISSION = ENGINEERING_DIR / "backend_admission.json"

sys.path.insert(0, str(ENGINEERING_DIR))
SPEC = importlib.util.spec_from_file_location("run_differential_verifier_fuzz", DRIVER)
assert SPEC is not None and SPEC.loader is not None
differential = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = differential
SPEC.loader.exec_module(differential)


class MlDsaDifferentialFuzzTest(unittest.TestCase):
    def test_manifest_only_cli(self):
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--manifest-only"],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("wrapper + OpenSSL 3.6.3 + libcrux 0.0.10", completed.stdout)

    def test_differential_compile_contract(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            differential.verifier_fuzz.wrapper, "run"
        ) as run:
            differential.verifier_fuzz.compile_fuzzer(
                "clang",
                Path(temporary),
                sanitizer="address-undefined",
                coverage=True,
                differential_sources=(OPENSSL_BRIDGE,),
                differential_link_args=("libcrux.so", "-lcrypto"),
            )

        command = run.call_args.args[0]
        self.assertIn("-DPQBTC_MLDSA44_DIFFERENTIAL=1", command)
        self.assertIn(str(OPENSSL_BRIDGE), command)
        self.assertIn("libcrux.so", command)
        self.assertIn("-lcrypto", command)
        self.assertIn("-fsanitize=fuzzer,address,undefined", command)

    def test_external_bridges_are_binary_and_in_process(self):
        openssl_source = OPENSSL_BRIDGE.read_text(encoding="utf8")
        self.assertIn("EVP_PKEY_verify_message_init", openssl_source)
        self.assertIn("EVP_PKEY_verify(", openssl_source)
        self.assertIn("PQBTC_MLDSA44_ORACLE_ERROR", openssl_source)

        libcrux_source = LIBCRUX_BRIDGE.read_text(encoding="utf8")
        self.assertIn("portable::verify", libcrux_source)
        self.assertIn('extern "C" fn pqbtc_mldsa44_libcrux_verify', libcrux_source)
        self.assertNotIn("Command::", libcrux_source)

        replay_source = REPLAY_SOURCE.read_text(encoding="utf8")
        self.assertIn("LLVMFuzzerTestOneInput(input, input_size)", replay_source)
        self.assertIn("PQBTC_MLDSA44_FUZZ_MAX_FRAME_BYTES 8096U", replay_source)

    def test_evidence_inventory_covers_execution_inputs(self):
        manifest = differential.reference.load_manifest()
        inventory = differential.validate_local_inputs(manifest)
        for path in (
            DRIVER,
            REPO_ROOT / "contrib" / "ml-dsa-ref" / "compare_oracles.py",
            REPO_ROOT / "contrib" / "ml-dsa-ref" / "libcrux_oracle.rs",
            FUZZ_SOURCE,
            OPENSSL_BRIDGE,
            LIBCRUX_BRIDGE,
            REPLAY_SOURCE,
            WORKFLOW,
        ):
            self.assertIn(str(path.relative_to(REPO_ROOT)), inventory)

    def test_exact_replay_cases_match_frozen_frames(self):
        with tempfile.TemporaryDirectory() as temporary:
            library = differential.verifier_fuzz.wrapper.compile_shared(
                "cc", Path(temporary), testing=True
            )
            cases = {
                case.name: case
                for case in differential.verifier_fuzz.project_corpus(library)
            }
        actual = {
            name: (
                "accept"
                if cases[name].expected == differential.verifier_fuzz.OK
                else "reject",
                hashlib.sha256(cases[name].frame).hexdigest(),
            )
            for name in differential.SMOKE_CASE_NAMES
        }
        self.assertEqual(
            actual,
            {
                "valid_frozen_vector": (
                    "accept",
                    "1f1400abcc4219a5bb48c05e7f35525a9c98861f7b14fe8cfd8653dd52ca001d",
                ),
                "valid_empty_message_context": (
                    "accept",
                    "34335fc41196fad28e8970efd5386acfd0ad7aa0d1bebca6b8d6237ef97b44c4",
                ),
                "reject_ctilde_bit_flip": (
                    "reject",
                    "dd431b2d49e7ebf65bd4d6d6d14ec56e7d9bd433a9602e9aedb51218c267655f",
                ),
                "reject_hint_counter_overflow": (
                    "reject",
                    "f9ab7ac3eb9ff8a2a278abc63ed58955f939b2e281555177ad9dcaf4aab0741f",
                ),
                "reject_null_signature": (
                    "reject",
                    "ccd69d2b0691117dafce3ccaa79096cf13ce86d96fa153d21878eec5830aaaa7",
                ),
            },
        )

    def test_exact_replay_records_the_failing_named_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = differential.verifier_fuzz.wrapper.compile_shared(
                "cc", root, testing=True
            )
            cases = differential.verifier_fuzz.project_corpus(library)
            executable = root / "replay-stub"
            executable.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  *reject_ctilde_bit_flip) exit 7 ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf8",
            )
            executable.chmod(0o755)
            output = root / "evidence"
            output.mkdir()
            records = differential.replay_differential_smoke(
                executable, cases, output
            )

            failures = [record for record in records if record["status"] == "fail"]
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["name"], "reject_ctilde_bit_flip")
            self.assertEqual(failures[0]["return_code"], 7)
            self.assertIn(
                "case: reject_ctilde_bit_flip",
                (output / "differential-smoke.log").read_text(encoding="utf8"),
            )

    def test_target_catches_acceptance_disagreement_and_oracle_error(self):
        compiler = "cc"
        stub_source = textwrap.dedent(
            r"""
            #include "pqbtc_mldsa44.h"
            #include "pqbtc_mldsa44_differential.h"
            #include <stdint.h>
            #include <stdlib.h>

            int wrapper_result;
            int openssl_result;
            int libcrux_result;

            int pqbtc_mldsa44_verify_strict(
                const uint8_t* signature, size_t signature_size,
                const uint8_t* public_key, size_t public_key_size,
                const uint8_t* message, size_t message_size,
                const uint8_t* context, size_t context_size)
            {
                (void)signature; (void)signature_size;
                (void)public_key; (void)public_key_size;
                (void)message; (void)message_size;
                (void)context; (void)context_size;
                return wrapper_result;
            }

            int pqbtc_mldsa44_openssl_verify(
                const uint8_t* signature, size_t signature_size,
                const uint8_t* public_key, size_t public_key_size,
                const uint8_t* message, size_t message_size,
                const uint8_t* context, size_t context_size)
            {
                (void)signature; (void)signature_size;
                (void)public_key; (void)public_key_size;
                (void)message; (void)message_size;
                (void)context; (void)context_size;
                return openssl_result;
            }

            int pqbtc_mldsa44_libcrux_verify(
                const uint8_t* signature, size_t signature_size,
                const uint8_t* public_key, size_t public_key_size,
                const uint8_t* message, size_t message_size,
                const uint8_t* context, size_t context_size)
            {
                (void)signature; (void)signature_size;
                (void)public_key; (void)public_key_size;
                (void)message; (void)message_size;
                (void)context; (void)context_size;
                return libcrux_result;
            }

            size_t LLVMFuzzerMutate(
                uint8_t* data, size_t size, size_t max_size)
            {
                (void)data; (void)max_size;
                return size;
            }

            int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

            int main(int argc, char** argv)
            {
                uint8_t frame[10 + 2420 + 1312] = {0};
                if (argc != 4) return 2;
                wrapper_result = atoi(argv[1]);
                openssl_result = atoi(argv[2]);
                libcrux_result = atoi(argv[3]);
                frame[0] = 1;
                frame[2] = 0x74;
                frame[3] = 0x09;
                frame[4] = 0x20;
                frame[5] = 0x05;
                return LLVMFuzzerTestOneInput(frame, sizeof(frame));
            }
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stub = root / "stub.c"
            executable = root / "differential-contract"
            stub.write_text(stub_source, encoding="utf8")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DPQBTC_MLDSA44_DIFFERENTIAL=1",
                    f"-I{ENGINEERING_DIR}",
                    str(FUZZ_SOURCE),
                    str(stub),
                    "-o",
                    str(executable),
                ],
                check=True,
            )

            for arguments in (("0", "1", "1"), ("-9", "0", "0")):
                with self.subTest(arguments=arguments):
                    completed = subprocess.run(
                        [str(executable), *arguments],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

            disagreement = subprocess.run(
                [str(executable), "0", "0", "0"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(disagreement.returncode, 0)
            self.assertIn("DIFFERENTIAL_DISAGREEMENT", disagreement.stderr)

            oracle_error = subprocess.run(
                [str(executable), "-9", "-1", "0"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(oracle_error.returncode, 0)
            self.assertIn("DIFFERENTIAL_ORACLE_ERROR", oracle_error.stderr)

    def test_pinned_workflow_runs_and_retains_differential_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        for required in (
            '"contrib/ml-dsa-engineering/**"',
            "run_differential_verifier_fuzz.py",
            "RUSTUP_TOOLCHAIN=1.89.0",
            "FUZZ_CC=clang",
            "--seconds 60",
            "--seed 188",
            "sha256sum --check SHA256SUMS",
            'smoke["case_count"] == 5',
            'fuzz_report["executed_units"] > 207',
            'fuzz_report["fuzzer_duration_seconds"] <= 95',
            'openssl_runtime["libcrypto_resolution"] == "linked-dependency"',
            'openssl_runtime["openssl_conf"] == "/dev/null"',
            "if-no-files-found: error",
            "ml-dsa-44-differential-fuzz-run.json",
            "ml-dsa-44-differential-fuzz-run.sha256",
            "ml-dsa-44-differential-fuzz/",
            "retention-days: 90",
        ):
            self.assertIn(required, workflow)

    def test_release_hold_remains_unchanged(self):
        admission = json.loads(ADMISSION.read_text(encoding="utf8"))
        self.assertTrue(admission["decision"]["release_hold"])
        self.assertEqual(admission["decision"]["production_backend"], "NONE")


if __name__ == "__main__":
    unittest.main()
