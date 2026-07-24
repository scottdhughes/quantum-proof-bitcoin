#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-sustained-fuzz.yml"

sys.path.insert(0, str(ENGINEERING_DIR))
import run_stateful_signer_fuzz as signer_fuzz  # noqa: E402


class MlDsaStatefulSignerFuzzTest(unittest.TestCase):
    def test_manifest_and_generated_corpus_are_frozen(self):
        cases = signer_fuzz.generated_corpus()
        summary = signer_fuzz.validate_corpus_manifest(cases)

        self.assertEqual(summary["total_cases"], 31)
        self.assertEqual(summary["unique_frames"], 31)
        self.assertEqual(
            set(summary["scenario_counts"]),
            {
                *signer_fuzz.SCENARIOS.values(),
                signer_fuzz.INVALID_CONTEXT_SCENARIO,
            },
        )
        self.assertTrue(all(summary["scenario_counts"].values()))
        self.assertEqual(
            summary["invalid_argument_variant_counts"],
            {
                **{name: 1 for name in signer_fuzz.ARGUMENT_VARIANTS.values()},
                "alias_message": 2,
            },
        )
        self.assertEqual(
            summary["aggregate_sha256"],
            "9ee9c275e59e8a4d383bd474b080406b764aafd9b219dffb522d9ef4e73f05d1",
        )
        manifest = json.loads(
            signer_fuzz.CORPUS_MANIFEST.read_text(encoding="utf8")
        )
        self.assertEqual(
            manifest["fuzz_limits"]["hedged_signing_calls_per_input_max"],
            4,
        )

    def test_frames_round_trip_and_enforce_bounds(self):
        for case in signer_fuzz.generated_corpus():
            decoded = signer_fuzz.decode_frame(case.frame)
            self.assertEqual(
                signer_fuzz.encode_frame(**decoded.__dict__),
                case.frame,
            )
            self.assertLessEqual(len(case.frame), signer_fuzz.MAX_FRAME_BYTES)

        case = signer_fuzz.generated_corpus()[0]
        with self.assertRaises(signer_fuzz.StatefulFuzzError):
            signer_fuzz.decode_frame(case.frame[:-1])
        with self.assertRaises(signer_fuzz.StatefulFuzzError):
            signer_fuzz.encode_frame(
                **{
                    **signer_fuzz.decode_frame(case.frame).__dict__,
                    "context": bytes(signer_fuzz.MAX_CONTEXT_BYTES + 1),
                }
            )
        with self.assertRaises(signer_fuzz.StatefulFuzzError):
            signer_fuzz.encode_frame(
                **{
                    **signer_fuzz.decode_frame(case.frame).__dict__,
                    "short_length": 32,
                }
            )

    def test_corpus_has_state_and_size_boundaries(self):
        decoded = {
            case.name: signer_fuzz.decode_frame(case.frame)
            for case in signer_fuzz.generated_corpus()
        }
        self.assertEqual(decoded["fresh_empty_message_and_context"].message, b"")
        self.assertEqual(decoded["fresh_empty_message_and_context"].context, b"")
        self.assertEqual(len(decoded["fresh_maximum_context"].context), 255)
        self.assertEqual(
            len(
                decoded[
                    "fresh_a_then_invalid_256_context_then_repeat_a_then_fresh_b"
                ].context
            ),
            256,
        )
        self.assertEqual(len(decoded["fresh_maximum_message"].message), 4096)
        self.assertEqual(
            len(
                decoded[
                    "fresh_a_then_invalid_alias_message_maximum_message_then_repeat_a_then_fresh_b"
                ].message
            ),
            4096,
        )
        self.assertEqual(
            {
                frame.short_length
                for frame in decoded.values()
                if frame.scenario == 2
            },
            {0, 1, 16, 31},
        )

    def test_manifest_only_cli_replays_validation(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ENGINEERING_DIR / "run_stateful_signer_fuzz.py"),
                "--manifest-only",
            ],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIn("31 cases, 31 unique frames", completed.stdout)

    def test_compile_contracts_are_distinct_and_testing_only(self):
        contracts = (
            (
                "address-undefined",
                True,
                {"-fsanitize=fuzzer,address,undefined", "-fprofile-instr-generate"},
                {"-fsanitize=fuzzer,memory", "-fsanitize-memory-track-origins=2"},
            ),
            (
                "memory",
                False,
                {"-fsanitize=fuzzer,memory", "-fsanitize-memory-track-origins=2", "-pie"},
                {"-fsanitize=fuzzer,address,undefined", "-fprofile-instr-generate"},
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for sanitizer, coverage, required, prohibited in contracts:
                with self.subTest(sanitizer=sanitizer):
                    with mock.patch.object(signer_fuzz.wrapper, "run") as run:
                        signer_fuzz.compile_fuzzer(
                            "clang",
                            Path(temporary),
                            sanitizer=sanitizer,
                            coverage=coverage,
                        )
                    command = set(run.call_args.args[0])
                    self.assertIn("-DPQBTC_MLDSA44_TESTING=1", command)
                    self.assertTrue(required <= command)
                    self.assertTrue(prohibited.isdisjoint(command))
                    self.assertIn(str(signer_fuzz.FUZZ_SOURCE), command)
                    self.assertIn(str(signer_fuzz.wrapper.WRAPPER_SOURCE), command)

    def test_deterministic_replay_records_every_named_case(self):
        cases = signer_fuzz.generated_corpus()[:2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            signer_fuzz.materialize_corpus(corpus, cases)
            completed = subprocess.CompletedProcess(
                args=["fuzzer"], returncode=0, stdout="", stderr=""
            )
            with mock.patch.object(
                signer_fuzz.subprocess, "run", return_value=completed
            ) as run:
                report = signer_fuzz.replay_corpus(
                    Path("fuzzer"),
                    corpus,
                    cases,
                    root / "replay.log",
                    sanitizer="address-undefined",
                    profile_pattern=None,
                )
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["case_count"], 2)
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all(case["status"] == "pass" for case in report["cases"]))
            self.assertIn("case:", (root / "replay.log").read_text(encoding="utf8"))

    def test_campaign_report_preserves_stateful_contract(self):
        cases = signer_fuzz.generated_corpus()
        summary = signer_fuzz.corpus_summary(cases)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for name in ("corpus", "minimized-corpus", "crashes"):
                (output / name).mkdir()
            (output / "corpus" / "seed").write_bytes(b"seed")
            (output / "minimized-corpus" / "seed").write_bytes(b"seed")
            fuzzer = output / "fuzzer"
            fuzzer.write_bytes(b"binary")
            completed = subprocess.CompletedProcess(
                args=["fuzzer"],
                returncode=0,
                stdout="",
                stderr=(
                    "#31 DONE\n"
                    "stat::number_of_executed_units: 31\n"
                    "stat::peak_rss_mb: 1\n"
                ),
            )
            signer_fuzz.write_campaign_report(
                output,
                compiler=sys.executable,
                sanitizer="address-undefined",
                coverage=False,
                runs=31,
                seconds=None,
                seed=188,
                retained_source=signer_fuzz.empty_retained_source(),
                retained_import=None,
                source_summary=summary,
                replay={"status": "pass", "case_count": 31, "cases": []},
                fuzzer=fuzzer,
                started_at="2026-07-23T00:00:00+00:00",
                duration_seconds=1.25,
                fuzzer_duration_seconds=1.0,
                completed=completed,
                processing_error=None,
                crash_minimization=[],
            )
            report = json.loads((output / "campaign.json").read_text(encoding="utf8"))
            self.assertEqual(report["target"], signer_fuzz.TARGET_NAME)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["executed_units"], 31)
            self.assertTrue(report["stateful_contract"]["seeded_keygen_determinism"])
            self.assertTrue(report["stateful_contract"]["entropy_request_accounting"])
            self.assertFalse(report["stateful_contract"]["external_oracles_in_process"])
            self.assertEqual(report["resource_limits"]["harness_frame_bytes"], 4456)
            self.assertEqual(report["minimized_corpus"]["file_count"], 1)
            self.assertIsNone(report["retained_corpus_import"])
            self.assertEqual(report["repository_head"], signer_fuzz.repository_head())
            for field in (
                "driver_sha256",
                "verifier_fuzz_driver_sha256",
                "wrapper_test_driver_sha256",
            ):
                self.assertRegex(report["source_files"][field], r"^[0-9a-f]{64}$")

    def test_invalid_retained_corpus_produces_hashed_failure_evidence(self):
        cases = signer_fuzz.generated_corpus()
        summary = signer_fuzz.corpus_summary(cases)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            args = SimpleNamespace(
                output_dir=output,
                seed_corpus=root / "missing-corpus",
                sanitizer="address-undefined",
                coverage=False,
                runs=1,
                seconds=None,
                seed=188,
            )
            with (
                mock.patch.object(
                    signer_fuzz.shutil, "which", return_value="/tool/clang"
                ),
                mock.patch.object(
                    signer_fuzz.verifier_fuzz,
                    "compiler_identity",
                    return_value={"path": "/tool/clang"},
                ),
                mock.patch.object(
                    signer_fuzz.verifier_fuzz,
                    "repository_commit",
                    return_value="a" * 40,
                ),
                mock.patch.object(
                    signer_fuzz.verifier_fuzz,
                    "repository_dirty",
                    return_value=False,
                ),
            ):
                self.assertEqual(
                    signer_fuzz.run_campaign(args, cases, summary),
                    1,
                )
            report = json.loads(
                (output / "campaign.json").read_text(encoding="utf8")
            )
            self.assertEqual(report["status"], "fail")
            self.assertIn("seed corpus does not exist", report["processing_error"])
            self.assertEqual(report["imported_retained_seeds"], 0)
            self.assertTrue((output / "SHA256SUMS").is_file())

    def test_retained_seed_import_is_strict_bounded_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            existing = b"existing"
            novel = b"novel"
            (destination / "project.bin").write_bytes(existing)
            (source / "duplicate-existing").write_bytes(existing)
            (source / "novel").write_bytes(novel)
            (source / "duplicate-novel").write_bytes(novel)

            expected_source = signer_fuzz.verifier_fuzz.directory_summary(source)
            (source / "novel").write_bytes(b"other")
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "differs from validated evidence",
            ):
                signer_fuzz.import_seed_corpus(
                    source,
                    destination,
                    expected_source_summary=expected_source,
                )
            (source / "novel").write_bytes(novel)

            receipt = signer_fuzz.import_seed_corpus(
                source,
                destination,
                expected_source_summary=expected_source,
            )
            self.assertEqual(receipt["source_summary"], expected_source)
            self.assertEqual(receipt["unique_source_summary"]["file_count"], 2)
            self.assertEqual(receipt["imported_summary"]["file_count"], 1)
            self.assertEqual(receipt["imported_summary"]["total_bytes"], len(novel))
            novel_digest = hashlib.sha256(novel).hexdigest()
            self.assertEqual(
                (destination / f"retained_{novel_digest}.bin").read_bytes(),
                novel,
            )
            self.assertEqual(
                signer_fuzz.import_seed_corpus(
                    source,
                    destination,
                    expected_source_summary=expected_source,
                )["imported_summary"]["file_count"],
                0,
            )

            nested = source / "nested"
            nested.mkdir()
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "not a regular file",
            ):
                signer_fuzz.import_seed_corpus(source, destination)
            nested.rmdir()

            (source / "oversized").write_bytes(
                bytes(signer_fuzz.MAX_FRAME_BYTES + 1)
            )
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "size bound",
            ):
                signer_fuzz.import_seed_corpus(source, destination)

    def test_retained_evidence_validation_binds_campaign_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            minimized = evidence / "minimized-corpus"
            minimized.mkdir()
            seed = minimized / "seed"
            seed.write_bytes(b"seed")
            head = "a" * 40
            campaign = {
                "target": signer_fuzz.TARGET_NAME,
                "status": "pass",
                "return_code": 0,
                "processing_error": None,
                "repository_commit": head,
                "repository_head": head,
                "repository_dirty": False,
                "sanitizer": "address-undefined",
                "minimized_corpus": signer_fuzz.verifier_fuzz.directory_summary(
                    minimized
                ),
            }
            (evidence / "campaign.json").write_text(
                json.dumps(campaign) + "\n",
                encoding="utf8",
            )
            signer_fuzz.verifier_fuzz.write_evidence_hashes(evidence)

            validation = signer_fuzz.validate_retained_evidence(
                evidence,
                expected_head=head,
                expected_sanitizer="address-undefined",
            )
            self.assertEqual(validation["restored_seed_file_count"], 1)
            self.assertRegex(
                validation["source_evidence_sha256"],
                r"^[0-9a-f]{64}$",
            )

            unchecked = evidence / "unchecked"
            unchecked.mkdir()
            (unchecked / "SHA256SUMS").write_text(
                "not the root manifest\n",
                encoding="utf8",
            )
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "checksum inventory differs",
            ):
                signer_fuzz.validate_retained_evidence(
                    evidence,
                    expected_head=head,
                    expected_sanitizer="address-undefined",
                )
            signer_fuzz.verifier_fuzz.write_evidence_hashes(evidence)
            self.assertIn(
                "unchecked/SHA256SUMS",
                (evidence / "SHA256SUMS").read_text(encoding="utf8"),
            )
            (unchecked / "SHA256SUMS").unlink()
            unchecked.rmdir()
            signer_fuzz.verifier_fuzz.write_evidence_hashes(evidence)

            seed.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "checksum differs",
            ):
                signer_fuzz.validate_retained_evidence(
                    evidence,
                    expected_head=head,
                    expected_sanitizer="address-undefined",
                )
            seed.write_bytes(b"seed")
            nested = minimized / "nested"
            nested.mkdir()
            (nested / "seed").write_bytes(b"nested")
            signer_fuzz.verifier_fuzz.write_evidence_hashes(evidence)
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "not a regular file",
            ):
                signer_fuzz.validate_retained_evidence(
                    evidence,
                    expected_head=head,
                    expected_sanitizer="address-undefined",
                )

    @unittest.skipIf(sys.platform == "win32", "symlink creation needs privileges")
    def test_retained_evidence_validation_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            target = root / "target"
            target.write_bytes(b"seed")
            (evidence / "linked").symlink_to(target)
            with self.assertRaisesRegex(
                signer_fuzz.StatefulFuzzError,
                "must not contain symlinks",
            ):
                signer_fuzz.validate_retained_evidence(
                    evidence,
                    expected_head="a" * 40,
                    expected_sanitizer="address-undefined",
                )

    def test_target_asserts_exact_state_transition_contract(self):
        target = signer_fuzz.FUZZ_SOURCE.read_text(encoding="utf8")
        for required in (
            "pqbtc_mldsa44_test_reset();",
            "pqbtc_mldsa44_test_keypair_from_seed(",
            "pqbtc_mldsa44_test_entropy_requests()",
            "pqbtc_mldsa44_test_entropy_requested_bytes()",
            "PQBTC_MLDSA44_ERR_ENTROPY_REPEAT",
            "PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO",
            "PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED",
            "PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH",
            "RequireInvalidArgumentDoesNotConsumeState",
            "RequireInvalidContextPreservesRepeatState",
            "RequireFreshThenEntropyFailurePreservesRepeat",
            "RequireFaultThenRepeat",
            "RequireSuccessfulSignature",
            "LLVMFuzzerCustomMutator",
        ):
            self.assertIn(required, target)
        entrypoint = target[target.index("int LLVMFuzzerTestOneInput") :]
        self.assertLess(
            entrypoint.index("pqbtc_mldsa44_test_reset();"),
            entrypoint.index("if (!ParseFrame"),
        )
        self.assertNotIn("openssl", target.lower())
        self.assertNotIn("libcrux", target.lower())

    def test_entropy_observability_is_test_only_and_reset(self):
        source = (ENGINEERING_DIR / "pqbtc_mldsa44.c").read_text(encoding="utf8")
        test_header = (ENGINEERING_DIR / "pqbtc_mldsa44_test.h").read_text(
            encoding="utf8"
        )
        public_header = (ENGINEERING_DIR / "pqbtc_mldsa44.h").read_text(
            encoding="utf8"
        )
        for symbol in (
            "pqbtc_mldsa44_test_entropy_requests",
            "pqbtc_mldsa44_test_entropy_requested_bytes",
        ):
            self.assertIn(symbol, source)
            self.assertIn(symbol, test_header)
            self.assertNotIn(symbol, public_header)
        self.assertIn(
            "atomic_store_explicit(&g_test_entropy_requests, 0",
            source,
        )
        self.assertIn(
            "atomic_store_explicit(&g_test_entropy_requested_bytes, 0",
            source,
        )

    def test_workflow_runs_separate_sanitizer_lanes_and_artifacts(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        for required in (
            "stateful-signer-fuzz:",
            "Stateful signer (${{ matrix.label }})",
            "run_stateful_signer_fuzz.py",
            "ml-dsa-44-stateful-signer-${{ matrix.artifact }}",
            "sanitizer: address-undefined",
            "sanitizer: memory",
            "campaign_seconds=1800",
            "campaign_seconds=60",
            "campaign_seed=188",
            "deterministic_replay",
            'assert report["repository_dirty"] is False',
            'assert expected_seconds - 1 <= report["fuzzer_duration_seconds"]',
            "git merge-base --is-ancestor",
            "--validate-retained-evidence",
            'assert report["repository_head"] == sys.argv[4]',
            "source_evidence_sha256",
            "restored_seed_file_count",
            "restored_seed_total_bytes",
            "restored_seed_aggregate_sha256",
            'report["retained_corpus_import"]',
            "sha256sum --check SHA256SUMS",
            "retention-days: 90",
        ):
            self.assertIn(required, workflow)
        self.assertIn(
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
