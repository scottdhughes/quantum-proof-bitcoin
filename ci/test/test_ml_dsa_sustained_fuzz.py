#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-sustained-fuzz.yml"
ADMISSION = ENGINEERING_DIR / "backend_admission.json"

sys.path.insert(0, str(ENGINEERING_DIR))
SPEC = importlib.util.spec_from_file_location(
    "run_verifier_fuzz",
    ENGINEERING_DIR / "run_verifier_fuzz.py",
)
assert SPEC is not None and SPEC.loader is not None
verifier_fuzz = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier_fuzz
SPEC.loader.exec_module(verifier_fuzz)


class MlDsaSustainedFuzzTest(unittest.TestCase):
    def test_frozen_corpus_source_hashes_match_current_inputs(self):
        manifest = json.loads(
            verifier_fuzz.CORPUS_MANIFEST.read_text(encoding="utf8")
        )
        self.assertEqual(
            manifest["sources"],
            {
                "repo_vectors_sha256": hashlib.sha256(
                    verifier_fuzz.wrapper.VECTORS.read_bytes()
                ).hexdigest(),
                "wycheproof_vectors_sha256": hashlib.sha256(
                    verifier_fuzz.WYCHEPROOF_VECTORS.read_bytes()
                ).hexdigest(),
                "promoted_source_sha256": hashlib.sha256(
                    verifier_fuzz.PROMOTED_SOURCE.read_bytes()
                ).hexdigest(),
            },
        )

    def test_promoted_source_is_frozen_disjoint_and_replays(self):
        promoted = verifier_fuzz.validate_promoted_source()
        self.assertEqual(len(promoted), 38)
        self.assertEqual(sum(len(case.frame) for case in promoted), 120844)
        self.assertEqual(
            {
                name: sum(
                    verifier_fuzz.RESULT_NAMES[case.expected] == name
                    for case in promoted
                )
                for name in ("invalid_argument", "verify_rejection")
            },
            {"invalid_argument": 13, "verify_rejection": 25},
        )

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            test_library = verifier_fuzz.wrapper.compile_shared(
                "cc", build, testing=True
            )
            production_library = verifier_fuzz.wrapper.compile_shared(
                "cc", build, testing=False
            )
            baseline = verifier_fuzz.project_corpus(
                test_library
            ) + verifier_fuzz.wycheproof_corpus(
                verifier_fuzz.validate_wycheproof_source()
            )
            summary = verifier_fuzz.validate_corpus_manifest(
                baseline + promoted
            )
            verifier_fuzz.replay_corpus(production_library, promoted)

        baseline_hashes = {
            hashlib.sha256(case.frame).hexdigest() for case in baseline
        }
        promoted_hashes = {
            hashlib.sha256(case.frame).hexdigest() for case in promoted
        }
        source_manifest = verifier_fuzz.load_promoted_source_manifest()
        derivation = source_manifest["derivation"]
        candidate_hashes = set(derivation["candidate_minimized_sha256"])
        recorded_baseline_hashes = set(derivation["baseline_unique_sha256"])
        retained_hashes = set(derivation["imported_retained_sha256"])
        self.assertEqual(len(candidate_hashes), 141)
        self.assertEqual(len(recorded_baseline_hashes), 202)
        self.assertEqual(len(retained_hashes), 72)
        self.assertEqual(len(candidate_hashes & recorded_baseline_hashes), 50)
        self.assertEqual(len(candidate_hashes & retained_hashes), 53)
        self.assertTrue(recorded_baseline_hashes.isdisjoint(retained_hashes))
        self.assertEqual(recorded_baseline_hashes, baseline_hashes)
        self.assertEqual(
            promoted_hashes,
            candidate_hashes - recorded_baseline_hashes - retained_hashes,
        )
        self.assertEqual(len(promoted_hashes), 38)
        self.assertTrue(promoted_hashes.isdisjoint(baseline_hashes))
        self.assertEqual(
            summary,
            {
                "total_cases": 245,
                "unique_frames": 240,
                "source_counts": {
                    "project": 27,
                    "promoted": 38,
                    "wycheproof": 180,
                },
                "expected_counts": {
                    "ok": 81,
                    "invalid_argument": 36,
                    "verify_rejection": 128,
                },
                "aggregate_sha256": (
                    "6ee1368b01bfd758dd1c78a79bb778976"
                    "9137f8d93055dfe9c4d040706597979"
                ),
            },
        )

    def test_promoted_source_rejects_tampering_and_unsafe_layouts(self):
        source_text = verifier_fuzz.PROMOTED_SOURCE.read_text(encoding="utf8")
        source_manifest = json.loads(source_text)

        def check_rejected(
            *, mutate=None, raw_text=None, extra_file=False, missing=False
        ):
            with tempfile.TemporaryDirectory() as temporary:
                source_dir = Path(temporary)
                source_path = source_dir / "SOURCE.json"
                if not missing:
                    if raw_text is None:
                        manifest = json.loads(json.dumps(source_manifest))
                        if mutate is not None:
                            mutate(manifest)
                        raw_text = json.dumps(manifest, indent=2) + "\n"
                    source_path.write_text(raw_text, encoding="utf8")
                if extra_file:
                    (source_dir / "extra").write_text("unexpected", encoding="utf8")
                with self.assertRaises(verifier_fuzz.FuzzHarnessError):
                    verifier_fuzz.validate_promoted_source(source_path)

        cases = []
        cases.append(("missing", {"missing": True}))
        cases.append(("extra_file", {"extra_file": True}))
        cases.append(
            (
                "duplicate_key",
                {
                    "raw_text": source_text.replace(
                        '  "schema_version": 1,\n',
                        '  "schema_version": 1,\n  "schema_version": 1,\n',
                        1,
                    )
                },
            )
        )
        cases.append(
            ("extra_root_field", {"mutate": lambda data: data.update(extra=True)})
        )
        cases.append(
            (
                "schema_type_confusion",
                {"mutate": lambda data: data.update(schema_version=True)},
            )
        )
        cases.append(
            (
                "source_identity",
                {
                    "mutate": lambda data: data["source"].update(
                        workflow_run_id=1
                    )
                },
            )
        )
        cases.append(
            (
                "source_type_confusion",
                {
                    "mutate": lambda data: data["source"].update(
                        workflow_run_attempt=True
                    )
                },
            )
        )
        cases.append(
            (
                "non_finite_json",
                {
                    "raw_text": source_text.replace(
                        '"candidate_minimized_cases": 141',
                        '"candidate_minimized_cases": NaN',
                        1,
                    )
                },
            )
        )
        cases.append(
            (
                "selection_metadata",
                {
                    "mutate": lambda data: data["selection"].update(
                        selected_cases=37
                    )
                },
            )
        )
        cases.append(
            (
                "derivation_inventory_order",
                {
                    "mutate": lambda data: data["derivation"][
                        "candidate_minimized_sha256"
                    ].__setitem__(
                        slice(0, 2),
                        list(
                            reversed(
                                data["derivation"][
                                    "candidate_minimized_sha256"
                                ][:2]
                            )
                        ),
                    )
                },
            )
        )
        cases.append(
            (
                "invalid_base64",
                {
                    "mutate": lambda data: data["cases"][0].update(
                        frame_base64="!"
                    )
                },
            )
        )
        cases.append(
            (
                "wrong_size",
                {
                    "mutate": lambda data: data["cases"][0].update(
                        size=data["cases"][0]["size"] + 1
                    )
                },
            )
        )
        cases.append(
            (
                "wrong_hash",
                {
                    "mutate": lambda data: data["cases"][0].update(
                        sha256="0" * 64
                    )
                },
            )
        )
        cases.append(
            (
                "unsupported_result",
                {
                    "mutate": lambda data: data["cases"][0].update(
                        expected_result="ok"
                    )
                },
            )
        )
        cases.append(
            (
                "unsorted",
                {
                    "mutate": lambda data: data["cases"].__setitem__(
                        slice(0, 2), list(reversed(data["cases"][:2]))
                    )
                },
            )
        )

        def install_malformed_frame(data):
            frame = b"\x02" + bytes(9)
            record = data["cases"][0]
            record.update(
                artifact_member=(
                    "ml-dsa-44-differential-fuzz/minimized-corpus/"
                    + hashlib.sha1(frame).hexdigest()
                ),
                frame_base64=base64.b64encode(frame).decode("ascii"),
                sha256=hashlib.sha256(frame).hexdigest(),
                size=len(frame),
            )
            data["cases"].sort(key=lambda item: item["sha256"])

        cases.append(("malformed_frame", {"mutate": install_malformed_frame}))
        for label, arguments in cases:
            with self.subTest(label=label):
                check_rejected(**arguments)

    def test_machine_readable_gate_remains_open(self):
        admission = json.loads(ADMISSION.read_text(encoding="utf8"))
        gate = next(
            item
            for item in admission["open_gates"]
            if item["id"] == "structure_aware_fuzzing_and_resources"
        )
        self.assertEqual(gate["tracking_issue"], 188)
        self.assertEqual(
            gate["status"],
            "DIFFERENTIAL_SANITIZER_AND_SUPPLEMENTARY_MIRI_EVIDENCE_RESOURCES_OPEN",
        )
        self.assertTrue(admission["decision"]["release_hold"])
        self.assertEqual(admission["decision"]["production_backend"], "NONE")

    def test_workflow_freezes_bounded_campaign_contract(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        for required in (
            "schedule:",
            "cron: '17 4 * * 3'",
            "actions: read",
            "contents: read",
            "timeout-minutes: 45",
            "sanitizer: address-undefined",
            "sanitizer: memory",
            "campaign_seconds=1800",
            "campaign_seconds=60",
            'campaign_seed="$GITHUB_RUN_NUMBER"',
            "campaign_seed=188",
            "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref }}",
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "--seed-corpus",
            "--coverage",
            "--json databaseId,attempt",
            '--name "$artifact_name"',
            "if: always()",
            "retention-days: 90",
            "github.run_id",
            "github.run_attempt",
            "coverage.json",
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

    def test_retained_corpus_import_is_bounded_and_content_addressed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            seed = b"retained seed"
            (source / "seed.bin").write_bytes(seed)
            (source / "ignored-directory").mkdir()

            imported = verifier_fuzz.import_seed_corpus(source, destination)

            digest = hashlib.sha256(seed).hexdigest()
            self.assertEqual(imported, 1)
            self.assertEqual(
                (destination / f"retained_{digest}.bin").read_bytes(),
                seed,
            )
            self.assertEqual(verifier_fuzz.import_seed_corpus(source, destination), 0)

            (source / "oversized.bin").write_bytes(
                bytes(verifier_fuzz.MAX_FRAME_BYTES + 1)
            )
            with self.assertRaises(verifier_fuzz.FuzzHarnessError):
                verifier_fuzz.import_seed_corpus(source, destination)

    def test_sanitizer_compile_contracts_are_distinct(self):
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
                    with mock.patch.object(verifier_fuzz.wrapper, "run") as run:
                        verifier_fuzz.compile_fuzzer(
                            "clang",
                            Path(temporary),
                            sanitizer=sanitizer,
                            coverage=coverage,
                        )
                    command = set(run.call_args.args[0])
                    self.assertTrue(required <= command)
                    self.assertTrue(prohibited.isdisjoint(command))

    def test_compiler_tool_uses_matching_versioned_fallback(self):
        completed = (
            subprocess.CompletedProcess(
                args=["clang", "--print-prog-name=llvm-profdata"],
                returncode=0,
                stdout="llvm-profdata\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["clang", "--version"],
                returncode=0,
                stdout="Ubuntu clang version 18.1.3\n",
                stderr="",
            ),
        )

        def resolve(candidate):
            return "/usr/bin/llvm-profdata-18" if candidate == "llvm-profdata-18" else None

        with mock.patch.object(
            verifier_fuzz.subprocess,
            "run",
            side_effect=completed,
        ), mock.patch.object(verifier_fuzz.shutil, "which", side_effect=resolve):
            tool = verifier_fuzz.compiler_tool("clang", "llvm-profdata")

        self.assertEqual(tool, "/usr/bin/llvm-profdata-18")

    def test_empty_minimized_corpus_is_a_campaign_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"seed")
            completed = subprocess.CompletedProcess(
                args=["fuzzer"], returncode=0, stdout="", stderr=""
            )
            with mock.patch.object(
                verifier_fuzz.subprocess,
                "run",
                return_value=completed,
            ):
                with self.assertRaisesRegex(
                    verifier_fuzz.FuzzHarnessError,
                    "empty corpus",
                ):
                    verifier_fuzz.minimize_corpus(
                        Path("fuzzer"),
                        corpus,
                        root / "minimized",
                        root / "minimization.log",
                        sanitizer="address-undefined",
                        profile_pattern=None,
                    )

    def test_corpus_minimization_preserves_value_profile_features(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"seed")

            def run(command, **_kwargs):
                (root / "minimized" / "seed").write_bytes(b"seed")
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout="",
                    stderr="",
                )

            with mock.patch.object(
                verifier_fuzz.subprocess,
                "run",
                side_effect=run,
            ) as run_mock:
                verifier_fuzz.minimize_corpus(
                    Path("fuzzer"),
                    corpus,
                    root / "minimized",
                    root / "minimization.log",
                    sanitizer="address-undefined",
                    profile_pattern=None,
                )

            command = run_mock.call_args.args[0]
            self.assertIn("-merge=1", command)
            self.assertEqual(command.count("-use_value_profile=1"), 1)

    def test_wall_clock_timeout_preserves_campaign_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "corpus"
            crashes = root / "crashes"
            corpus.mkdir()
            crashes.mkdir()
            timeout = subprocess.TimeoutExpired(
                cmd=["fuzzer"],
                timeout=31,
                output=b"partial stdout",
                stderr=b"partial stderr",
            )
            with mock.patch.object(
                verifier_fuzz.subprocess,
                "run",
                side_effect=timeout,
            ):
                completed = verifier_fuzz.run_fuzzer(
                    Path("fuzzer"),
                    corpus,
                    crashes,
                    root / "fuzzer.log",
                    runs=None,
                    seconds=1,
                    sanitizer="address-undefined",
                    profile_pattern=None,
                    seed=188,
                )

            self.assertEqual(completed.returncode, 124)
            log = (root / "fuzzer.log").read_text(encoding="utf8")
            self.assertIn("partial stdout", log)
            self.assertIn("partial stderr", log)
            self.assertIn("31-second wall-clock limit", log)

    def test_crash_minimization_timeout_retains_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            crashes = output / "crashes"
            crashes.mkdir()
            artifact = crashes / "crash-example"
            artifact.write_bytes(b"crash")
            timeout = subprocess.TimeoutExpired(
                cmd=["fuzzer"],
                timeout=verifier_fuzz.CRASH_MINIMIZATION_TIMEOUT_SECONDS,
                output=b"partial minimizer output",
                stderr=b"",
            )
            with mock.patch.object(
                verifier_fuzz.subprocess,
                "run",
                side_effect=timeout,
            ):
                records = verifier_fuzz.minimize_crash_artifacts(
                    Path("fuzzer"),
                    crashes,
                    output,
                    sanitizer="address-undefined",
                    seed=188,
                )

            self.assertTrue(artifact.is_file())
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0]["timed_out"])
            self.assertEqual(records[0]["return_code"], 124)
            self.assertIn(
                "partial minimizer output",
                (output / "crash-minimization.log").read_text(encoding="utf8"),
            )

    def test_evidence_hashes_cover_nested_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            nested = output / "minimized-corpus"
            nested.mkdir()
            (output / "campaign.json").write_text("{}\n", encoding="utf8")
            (nested / "seed").write_bytes(b"seed")

            verifier_fuzz.write_evidence_hashes(output)

            sums = (output / "SHA256SUMS").read_text(encoding="utf8")
            self.assertIn("campaign.json", sums)
            self.assertIn("minimized-corpus/seed", sums)
            self.assertNotIn("SHA256SUMS  SHA256SUMS", sums)

    def test_failure_report_retains_actionable_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for name in ("corpus", "crashes", "minimized-corpus"):
                (output / name).mkdir()
            (output / "corpus" / "seed").write_bytes(b"seed")
            completed = subprocess.CompletedProcess(
                args=["fuzzer"],
                returncode=1,
                stdout="",
                stderr="#1 DONE\nstat::number_of_executed_units: 1\n",
            )

            verifier_fuzz.write_campaign_report(
                output,
                compiler=sys.executable,
                sanitizer="address-undefined",
                coverage=False,
                runs=None,
                seconds=60,
                imported_seeds=0,
                source_summary={"total_cases": 207},
                started_at="2026-07-20T00:00:00+00:00",
                duration_seconds=1.25,
                seed=188,
                completed=completed,
                processing_error="corpus minimization failed",
                crash_minimization=[],
            )

            report = json.loads(
                (output / "campaign.json").read_text(encoding="utf8")
            )
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["return_code"], 1)
            self.assertEqual(report["processing_error"], "corpus minimization failed")
            self.assertEqual(report["resource_limits"]["seed"], 188)
            self.assertIn("source_capsule_sha256", report["source_files"])
            self.assertEqual(report["last_progress_line"], "#1 DONE")
            self.assertEqual(report["final_stats"], ["stat::number_of_executed_units: 1"])

    def test_campaign_options_require_sanitizers_and_nonzero_seed(self):
        runner = ENGINEERING_DIR / "run_verifier_fuzz.py"
        for arguments, message in (
            (["--seconds", "1"], "fuzz campaign options require --sanitizers"),
            (["--sanitizers", "--seed", "0"], "--seed must be a nonzero"),
        ):
            completed = subprocess.run(
                [sys.executable, str(runner), *arguments],
                cwd=REPO_ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn(message, completed.stderr)


if __name__ == "__main__":
    unittest.main()
