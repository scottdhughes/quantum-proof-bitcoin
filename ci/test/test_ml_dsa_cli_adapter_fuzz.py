#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_DIR = REPO_ROOT / "contrib" / "ml-dsa-ref"
DRIVER = REFERENCE_DIR / "run_cli_adapter_fuzz.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-review-reproduction.yml"
BASELINE_POINTER = REFERENCE_DIR / "review_baseline_commit.txt"
TRUSTED_MAIN_BASELINE_PATHSPEC = (
    ".github/workflows/ml-dsa-44-review-reproduction.yml",
    "contrib/ml-dsa-engineering",
    "contrib/ml-dsa-ref",
    "ci/test/test_ml_dsa_cli_adapter_fuzz.py",
    "ci/test/test_ml_dsa_differential_fuzz.py",
    "ci/test/test_ml_dsa_reference.py",
    "ci/test/test_ml_dsa_review_baseline.py",
    ":(exclude)contrib/ml-dsa-ref/review_baseline_commit.txt",
    ":(exclude)contrib/ml-dsa-ref/README.md",
    ":(exclude)contrib/ml-dsa-ref/wolfram/**",
)

sys.path.insert(0, str(REFERENCE_DIR))
import run_cli_adapter_fuzz as cli_fuzz  # noqa: E402
import compare_oracles as comparator  # noqa: E402


def trusted_main_baseline_pathspec(workflow):
    lines = [line.strip() for line in workflow.splitlines()]
    marker = 'git diff --exit-code "$BASELINE" -- \\'
    if lines.count(marker) != 1:
        raise ValueError("trusted-main baseline guard is missing or ambiguous")
    start = lines.index(marker) + 1
    pathspec = []
    for line in lines[start:]:
        continued = line.endswith("\\")
        argument = line[:-1].rstrip() if continued else line
        if argument.startswith("'") and argument.endswith("'"):
            argument = argument[1:-1]
        pathspec.append(argument)
        if not continued:
            break
    return tuple(pathspec)


def pr_vector_guard_script(workflow):
    lines = workflow.splitlines()
    marker = 'python3 - "$BASELINE" <<\'PY\''
    starts = [
        index for index, line in enumerate(lines) if line.strip() == marker
    ]
    if len(starts) != 1:
        raise ValueError("PR vector-delta guard is missing or ambiguous")
    start = starts[0] + 1
    try:
        end = next(
            index
            for index in range(start, len(lines))
            if lines[index].strip() == "PY"
        )
    except StopIteration as exc:
        raise ValueError("PR vector-delta guard has no heredoc terminator") from exc
    return textwrap.dedent("\n".join(lines[start:end])) + "\n"


class DummyOracle:
    def __init__(
        self,
        *,
        derives_public_key: bool,
        sign_requires_public_key: bool,
    ):
        self.executable = Path("/nonexistent/oracle")
        self.derives_public_key = derives_public_key
        self.sign_requires_public_key = sign_requires_public_key
        self.sanitized = False


class MlDsaCliAdapterFuzzTest(unittest.TestCase):
    def setUp(self):
        self.material = {
            "seed": "01" * cli_fuzz.KEYGEN_SEED_BYTES,
            "private_key": "02" * cli_fuzz.PRIVATE_KEY_BYTES,
            "public_key": "03" * cli_fuzz.PUBLIC_KEY_BYTES,
            "message": "04" * 32,
            "context": "05" * 24,
            "signature": "06" * cli_fuzz.SIGNATURE_BYTES,
        }

    def cases(self, oracle):
        return cli_fuzz.fixed_cases(oracle, **self.material)

    def test_frozen_manifest_matches_sources_and_generated_contract(self):
        manifest = cli_fuzz.validate_manifest()
        self.assertEqual(manifest["parser_limits"], cli_fuzz.parser_limits())
        self.assertEqual(manifest["process_limits"], cli_fuzz.process_limits())
        self.assertEqual(
            manifest["fixed_case_contract"], cli_fuzz.fixed_case_contract()
        )
        self.assertEqual(
            manifest["mutation_contract"], cli_fuzz.mutation_contract()
        )
        self.assertEqual(
            manifest["sources"],
            {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in cli_fuzz.SOURCE_PATHS.items()
            },
        )

    def test_fixed_case_sets_cover_both_adapter_shapes(self):
        c_oracle = DummyOracle(
            derives_public_key=True,
            sign_requires_public_key=False,
        )
        rust_oracle = DummyOracle(
            derives_public_key=False,
            sign_requires_public_key=True,
        )
        c_cases = self.cases(c_oracle)
        rust_cases = self.cases(rust_oracle)
        self.assertEqual(
            len(c_cases),
            len(cli_fuzz.COMMON_FIXED_CASE_IDS)
            + len(cli_fuzz.KEYGEN_FIXED_CASE_IDS)
            + len(cli_fuzz.PUBLIC_KEY_FIXED_CASE_IDS)
            + len(cli_fuzz.SIGN_FIXED_CASE_IDS),
        )
        self.assertEqual(
            len(rust_cases),
            len(cli_fuzz.COMMON_FIXED_CASE_IDS)
            + len(cli_fuzz.KEYGEN_FIXED_CASE_IDS)
            + len(cli_fuzz.SIGN_FIXED_CASE_IDS)
            + len(cli_fuzz.SIGN_PUBLIC_KEY_FIXED_CASE_IDS),
        )
        for cases in (c_cases, rust_cases):
            names = [case.name for case in cases]
            self.assertEqual(len(names), len(set(names)))
            self.assertIn("verify_valid_lowercase", names)
            self.assertIn("verify_valid_uppercase", names)
            self.assertIn("verify_message_maximum", names)
            self.assertIn("verify_message_oversized", names)
            self.assertIn("verify_signature_extended", names)
            self.assertIn("verify_signature_oversized", names)
            self.assertTrue(
                all(case.expected in {
                    "usage",
                    "malformed",
                    "verify_accept",
                    "verify_reject",
                    "verify_size_reject",
                } for case in cases)
            )

    def test_seeded_mutations_are_bounded_malformed_and_stable(self):
        cases = cli_fuzz.mutation_cases(
            public_key=self.material["public_key"],
            message=self.material["message"],
            context=self.material["context"],
            signature=self.material["signature"],
        )
        self.assertEqual(len(cases), cli_fuzz.MUTATION_CASES)
        self.assertEqual(len({case.name for case in cases}), len(cases))
        self.assertTrue(all(case.expected == "malformed" for case in cases))
        labels = "".join(f"{case.name}\n" for case in cases).encode("ascii")
        self.assertEqual(
            hashlib.sha256(labels).hexdigest(),
            cli_fuzz.mutation_contract()["label_inventory_sha256"],
        )
        covered = {
            field
            for field in cli_fuzz.MUTATION_FIELDS
            if any(f"_{field}_" in case.name for case in cases)
        }
        self.assertEqual(covered, set(cli_fuzz.MUTATION_FIELDS))
        for kind in cli_fuzz.MUTATION_KINDS:
            self.assertTrue(any(f"_{kind}_" in case.name for case in cases))
        self.assertTrue(
            any(
                any(isinstance(argument, bytes) for argument in case.arguments)
                for case in cases
            )
        )

    def test_evidence_metadata_does_not_contain_argument_values(self):
        arguments = (
            "verify",
            self.material["public_key"],
            self.material["message"],
            self.material["context"],
            self.material["signature"],
        )
        summary = cli_fuzz.argument_summary(arguments)
        serialized = json.dumps(summary, sort_keys=True)
        for argument in arguments[1:]:
            self.assertNotIn(argument, serialized)
        self.assertEqual(summary["argument_count"], 5)
        self.assertRegex(summary["argv_sha256"], r"^[0-9a-f]{64}$")

    def test_research_message_limit_preserves_selected_acvp_cases(self):
        manifest = json.loads(
            (REFERENCE_DIR / "vectors.json").read_text(encoding="utf8")
        )
        recorded_sizes = []
        for value in manifest["vectors"].values():
            if isinstance(value, dict):
                if "message_bytes" in value:
                    recorded_sizes.append(value["message_bytes"])
                for case in value.get("cases", []):
                    if "message_bytes" in case:
                        recorded_sizes.append(case["message_bytes"])
        self.assertGreater(max(recorded_sizes), 4096)
        self.assertLessEqual(max(recorded_sizes), cli_fuzz.MAX_MESSAGE_BYTES)
        self.assertEqual(cli_fuzz.MAX_MESSAGE_BYTES, 8192)
        self.assertEqual(
            cli_fuzz.parser_limits()["selected_acvp_maximum_message_bytes"],
            8192,
        )

    def test_c_bounded_hex_helper_contract(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        source = textwrap.dedent(
            """
            #include "oracle_cli.h"
            #include <stddef.h>
            #include <stdint.h>

            int main(void)
            {
                uint8_t output[4] = {0};
                size_t size = 99;
                if (!OracleDecodeHexBounded("00aAFF", output, 4, &size)) return 1;
                if (size != 3 || output[0] != 0 || output[1] != 0xaa ||
                    output[2] != 0xff) return 2;
                if (!OracleDecodeHexBounded("", output, 4, &size) || size != 0) return 3;
                if (OracleDecodeHexBounded("000", output, 4, &size)) return 4;
                if (OracleDecodeHexBounded("0000000000", output, 4, &size)) return 5;
                if (OracleDecodeHexBounded("00g0", output, 4, &size)) return 6;
                if (!OracleDecodeHexExact("00010203", output, 4)) return 7;
                if (OracleDecodeHexExact("000102", output, 4)) return 8;
                if (!OracleCommandEquals("verify", "verify")) return 9;
                if (OracleCommandEquals("verify-extra", "verify")) return 10;
                return 0;
            }
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test_source = root / "test.c"
            executable = root / "test"
            test_source.write_text(source, encoding="utf8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    f"-I{REFERENCE_DIR}",
                    str(test_source),
                    "-o",
                    str(executable),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [str(executable)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                run_result.stdout + run_result.stderr,
            )

    def test_adapters_use_bounded_parsers_and_non_panicking_rust_argv(self):
        for source_name in ("openssl_oracle.c", "mldsa_native_oracle.c"):
            source = (REFERENCE_DIR / source_name).read_text(encoding="utf8")
            self.assertNotIn("strlen(", source)
            self.assertNotIn("malloc(", source)
            self.assertIn("OracleDecodeHexBounded", source)
            self.assertIn("OracleDecodeHexExact", source)
            self.assertNotIn('fprintf(stderr, "usage: %s', source)
        rust = (REFERENCE_DIR / "libcrux_oracle.rs").read_text(encoding="utf8")
        self.assertIn("env::args_os()", rust)
        self.assertNotIn("env::args()", rust)
        self.assertIn("MAX_MESSAGE_SIZE", rust)
        self.assertIn("MAX_VERIFY_SIGNATURE_SIZE", rust)

    def test_manifest_only_cli_and_workflow_integration(self):
        result = subprocess.run(
            [sys.executable, str(DRIVER), "--manifest-only"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("60 mutations per adapter", result.stdout)
        workflow = WORKFLOW.read_text(encoding="utf8")
        self.assertIn(
            "contrib/ml-dsa-ref/review_baseline_commit.txt",
            workflow,
        )
        self.assertIn('contrib/ml-dsa-ref/**', workflow)
        self.assertIn(
            "python3 contrib/ml-dsa-ref/compare_oracles.py", workflow
        )
        self.assertNotIn(
            'advisory["RUSTSEC-2026-0077"]["pqbtc_exact_regression"]["status"]',
            workflow,
        )
        for exact_field in (
            '"source": "C2SP Wycheproof ML-DSA-44 verification vectors"',
            '"test_case_ids": [125, 126]',
            '"cases": 2',
            '"status": "PASS"',
        ):
            self.assertIn(exact_field, workflow)

    def test_workflow_separates_pr_smoke_from_frozen_main_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        normalized = "\n".join(
            line.strip() for line in workflow.splitlines()
        )
        expected_scope = textwrap.dedent(
            """\
            if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
            baseline_mode="pull_request"
            evidence_trust_scope="pull_request_head_smoke_only"
            promotion_eligible="false"
            artifact_prefix="ml-dsa-44-review-candidate"
            elif [[ "$GITHUB_REF" == "refs/heads/main" ]]; then
            baseline_mode="main"
            evidence_trust_scope="pending_frozen_baseline_validation"
            promotion_eligible="false"
            artifact_prefix="ml-dsa-44-review-pending"
            else
            baseline_mode="main"
            evidence_trust_scope="rejected_non_main_dispatch"
            promotion_eligible="false"
            artifact_prefix="ml-dsa-44-review-rejected"
            fi"""
        )
        expected_promotion_block = textwrap.dedent(
            """\
            if [[ "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
            artifact_prefix="ml-dsa-44-review-candidate"
            else
            sed -i \\
            -e 's/^evidence_trust_scope=.*/evidence_trust_scope=frozen_baseline_reproduction/' \\
            -e 's/^promotion_eligible=.*/promotion_eligible=true/' \\
            "$CONTEXT"
            artifact_prefix="ml-dsa-44-review-evidence"
            fi
            echo "artifact_prefix=$artifact_prefix" >> "$GITHUB_OUTPUT"
            """
        )
        self.assertIn(
            "if: github.event_name == 'pull_request' || "
            "github.ref == 'refs/heads/main'",
            normalized,
        )
        self.assertIn(expected_scope, normalized)
        pointer = BASELINE_POINTER.read_bytes()
        self.assertEqual(len(pointer), 41)
        self.assertEqual(pointer[-1:], b"\n")
        self.assertRegex(pointer[:-1].decode("ascii"), r"^[0-9a-f]{40}$")
        self.assertIn(
            "BASELINE_FILE: contrib/ml-dsa-ref/review_baseline_commit.txt",
            workflow,
        )
        self.assertNotIn(
            "      BASELINE: ",
            workflow,
        )
        for pointer_guard in (
            "python3 contrib/ml-dsa-ref/validate_review_baseline.py",
            '--pointer "$BASELINE_FILE"',
            '--head "$EXPECTED_HEAD"',
            '--base "$EXPECTED_BASE"',
            '--mode "$BASELINE_MODE"',
            'echo "BASELINE=$baseline" >> "$GITHUB_ENV"',
        ):
            self.assertIn(pointer_guard, workflow)
        for validator_test_integration in (
            '- "ci/test/test_ml_dsa_review_baseline.py"',
            "ci.test.test_ml_dsa_review_baseline",
        ):
            self.assertIn(validator_test_integration, workflow)
        self.assertLess(
            workflow.index("- name: Initialize failure evidence"),
            workflow.index("- name: Checkout PQBTC review head"),
        )
        self.assertLess(
            workflow.index("- name: Checkout PQBTC review head"),
            workflow.index("- name: Validate review baseline pointer"),
        )
        vector_guard = pr_vector_guard_script(workflow)
        self.assertIn(
            '"c2a94fe4fc8e63a6bec4528b4589958772cb0ea01f669cfd8c78bed357a68633"',
            vector_guard,
        )
        self.assertNotIn(
            "2fe1fffc7bfe8ec7597e408449a0d6b99f6ec0f035ab6669211d4d13f376a2b9",
            vector_guard,
        )
        self.assertIn("if actual_sha256 != expected_sha256:", vector_guard)
        self.assertNotIn(
            'git diff --exit-code "$BASELINE" -- '
            "contrib/ml-dsa-ref/vectors.json",
            normalized,
        )
        self.assertIn(
            'test "$GITHUB_REF" = "refs/heads/main"',
            normalized,
        )
        self.assertEqual(
            trusted_main_baseline_pathspec(workflow),
            TRUSTED_MAIN_BASELINE_PATHSPEC,
        )
        self.assertIn(expected_promotion_block, normalized)
        self.assertIn(
            "name: ${{ steps.repository_inputs.outputs.artifact_prefix || "
            "steps.evidence_scope.outputs.artifact_prefix }}-"
            "${{ github.event.pull_request.head.sha || github.sha }}",
            normalized,
        )
        self.assertNotIn(
            "name: ml-dsa-44-review-evidence-${{", normalized
        )
        self.assertIn(
            "--json databaseId,attempt,createdAt,event,headSha",
            normalized,
        )
        self.assertIn(
            "--event schedule",
            normalized,
        )
        self.assertIn(
            "--event workflow_dispatch",
            normalized,
        )
        self.assertIn(
            "sort -t $'\\t' -k1,1r -k2,2nr",
            normalized,
        )
        self.assertIn(
            "evidence_trust_scope=frozen_baseline_reproduction",
            normalized,
        )
        self.assertIn(
            "promotion_eligible=true",
            normalized,
        )
        job_guard_cases = (
            ("pull_request", "refs/pull/1/merge", True),
            ("schedule", "refs/heads/main", True),
            ("workflow_dispatch", "refs/heads/main", True),
            ("workflow_dispatch", "refs/heads/feature", False),
        )
        for event_name, ref, expected in job_guard_cases:
            self.assertEqual(
                event_name == "pull_request" or ref == "refs/heads/main",
                expected,
            )

    def test_pr_vector_guard_allows_only_exact_steady_state(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git unavailable")
        workflow = WORKFLOW.read_text(encoding="utf8")
        guard = pr_vector_guard_script(workflow)
        relative_vector_path = "contrib/ml-dsa-ref/vectors.json"
        candidate_bytes = (REFERENCE_DIR / "vectors.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(candidate_bytes).hexdigest(),
            "c2a94fe4fc8e63a6bec4528b4589958772cb0ea01f669cfd8c78bed357a68633",
        )

        def run_guard(current_bytes, *, committed_baseline=candidate_bytes):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                vector_path = root / relative_vector_path
                vector_path.parent.mkdir(parents=True)
                vector_path.write_bytes(committed_baseline)
                for arguments in (
                    ("init", "--quiet"),
                    ("add", relative_vector_path),
                    (
                        "-c",
                        "user.name=PQBTC CI",
                        "-c",
                        "user.email=pqbtc-ci@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "--quiet",
                        "--no-verify",
                        "-m",
                        "baseline",
                    ),
                ):
                    subprocess.run(
                        [git, *arguments],
                        cwd=root,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                baseline_revision = subprocess.run(
                    [git, "rev-parse", "HEAD"],
                    cwd=root,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ).stdout.strip()
                vector_path.write_bytes(current_bytes)
                return subprocess.run(
                    [sys.executable, "-", baseline_revision],
                    cwd=root,
                    check=False,
                    input=guard,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

        steady_state = run_guard(
            candidate_bytes,
            committed_baseline=candidate_bytes,
        )
        self.assertEqual(
            steady_state.returncode,
            0,
            steady_state.stdout + steady_state.stderr,
        )

        tampered_regression = candidate_bytes.replace(
            b'"test_case_id": 125',
            b'"test_case_id": 124',
            1,
        )
        unrelated_drift = candidate_bytes.replace(
            b'"signature_bytes": 2420',
            b'"signature_bytes": 2421',
            1,
        )
        cases = (
            ("tampered regression", tampered_regression, candidate_bytes),
            ("unrelated drift", unrelated_drift, candidate_bytes),
            (
                "tampered baseline",
                candidate_bytes,
                candidate_bytes + b"\n",
            ),
        )
        for label, rejected, rejected_baseline in cases:
            if label == "tampered baseline":
                self.assertNotEqual(rejected_baseline, candidate_bytes)
            else:
                self.assertNotEqual(rejected, candidate_bytes, label)
            with self.subTest(label=label):
                result = run_guard(
                    rejected,
                    committed_baseline=rejected_baseline,
                )
                self.assertNotEqual(
                    result.returncode,
                    0,
                    result.stdout + result.stderr,
                )

    def test_trusted_main_baseline_pathspec_is_semantically_fail_closed(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git unavailable")
        workflow = WORKFLOW.read_text(encoding="utf8")
        pathspec = trusted_main_baseline_pathspec(workflow)
        self.assertIn(
            ".github/workflows/ml-dsa-44-review-reproduction.yml",
            pathspec,
        )
        self.assertIn(
            ":(exclude)contrib/ml-dsa-ref/review_baseline_commit.txt",
            pathspec,
        )
        self.assertNotIn(
            "contrib/ml-dsa-ref/review_baseline_commit.txt",
            pathspec,
        )
        fixture_files = {
            "contrib/ml-dsa-ref/review_baseline_commit.txt": "0" * 40 + "\n",
            "contrib/ml-dsa-ref/validate_review_baseline.py": (
                "# baseline validator\n"
            ),
            ".github/workflows/ml-dsa-44-review-reproduction.yml": (
                "name: baseline workflow\n"
            ),
            "contrib/ml-dsa-engineering/run_differential_verifier_fuzz.py": (
                "print('baseline generator')\n"
            ),
            "contrib/ml-dsa-ref/oracle_cli.h": "/* baseline oracle */\n",
            "contrib/ml-dsa-ref/README.md": "baseline documentation\n",
            "contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wl": (
                "(* baseline model *)\n"
            ),
            "ci/test/test_ml_dsa_cli_adapter_fuzz.py": "# baseline CLI test\n",
            "ci/test/test_ml_dsa_differential_fuzz.py": (
                "# baseline differential test\n"
            ),
            "ci/test/test_ml_dsa_reference.py": "# baseline reference test\n",
            "ci/test/test_ml_dsa_review_baseline.py": (
                "# baseline validator test\n"
            ),
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in fixture_files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf8")

            def run_git(*arguments):
                result = subprocess.run(
                    [git, "-C", str(root), *arguments],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    result.stdout + result.stderr,
                )
                return result

            run_git("init", "-q")
            run_git("add", "-A")
            run_git(
                "-c",
                "user.name=Trusted Evidence Test",
                "-c",
                "user.email=trusted-evidence@example.invalid",
                "commit",
                "-q",
                "-m",
                "baseline",
            )
            baseline = run_git("rev-parse", "HEAD").stdout.strip()

            def run_guard():
                return subprocess.run(
                    [
                        git,
                        "-C",
                        str(root),
                        "diff",
                        "--exit-code",
                        baseline,
                        "--",
                        *pathspec,
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

            self.assertEqual(run_guard().returncode, 0)
            pointer = root / "contrib" / "ml-dsa-ref" / (
                "review_baseline_commit.txt"
            )
            pointer.write_text(baseline + "\n", encoding="ascii")
            self.assertEqual(
                run_guard().returncode,
                0,
                "pointer-only baseline advancement must remain live",
            )
            run_git("add", "contrib/ml-dsa-ref/review_baseline_commit.txt")
            run_git(
                "-c",
                "user.name=Trusted Evidence Test",
                "-c",
                "user.email=trusted-evidence@example.invalid",
                "commit",
                "-q",
                "-m",
                "advance pointer",
            )
            promoted_head = run_git("rev-parse", "HEAD").stdout.strip()
            first_parent = run_git(
                "rev-list",
                "--first-parent",
                promoted_head,
            ).stdout.splitlines()
            self.assertIn(baseline, first_parent)
            self.assertEqual(run_guard().returncode, 0)
            guarded_paths = (
                ".github/workflows/ml-dsa-44-review-reproduction.yml",
                "contrib/ml-dsa-engineering/run_differential_verifier_fuzz.py",
                "contrib/ml-dsa-ref/oracle_cli.h",
                "contrib/ml-dsa-ref/validate_review_baseline.py",
                "ci/test/test_ml_dsa_review_baseline.py",
            )
            for relative in guarded_paths:
                with self.subTest(guarded_path=relative):
                    target = root / relative
                    original = target.read_text(encoding="utf8")
                    target.write_text(
                        original + "# guarded mutation\n",
                        encoding="utf8",
                    )
                    self.assertNotEqual(
                        run_guard().returncode,
                        0,
                        f"trusted-main guard accepted {relative}",
                    )
                    target.write_text(original, encoding="utf8")
                    self.assertEqual(run_guard().returncode, 0)

            excluded_paths = (
                "contrib/ml-dsa-ref/README.md",
                "contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wl",
            )
            for relative in excluded_paths:
                with self.subTest(excluded_path=relative):
                    target = root / relative
                    original = target.read_text(encoding="utf8")
                    target.write_text(
                        original + "excluded documentation mutation\n",
                        encoding="utf8",
                    )
                    result = run_guard()
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stdout + result.stderr,
                    )
                    target.write_text(original, encoding="utf8")

    def test_comparator_reports_cli_harness_failure_without_traceback(self):
        error = cli_fuzz.CliFuzzError("forced CLI harness failure")
        stderr = io.StringIO()
        with (
            mock.patch.object(
                comparator.cli_adapter_fuzz,
                "validate_manifest",
                side_effect=error,
            ),
            mock.patch.object(
                sys,
                "argv",
                ["compare_oracles.py", "--manifest-only"],
            ),
            redirect_stderr(stderr),
        ):
            self.assertEqual(comparator.main(), 1)
        self.assertEqual(
            stderr.getvalue(),
            "compare_oracles.py: forced CLI harness failure\n",
        )


if __name__ == "__main__":
    unittest.main()
