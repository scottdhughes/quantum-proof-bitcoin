#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
RESOURCE_POLICY = ENGINEERING_DIR / "verifier_resource_policy.json"
RESOURCE_RUNNER = ENGINEERING_DIR / "run_verifier_resource_envelope.py"
RESOURCE_PROBE = ENGINEERING_DIR / "pqbtc_mldsa44_resource_probe.c"
RESOURCE_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-resource-envelope.yml"
)
BATCH_IDS = [
    "mixed_rotating",
    "valid_rotating",
    "deep_reject_rotating",
    "same_key_mixed",
]


def load_resource_plan() -> dict:
    completed = subprocess.run(
        [sys.executable, str(RESOURCE_RUNNER), "--plan-only"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


def load_resource_runner() -> dict[str, object]:
    sys.path.insert(0, str(ENGINEERING_DIR))
    try:
        return runpy.run_path(str(RESOURCE_RUNNER))
    finally:
        del sys.path[0]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MlDsaResourceEnvelopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resource = load_resource_runner()

    def test_resource_evidence_assets_exist(self):
        for path in (
            RESOURCE_POLICY,
            RESOURCE_RUNNER,
            RESOURCE_PROBE,
            RESOURCE_WORKFLOW,
        ):
            self.assertTrue(path.is_file(), path)

    def test_policy_freezes_observation_without_bootstrapping_acceptance(self):
        policy = json.loads(RESOURCE_POLICY.read_text(encoding="utf8"))
        self.assertEqual(policy["schema_version"], 1)
        self.assertEqual(policy["phase"], "TRUSTED_MAIN_OBSERVATION_REQUIRED")
        self.assertEqual(policy["target"], "pqbtc_mldsa44_verify_strict")
        self.assertEqual(
            policy["profile"],
            {
                "system": "Linux",
                "machine": "x86_64",
                "measurement_target": (
                    "isolated-production-shaped-direct-verifier"
                ),
                "backend": "mldsa-native-portable-c",
                "optimization": "-O2",
                "thread_model": "one guarded pthread",
                "allocation_model": "default upstream stack allocation",
            },
        )

        batch = policy["batch"]
        self.assertEqual(batch["batches"], BATCH_IDS)
        self.assertEqual(batch["unique_frames"], 240)
        self.assertEqual(batch["full_corpus_rounds"], 17)
        self.assertEqual(batch["prefix_frames"], 207)
        self.assertEqual(batch["verification_calls"], 4287)
        self.assertEqual(17 * 240 + 207, batch["verification_calls"])
        self.assertIn("research workload only", batch["capacity_scope"])
        self.assertIn("not a transaction", batch["capacity_scope"])
        self.assertEqual(
            batch["required_accept_cases"],
            [
                "valid_empty_message_context",
                "valid_frozen_vector",
                "valid_max_context",
                "valid_max_fuzz_message",
            ],
        )
        self.assertEqual(
            batch["required_deep_reject_cases"],
            [
                "reject_context_flip",
                "reject_ctilde_bit_flip",
                "reject_hint_counter_backwards",
                "reject_hint_nonzero_padding",
                "reject_message_flip",
                "reject_public_key_rho_flip",
                "reject_public_key_t1_flip",
            ],
        )
        self.assertEqual(
            batch["same_key_cases"],
            [
                "reject_context_flip",
                "reject_ctilde_bit_flip",
                "reject_hint_counter_backwards",
                "reject_hint_nonzero_padding",
                "reject_message_flip",
                "valid_empty_message_context",
                "valid_frozen_vector",
                "valid_max_context",
                "valid_max_fuzz_message",
            ],
        )

        limits = policy["enforced_limits"]
        self.assertEqual(limits["thread_stack_bytes"], 131072)
        self.assertEqual(limits["thread_guard_bytes"], 4096)
        self.assertEqual(limits["address_space_bytes"], 268435456)
        self.assertEqual(limits["open_files"], 64)
        self.assertEqual(limits["output_file_bytes"], 65536)
        self.assertEqual(limits["core_file_bytes"], 0)
        self.assertEqual(limits["project_heap_calls"], 0)
        self.assertEqual(limits["cpu_watchdog_seconds"], 120)
        self.assertEqual(limits["wall_watchdog_seconds"], 180)

        acceptance = policy["acceptance_limits"]
        self.assertIsNone(acceptance["cpu_seconds"])
        self.assertIsNone(acceptance["wall_seconds"])
        self.assertIsNone(acceptance["peak_rss_kib"])
        self.assertEqual(
            acceptance["status"],
            "UNSET_PENDING_SEPARATE_REVIEW_OF_TRUSTED_MAIN_OBSERVATION",
        )
        stack = policy["stack_evidence"]
        self.assertEqual(
            stack["upstream_mld_total_alloc_44_verify_bytes"],
            24448,
        )
        self.assertEqual(
            stack["required_symbols"],
            [
                "pqbtc_mldsa44_upstream_verify",
                "pqbtc_mldsa44_verify_strict",
            ],
        )
        self.assertTrue(stack["require_static_stack_usage"])
        self.assertIn(
            ".su values are not summed into a formal call-chain bound",
            stack["call_chain_claim"],
        )
        self.assertTrue(policy["promotion"]["requires_separate_policy_change"])
        self.assertTrue(policy["promotion"]["requires_trusted_main_push"])
        self.assertEqual(
            policy["promotion"]["requires_both_compilers"],
            ["clang", "gcc"],
        )
        self.assertTrue(policy["promotion"]["timing_threshold_bootstrap_forbidden"])
        self.assertEqual(
            policy["promotion"]["pull_request_evidence"],
            "UNTRUSTED_PR_OBSERVATION",
        )
        self.assertEqual(
            policy["promotion"]["trusted_main_evidence"],
            "TRUSTED_MAIN_OBSERVATION",
        )
        self.assertFalse(policy["scope"]["release_hold_changed"])
        self.assertTrue(policy["scope"]["batch_limit_is_not_consensus_policy"])

    def test_plan_is_fail_closed_and_exactly_embeds_policy(self):
        policy = self.resource["load_policy"]()
        plan = load_resource_plan()
        self.assertEqual(plan, self.resource["build_plan"](policy))
        self.assertEqual(
            set(plan),
            {
                "schema_version",
                "target",
                "host",
                "measurement",
                "policy",
                "policy_sha256",
                "inputs",
            },
        )
        self.assertEqual(plan["schema_version"], 1)
        self.assertEqual(plan["target"], "pqbtc_mldsa44_verify_strict")
        self.assertEqual(plan["host"], {"machine": "x86_64", "system": "Linux"})
        self.assertEqual(plan["policy"], policy)
        self.assertRegex(plan["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(plan["policy_sha256"], sha256(RESOURCE_POLICY))
        self.assertEqual(
            set(plan["inputs"]),
            {
                "policy",
                "runner",
                "probe",
                "wrapper_source",
                "wrapper_header",
                "wrapper_test_header",
                "wrapper_config",
                "source_manifest",
                "wrapper_test_driver",
                "fuzz_driver",
                "fuzz_manifest",
                "vectors",
                "wycheproof_source",
                "promoted_source",
                "workflow",
                "resource_test",
            },
        )
        for digest in plan["inputs"].values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            plan["inputs"]["wrapper_test_driver"],
            sha256(ENGINEERING_DIR / "run_wrapper_tests.py"),
        )
        self.assertEqual(
            plan["measurement"],
            {
                "profile": "isolated-production-shaped-direct-verifier",
                "batch_ids": BATCH_IDS,
                "sample_count": 31,
                "raw_sample_count": 31,
                "retain_raw_samples": True,
                "subtract_control_samples": False,
                "first_call_separate": True,
                "wall_clock": "CLOCK_MONOTONIC",
                "cpu_clock": "CLOCK_THREAD_CPUTIME_ID",
                "control_loop": "reported separately and never subtracted",
                "numeric_acceptance": (
                    "unset pending a separate review of trusted main observations"
                ),
            },
        )
        self.assertEqual(plan["policy"]["batch"]["unique_frames"], 240)
        self.assertEqual(plan["policy"]["batch"]["verification_calls"], 4287)
        self.assertEqual(len(plan["measurement"]["batch_ids"]), 4)
        limits = plan["policy"]["enforced_limits"]
        self.assertEqual(limits["thread_stack_bytes"], 131072)
        self.assertEqual(limits["thread_guard_bytes"], 4096)
        self.assertEqual(limits["cpu_watchdog_seconds"], 120)
        self.assertEqual(limits["wall_watchdog_seconds"], 180)
        self.assertEqual(limits["project_heap_calls"], 0)
        acceptance = plan["policy"]["acceptance_limits"]
        self.assertIsNone(acceptance["cpu_seconds"])
        self.assertIsNone(acceptance["wall_seconds"])
        self.assertIsNone(acceptance["peak_rss_kib"])
        scope = plan["policy"]["scope"]
        self.assertTrue(scope["isolated_test_only"])
        self.assertFalse(scope["production_integration"])
        self.assertEqual(scope["production_backend"], "NONE")
        self.assertFalse(scope["simd256_admitted"])
        self.assertTrue(scope["release_hold"])

    def test_probe_targets_only_the_direct_production_verifier(self):
        source = RESOURCE_PROBE.read_text(encoding="utf8")
        for required in (
            "#if !defined(__linux__) || !defined(__x86_64__)",
            "#define RESOURCE_EXPECTED_RECORDS 240U",
            "#define RESOURCE_SAMPLE_COUNT 31U",
            "#define RESOURCE_BATCH_CALLS 4287U",
            "#define RESOURCE_THREAD_STACK_BYTES 131072U",
            "#define RESOURCE_THREAD_GUARD_BYTES 4096U",
            "#define RESOURCE_CPU_WATCHDOG_SECONDS 120U",
            "#define RESOURCE_WALL_WATCHDOG_SECONDS 180U",
            "pqbtc_mldsa44_verify_strict(",
            "pthread_attr_setstacksize(",
            "pthread_attr_setguardsize(",
            "RLIMIT_CPU",
            "RLIMIT_AS",
            "RLIMIT_NOFILE",
            "RLIMIT_FSIZE",
            "RLIMIT_CORE",
            "__wrap_malloc",
            "__wrap_calloc",
            "__wrap_realloc",
            "__wrap_free",
            "__wrap_aligned_alloc",
            "__wrap_posix_memalign",
            "--heap-positive-control",
            "--stack-positive-control",
            "--cpu-positive-control",
            "--wall-positive-control",
            "#include <limits.h>  // IWYU pragma: keep",
            "// IWYU pragma: no_include <bits/pthread_stack_min.h>",
            "// IWYU pragma: no_include <bits/types/struct_rusage.h>",
        ):
            self.assertIn(required, source)
        self.assertLess(
            source.index("if (received != g_bundle_size)"),
            source.index("trailing_byte = fgetc(input);"),
        )
        self.assertEqual(source.count("pqbtc_mldsa44_verify_strict("), 1)
        self.assertNotIn('#include <bits/', source)
        self.assertNotIn("fprintf(", source)
        self.assertNotIn("pqbtc_mldsa44_sign_hedged", source)
        self.assertNotIn("pqbtc_mldsa44_test_", source)
        self.assertNotIn('#include "pqbtc_mldsa44_test.h"', source)
        self.assertNotIn("PQBTC_MLDSA44_TESTING", source)
        for batch_id in BATCH_IDS:
            self.assertIn(f'"{batch_id}"', source)

    def test_stack_usage_parser_rejects_missing_dynamic_and_duplicate_symbols(self):
        parse_stack_usage = self.resource["parse_stack_usage"]
        error = self.resource["ResourceEnvelopeError"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "wrapper.su"
            wrapper.write_text(
                "pqbtc_mldsa44.c:300:1:"
                "pqbtc_mldsa44_upstream_verify\t25312\tstatic\n"
                "pqbtc_mldsa44.c:330:1:"
                "pqbtc_mldsa44_verify_strict\t16\tstatic\n",
                encoding="utf8",
            )
            parsed = parse_stack_usage([wrapper])
            self.assertEqual(
                set(parsed),
                {
                    "pqbtc_mldsa44_upstream_verify",
                    "pqbtc_mldsa44_verify_strict",
                },
            )
            self.assertEqual(
                parsed["pqbtc_mldsa44_upstream_verify"]["observed_symbol"],
                "pqbtc_mldsa44_upstream_verify",
            )

            wrapper.write_text(
                "sign.c:1221:"
                "pqbtc_mldsa44_upstream_verify\t25216\tstatic\n"
                "pqbtc_mldsa44.c:330:"
                "pqbtc_mldsa44_verify_strict\t16\tstatic\n",
                encoding="utf8",
            )
            parsed = parse_stack_usage([wrapper])
            self.assertEqual(
                parsed["pqbtc_mldsa44_upstream_verify"]["source"],
                "sign.c:1221",
            )

            wrapper.write_text(
                "sign.c:1221:5:"
                "pqbtc_mldsa44_upstream_verify.constprop\t448\tstatic\n"
                "pqbtc_mldsa44.c:330:5:"
                "pqbtc_mldsa44_verify_strict\t16\tstatic\n",
                encoding="utf8",
            )
            parsed = parse_stack_usage([wrapper])
            self.assertEqual(
                parsed["pqbtc_mldsa44_upstream_verify"]["observed_symbol"],
                "pqbtc_mldsa44_upstream_verify.constprop",
            )

            wrapper.write_text(
                "pqbtc_mldsa44.c:300:1:"
                "pqbtc_mldsa44_upstream_verify\t25312\tdynamic\n"
                "pqbtc_mldsa44.c:330:1:"
                "pqbtc_mldsa44_verify_strict\t16\tstatic\n",
                encoding="utf8",
            )
            with self.assertRaises(error):
                parse_stack_usage([wrapper])

            wrapper.write_text(
                "pqbtc_mldsa44.c:300:1:"
                "pqbtc_mldsa44_upstream_verify\t25312\tstatic\n",
                encoding="utf8",
            )
            with self.assertRaises(error):
                parse_stack_usage([wrapper])

            wrapper.write_text(
                "pqbtc_mldsa44.c:300:1:"
                "pqbtc_mldsa44_upstream_verify\t25312\tstatic\n"
                "pqbtc_mldsa44.c:301:1:"
                "pqbtc_mldsa44_upstream_verify\t25312\tstatic\n"
                "pqbtc_mldsa44.c:330:1:"
                "pqbtc_mldsa44_verify_strict\t16\tstatic\n",
                encoding="utf8",
            )
            with self.assertRaises(error):
                parse_stack_usage([wrapper])

    def test_probe_observation_validation_fails_closed(self):
        plan = load_resource_plan()
        validate = self.resource["validate_probe_observation"]
        error = self.resource["ResourceEnvelopeError"]
        observation = self._synthetic_observation()
        validated = validate(observation, plan)
        self.assertEqual(
            [batch["id"] for batch in validated["batches"]],
            BATCH_IDS,
        )
        self.assertEqual(
            validated["completed_calls"],
            1 + len(BATCH_IDS) * 4287,
        )

        mutations = [
            ("heap", lambda item: item["heap_calls"].update(malloc=1)),
            ("heap_bool", lambda item: item["heap_calls"].update(malloc=False)),
            ("schema_bool", lambda item: item.update(schema_version=True)),
            (
                "result_bool",
                lambda item: item["first_call"].update(result=False),
            ),
            ("completed", lambda item: item.update(completed_calls=17148)),
            ("sample", lambda item: item["batches"][0]["wall_samples_ns"].pop()),
            ("outcome", lambda item: item["batches"][1]["outcomes"].update(ok=4286)),
            (
                "input",
                lambda item: item.update(input_fnv1a64_after="0000000000000002"),
            ),
            ("extra", lambda item: item.update(unexpected=True)),
            (
                "rss_cap",
                lambda item: item.update(peak_rss_kib=262145),
            ),
            (
                "wall_cap",
                lambda item: item["batches"][0].update(
                    wall_samples_ns=[6_000_000_000] * 31
                ),
            ),
            (
                "cpu_cap",
                lambda item: item["batches"][0].update(
                    cpu_samples_ns=[4_000_000_000] * 31
                ),
            ),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                invalid = deepcopy(observation)
                mutate(invalid)
                with self.assertRaises(error):
                    validate(invalid, plan)

    def test_evidence_verifier_rejects_checksum_tamper_and_symlinks(self):
        make_fixture = self.resource["write_test_evidence_fixture"]
        verify = self.resource["verify_evidence"]
        error = self.resource["ResourceEnvelopeError"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            make_fixture(evidence, self._synthetic_observation())
            verify(evidence)

            report = evidence / self.resource["REPORT_FILE"]
            report.write_bytes(report.read_bytes() + b" ")
            with self.assertRaises(error):
                verify(evidence)

            linked_evidence = root / "linked-evidence"
            make_fixture(linked_evidence, self._synthetic_observation())
            target = root / "target"
            target.write_text("outside evidence\n", encoding="utf8")
            link = linked_evidence / "linked"
            link.symlink_to(target)
            with self.assertRaises(error):
                verify(linked_evidence)

            root_target = root / "root-target"
            make_fixture(root_target, self._synthetic_observation())
            root_link = root / "root-link"
            root_link.symlink_to(root_target, target_is_directory=True)
            with self.assertRaises(error):
                verify(root_link)

            inconsistent = root / "inconsistent"
            make_fixture(inconsistent, self._synthetic_observation())
            (inconsistent / self.resource["JOB_STATUS_FILE"]).write_text(
                "failure\n", encoding="ascii"
            )
            (inconsistent / self.resource["CHECKSUM_FILE"]).unlink()
            self.resource["write_evidence_hashes"](inconsistent)
            with self.assertRaises(error):
                verify(inconsistent)

    def test_failure_finalization_replaces_checksums_and_partial_observation(self):
        make_fixture = self.resource["write_test_evidence_fixture"]
        finalize = self.resource["_finalize_failure"]
        verify = self.resource["verify_evidence"]
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            make_fixture(evidence, self._synthetic_observation())
            report = json.loads(
                (evidence / self.resource["REPORT_FILE"]).read_text(encoding="utf8")
            )
            finalize(evidence, report, RuntimeError("synthetic probe failure"))
            self.assertFalse((evidence / self.resource["OBSERVATION_FILE"]).exists())
            self.assertEqual(verify(evidence)["status"], "FAIL")

    def test_frozen_fnv1a64_and_single_job_promotion_boundary(self):
        fnv1a64 = self.resource["fnv1a64_bytes"]
        self.assertEqual(fnv1a64(b""), "cbf29ce484222325")
        self.assertEqual(fnv1a64(b"hello"), "a430d84680aabd0b")
        require_int = self.resource["_require_int"]
        result_names = self.resource["RESULT_NAMES"]
        for result in result_names:
            self.assertEqual(
                require_int(result, "frozen verifier result", min(result_names)),
                result,
            )
        with self.assertRaises(self.resource["ResourceEnvelopeError"]):
            require_int(False, "frozen verifier result", min(result_names))

        local = self.resource["_local_ci_context"]()
        local_trust = self.resource["_build_trust"](local, True)
        self.assertEqual(local_trust["label"], "LOCAL_OBSERVATION")
        self.assertFalse(local_trust["trusted_observation"])
        self.assertFalse(local_trust["promotion_eligible"])

        head = "a" * 40
        main = {
            **local,
            "github_actions": True,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "repository": "scottdhughes/quantum-proof-bitcoin",
            "repository_id": "1136579990",
            "event_name": "push",
            "ref": "refs/heads/main",
            "ref_protected": True,
            "sha": head,
            "workflow": "ML-DSA-44 verifier resource envelope",
            "workflow_ref": (
                "scottdhughes/quantum-proof-bitcoin/.github/workflows/"
                "ml-dsa-44-resource-envelope.yml@refs/heads/main"
            ),
            "workflow_sha": head,
            "run_id": "123",
            "run_attempt": "1",
            "run_number": "7",
            "job": "observe",
            "expected_checkout_head": head,
        }
        validated = self.resource["_validate_github_context"](main, head)
        main_trust = self.resource["_build_trust"](validated, True)
        self.assertEqual(main_trust["label"], "TRUSTED_MAIN_OBSERVATION")
        self.assertTrue(main_trust["trusted_observation"])
        self.assertFalse(main_trust["promotion_eligible"])
        manual = {**main, "event_name": "workflow_dispatch"}
        manual_trust = self.resource["_build_trust"](
            self.resource["_validate_github_context"](manual, head), True
        )
        self.assertEqual(
            manual_trust["label"], "UNTRUSTED_MANUAL_OBSERVATION"
        )
        self.assertFalse(manual_trust["trusted_observation"])
        self.assertFalse(manual_trust["promotion_eligible"])
        invalid = deepcopy(main)
        invalid["repository_id"] = "1"
        with self.assertRaises(self.resource["ResourceEnvelopeError"]):
            self.resource["_validate_github_context"](invalid, head)

    def test_build_command_evidence_is_relocatable(self):
        compiler = "/opt/toolchain/bin/clang"
        source_root = str(REPO_ROOT)
        build_root = Path("/tmp/pqbtc-resource-build")
        raw_commands = [
            [
                compiler,
                f"-I{ENGINEERING_DIR}",
                str(RESOURCE_PROBE),
                "-o",
                str(build_root / "probe.o"),
            ]
        ]
        normalized = self.resource["_normalize_commands"](
            raw_commands, build_root
        )["commands"]
        self.assertEqual(
            normalized,
            [
                [
                    compiler,
                    "-I$REPO_ROOT/contrib/ml-dsa-engineering",
                    (
                        "$REPO_ROOT/contrib/ml-dsa-engineering/"
                        "pqbtc_mldsa44_resource_probe.c"
                    ),
                    "-o",
                    "$BUILD_DIR/probe.o",
                ]
            ],
        )
        expected = self.resource["_expected_normalized_commands"](compiler)
        self.assertTrue(all("-pthread" in command for command in expected))
        expected_text = json.dumps(expected, sort_keys=True)
        self.assertNotIn(source_root, expected_text)
        self.assertIn("$REPO_ROOT/contrib/ml-dsa-engineering", expected_text)
        self.assertIn("$BUILD_DIR/pqbtc_mldsa44-resource-probe", expected_text)

        expanded = [
            [
                argument.replace("$REPO_ROOT", source_root).replace(
                    "$BUILD_DIR", str(build_root)
                )
                for argument in command
            ]
            for command in expected
        ]
        self.assertEqual(
            self.resource["_normalize_commands"](expanded, build_root)[
                "commands"
            ],
            expected,
        )

    def test_build_command_normalization_is_fail_closed(self):
        compiler = str(REPO_ROOT / "toolchain" / "clang")
        build_root = Path("/tmp/pqbtc-resource-build")
        outside_substring = f"/unrelated{REPO_ROOT}/source.c"
        normalized = self.resource["_normalize_commands"](
            [
                [
                    compiler,
                    outside_substring,
                    f"-I{outside_substring}",
                    str(RESOURCE_PROBE),
                    "-o",
                    str(build_root / "probe.o"),
                ]
            ],
            build_root,
        )["commands"][0]
        self.assertEqual(normalized[0], compiler)
        self.assertEqual(normalized[1], outside_substring)
        self.assertEqual(normalized[2], f"-I{outside_substring}")
        self.assertEqual(
            normalized[3],
            (
                "$REPO_ROOT/contrib/ml-dsa-engineering/"
                "pqbtc_mldsa44_resource_probe.c"
            ),
        )
        self.assertEqual(normalized[5], "$BUILD_DIR/probe.o")

        for placeholder in ("$REPO_ROOT", "$BUILD_DIR"):
            with self.subTest(placeholder=placeholder):
                with self.assertRaises(
                    self.resource["ResourceEnvelopeError"]
                ):
                    self.resource["_normalize_commands"](
                        [
                            [
                                "/usr/bin/clang",
                                f"{placeholder}/source.c",
                            ]
                        ],
                        build_root,
                    )
                with self.assertRaises(
                    self.resource["ResourceEnvelopeError"]
                ):
                    self.resource["_expected_normalized_commands"](
                        f"/opt/{placeholder}/clang"
                    )

    def test_workflow_preserves_pr_main_trust_boundary(self):
        workflow = RESOURCE_WORKFLOW.read_text(encoding="utf8")
        observe_job_preamble = workflow.split("  observe:\n", 1)[1].split(
            "    steps:\n", 1
        )[0]
        for required in (
            "pull_request:",
            "push:",
            "branches:",
            "- main",
            "workflow_dispatch:",
            "contents: read",
            "gcc",
            "clang",
            "fetch-depth: 0",
            "persist-credentials: false",
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
            "run_verifier_resource_envelope.py",
            "--output-dir",
            "--verify-evidence",
            "upload-artifact",
            "if: always()",
            '"contrib/ml-dsa-ref/vectors.json"',
            '"contrib/ml-dsa-engineering/pqbtc_mldsa44_test.h"',
            "timeout-minutes: 30",
            (
                "EVIDENCE_DIR: ${{ runner.temp }}/"
                "ml-dsa-44-resource-envelope-${{ matrix.compiler }}"
            ),
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("${{ runner.", observe_job_preamble)
        self.assertNotIn("EVIDENCE_DIR:", observe_job_preamble)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("actions/cache", workflow)

    def test_resource_lane_is_absent_from_production_build_surfaces(self):
        forbidden = (
            "pqbtc_mldsa44_resource_probe",
            "run_verifier_resource_envelope",
            "verifier_resource_policy",
        )
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.splitlines()
        manifests = [
            REPO_ROOT / relative
            for relative in tracked
            if Path(relative).name in {"CMakeLists.txt", "Makefile.am", "meson.build"}
            or Path(relative).suffix == ".mk"
        ]
        self.assertTrue(manifests)
        for manifest in manifests:
            content = manifest.read_text(encoding="utf8", errors="replace")
            for marker in forbidden:
                self.assertNotIn(marker, content, manifest)

        public_header = (ENGINEERING_DIR / "pqbtc_mldsa44.h").read_text(
            encoding="utf8"
        )
        config = (ENGINEERING_DIR / "pqbtc_mldsa44_config.h").read_text(
            encoding="utf8"
        )
        for marker in forbidden:
            self.assertNotIn(marker, public_header)
            self.assertNotIn(marker, config)

    @staticmethod
    def _synthetic_observation() -> dict:
        samples = list(range(1, 32))
        batch_outcomes = [
            {"ok": 100, "invalid_argument": 100, "verify_rejection": 4087},
            {"ok": 4287, "invalid_argument": 0, "verify_rejection": 0},
            {"ok": 0, "invalid_argument": 0, "verify_rejection": 4287},
            {"ok": 100, "invalid_argument": 0, "verify_rejection": 4187},
        ]
        return {
            "schema_version": 1,
            "status": "PASS",
            "records": 240,
            "sample_count": 31,
            "batch_calls": 4287,
            "completed_calls": 17149,
            "selection_counts": {
                "mixed_rotating": 240,
                "valid_rotating": 4,
                "deep_reject_rotating": 7,
                "same_key_mixed": 11,
            },
            "first_call": {
                "record": 0,
                "result": 0,
                "wall_ns": 1,
                "cpu_ns": 1,
            },
            "batches": [
                {
                    "id": batch_id,
                    "calls": 4287,
                    "outcomes": batch_outcomes[index],
                    "wall_samples_ns": samples,
                    "cpu_samples_ns": samples,
                }
                for index, batch_id in enumerate(BATCH_IDS)
            ],
            "control": {
                "iterations": 4287,
                "wall_samples_ns": samples,
                "cpu_samples_ns": samples,
            },
            "heap_calls": {
                "malloc": 0,
                "calloc": 0,
                "realloc": 0,
                "free": 0,
                "aligned_alloc": 0,
                "posix_memalign": 0,
            },
            "thread_stack_bytes": 131072,
            "thread_guard_bytes": 4096,
            "peak_rss_kib": 1024,
            "clock_resolution_ns": {"monotonic": 1, "thread_cpu": 1},
            "input_fnv1a64_before": "0000000000000001",
            "input_fnv1a64_after": "0000000000000001",
            "result_accumulator": 1,
        }


if __name__ == "__main__":
    unittest.main()
