"""Unit tests for the stateless SHRINCS differential harness."""

from __future__ import annotations

import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_stateless.py"
SPEC = importlib.util.spec_from_file_location("shrincs_stateless_oracle", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def fixture_vectors() -> list[dict]:
    vectors = []
    for name, mode, message, context, randomizer in (
        ("stateless_deterministic_empty_context", "deterministic",
         "f4dd4a2696c1d6493ff2c86048cee4b019746f2329bdd5a8e37bf2fa843c3883", "", None),
        ("stateless_fixed_randomizer_context", "fixed-randomizer",
         "6ca8be5ef96403aa67f22a49cf8d1fc9a2c4e72beb6efce6a99a91c7d078222ce9633b5996c7f7cb13b0e5e4ad7d13",
         b"PQBTC/SHRINCS/stateless-recovery-v0".hex(), "2b1aaa0472a7b3fcc5d613a0a7cde55c"),
    ):
        key, signature = bytes.fromhex("11" * 48), b"\xff" + bytes.fromhex("22" * 5776)
        vectors.append({"name": name, "mode": mode, "message": message, "context": context,
                        "opt_rand": randomizer, "public_key": key.hex(), "signature": signature.hex(),
                        "public_key_sha256": hashlib.sha256(key).hexdigest(),
                        "signature_sha256": hashlib.sha256(signature).hexdigest()})
    return vectors


class ShrincsStatelessOracleTests(unittest.TestCase):
    def test_workflow_preflight_precedes_upstream_compilation(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/shrincs-stateless-oracle.yml").read_text()
        self.assertIn("--preflight-only", workflow)
        self.assertLess(workflow.index("--preflight-only"), workflow.index("          cc "))
        preflight = workflow[:workflow.index("          cc ")]
        self.assertIn("contrib/shrincs-ref/generate_resource_vectors.py", preflight)
        self.assertIn("--libshrincs upstream/libshrincs", preflight)
        self.assertIn("--shrincs-bip upstream/shrincs-bip", preflight)

    def manifest(self) -> dict:
        return {
            "upstream": {
                "draft_specification": {"commit": "a" * 40},
                "libshrincs_wotsc": {"commit": "b" * 40},
            }
        }

    def vector(self, name: str) -> dict:
        return {
            "name": name,
            "mode": "deterministic",
            "opt_rand": None,
            "message": "00" * 32,
            "context": "",
            "public_key": "11" * 48,
            "signature": "ff" + "22" * 5776,
            "public_key_sha256": "33" * 32,
            "signature_sha256": "44" * 32,
        }

    def write_corpus(self, path: Path, profile: str = CHECKER.VECTOR_PROFILE) -> None:
        path.write_text(
            json.dumps(
                {
                    "profile": profile,
                    "draft_commit": "a" * 40,
                    "libshrincs_commit": "b" * 40,
                    "vectors": fixture_vectors(),
                }
            ),
            encoding="utf-8",
        )

    def test_selected_offsets_cover_twelve_regions(self) -> None:
        offsets = CHECKER.selected_signature_offsets(5777)
        self.assertEqual(len(offsets), 12)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(offsets[-1], 5776)
        self.assertIn(16, offsets)
        self.assertIn(2256, offsets)

    def test_valid_vector_corpus_loads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path)
            vectors = CHECKER.read_vectors(path, self.manifest())
            self.assertEqual([vector["name"] for vector in vectors],
                             ["stateless_deterministic_empty_context", "stateless_fixed_randomizer_context"])

    def test_vector_profile_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path, profile="wrong")
            with self.assertRaisesRegex(CHECKER.StatelessOracleError, "profile drifted"):
                CHECKER.read_vectors(path, self.manifest())

    def test_vector_pin_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path)
            manifest = self.manifest()
            manifest["upstream"]["draft_specification"]["commit"] = "c" * 40
            with self.assertRaisesRegex(CHECKER.StatelessOracleError, "draft pin drifted"):
                CHECKER.read_vectors(path, manifest)

    def test_invalid_hex_is_rejected(self) -> None:
        vector = self.vector("bad")
        vector["signature"] = "zz"
        with self.assertRaisesRegex(CHECKER.StatelessOracleError, "invalid hex"):
            CHECKER.bytes_from_vector(vector, "signature")


class StatelessProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pqbtc-stateless-source-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "source"
        self.repo.mkdir()
        self.git("init", "-q", "--object-format=sha1")
        (self.repo / "impl").mkdir()
        (self.repo / "impl/model.py").write_text("VALUE = 7\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("build/\n", encoding="utf-8")
        self.git("add", "--", ".gitignore", "impl/model.py")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.pin = self.git("rev-parse", "HEAD").strip()
        self.manifest = {"upstream": {"draft_specification": {"commit": self.pin},
                                      "libshrincs_wotsc": {"commit": self.pin}}}

    def git(self, *args: str) -> str:
        env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True, env=env).stdout

    def validate(self, path: Path | None = None) -> None:
        root = self.repo if path is None else path
        CHECKER.validate_pins(self.manifest, root, root)

    def test_pristine_checkout_is_accepted(self) -> None:
        self.validate()

    def test_tracked_source_change_is_rejected(self) -> None:
        (self.repo / "impl/model.py").write_text("VALUE = 8\n", encoding="utf-8")
        with self.assertRaises(CHECKER.StatelessOracleError):
            self.validate()

    def test_hidden_index_source_change_is_rejected(self) -> None:
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "--", "impl/model.py")
                (self.repo / "impl/model.py").write_text("VALUE = 8\n", encoding="utf-8")
                with self.assertRaises(CHECKER.StatelessOracleError):
                    self.validate()
                (self.repo / "impl/model.py").write_text("VALUE = 7\n", encoding="utf-8")
                self.git("update-index", flag.replace("--", "--no-", 1), "--", "impl/model.py")

    def test_nested_root_cannot_borrow_parent_pin(self) -> None:
        with self.assertRaises(CHECKER.StatelessOracleError):
            self.validate(self.repo / "impl")

    def test_untracked_and_ignored_inputs_are_rejected(self) -> None:
        for relative in ("injected.py", "build/injected.py"):
            with self.subTest(relative=relative):
                source = self.repo / relative
                source.parent.mkdir(exist_ok=True)
                source.write_text("VALUE = 8\n", encoding="utf-8")
                with self.assertRaises(CHECKER.StatelessOracleError):
                    self.validate()
                source.unlink()

    def test_staged_tree_is_not_accepted_as_pinned_source(self) -> None:
        (self.repo / "impl/model.py").write_text("VALUE = 8\n", encoding="utf-8")
        self.git("add", "--", "impl/model.py")
        with self.assertRaises(CHECKER.StatelessOracleError):
            self.validate()

    def test_module_loading_does_not_dirty_checkout(self) -> None:
        loaded = CHECKER.load_module(self.repo / "impl/model.py", "stateless_fixture")
        self.assertEqual(loaded.VALUE, 7)
        self.assertFalse((self.repo / "impl/__pycache__").exists())
        self.validate()

    def test_module_annotations_preserve_source_semantics(self) -> None:
        source = self.repo / "impl/model.py"
        source.write_text("VALUE: int = 7\n", encoding="utf-8")
        loaded = CHECKER.load_module(source, "stateless_annotations")
        self.assertIs(loaded.__annotations__["VALUE"], int)

    def test_manifest_policy_cannot_be_bypassed(self) -> None:
        original = json.loads((REPO_ROOT / "contrib/shrincs/manifest.json").read_text())
        mutations = [("consensus_enabled", True), ("production_backend", "unexpected"),
                     ("release_hold", False), ("required_gates", {})]
        for key, value in mutations:
            with self.subTest(field=key):
                data = dict(original, **{key: value})
                path = Path(self.temp.name) / "manifest.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(CHECKER.StatelessOracleError):
                    CHECKER.load_manifest(path)

    def test_custom_manifest_cannot_replace_frozen_pin(self) -> None:
        data = json.loads((REPO_ROOT / "contrib/shrincs/manifest.json").read_text())
        data["upstream"]["draft_specification"]["commit"] = self.pin
        path = Path(self.temp.name) / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(CHECKER.StatelessOracleError):
            CHECKER.load_manifest(path)


class StatelessRetainedCorpusTests(ShrincsStatelessOracleTests):
    def assert_corpus_rejected(self, mutate) -> None:
        with tempfile.TemporaryDirectory(prefix="pqbtc-stateless-corpus-") as temp:
            path = Path(temp) / "vectors.json"
            self.write_corpus(path)
            data = json.loads(path.read_text())
            mutate(data)
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(CHECKER.StatelessOracleError):
                CHECKER.read_vectors(path, self.manifest())

    def test_corrupt_embedded_hash_is_rejected(self) -> None:
        for field in ("public_key_sha256", "signature_sha256"):
            with self.subTest(field=field):
                self.assert_corpus_rejected(lambda data: data["vectors"][0].update({field: "00" * 32}))

    def test_duplicate_or_reordered_cases_are_rejected(self) -> None:
        self.assert_corpus_rejected(lambda data: data["vectors"].__setitem__(1, copy.deepcopy(data["vectors"][0])))
        self.assert_corpus_rejected(lambda data: data["vectors"].reverse())

    def test_case_shape_and_metadata_drift_are_rejected(self) -> None:
        for field, value in (("mode", "deterministic"), ("context", ""), ("opt_rand", None),
                             ("message", "00" * 47)):
            with self.subTest(field=field):
                self.assert_corpus_rejected(lambda data: data["vectors"][1].update({field: value}))
        self.assert_corpus_rejected(lambda data: data["vectors"].__setitem__(0, 42))

    def test_oversized_retained_file_is_rejected_before_parsing(self) -> None:
        self.assert_corpus_rejected(lambda data: data.update({"padding": "x" * 70000}))


class StatelessResultContractTests(unittest.TestCase):
    def test_non_boolean_abi_result_is_error_not_rejection(self) -> None:
        for result in (-1, 2):
            with self.subTest(result=result), self.assertRaises(CHECKER.StatelessOracleError):
                CHECKER.verify_with_c(lambda *args: result, b"pk", b"sig", b"message", b"")

    def test_boolean_abi_results_are_preserved(self) -> None:
        self.assertTrue(CHECKER.verify_with_c(lambda *args: 1, b"p", b"s", b"m", b""))
        self.assertFalse(CHECKER.verify_with_c(lambda *args: 0, b"p", b"s", b"m", b""))

    def assert_cannot_publish(self, vectors, counts, verifier, expected_error=None, existing=False) -> None:
        # Replace external cryptographic work only; exercise real main and artifact handling.
        with tempfile.TemporaryDirectory(prefix="pqbtc-stateless-result-") as temp:
            output = Path(temp) / "vectors.json"
            if existing:
                output.write_text("prior evidence\n", encoding="utf-8")
            argv = ["check_stateless.py", "--shrincs-bip", temp, "--libshrincs", temp,
                    "--library", str(Path(temp) / "unused.so"), "--vectors-out", str(output), "--json"]
            with mock.patch("sys.argv", argv), mock.patch.object(CHECKER, "validate_pins"), \
                    mock.patch.object(CHECKER, "load_module", return_value=SimpleNamespace()), \
                    mock.patch.object(CHECKER, "load_verifier", return_value=verifier), \
                    mock.patch.object(CHECKER, "create_vectors", return_value=vectors), \
                    mock.patch.object(CHECKER, "exercise_negative_cases", side_effect=counts), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                if expected_error:
                    with self.assertRaisesRegex(CHECKER.StatelessOracleError, expected_error):
                        CHECKER.main()
                else:
                    with self.assertRaises(CHECKER.StatelessOracleError):
                        CHECKER.main()
            self.assertEqual(stdout.getvalue(), "")
            if existing:
                self.assertEqual(output.read_text(), "prior evidence\n")
            else:
                self.assertFalse(output.exists())

    def test_empty_generated_corpus_cannot_publish_pass(self) -> None:
        self.assert_cannot_publish([], [], lambda *args: 1)

    def test_failed_native_verification_cannot_create_or_overwrite_artifact(self) -> None:
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.assert_cannot_publish(fixture_vectors(), [], lambda *args: 0, existing=existing)

    def test_partial_campaign_cannot_publish_pass(self) -> None:
        for field in range(3):
            counts = [[46208,384,6],[96,0,6]]
            counts[0][field] -= 1
            with self.subTest(field=field):
                self.assert_cannot_publish(fixture_vectors(), counts, lambda *args: 1,
                                           expected_error="incomplete stateless campaign")

    def test_native_abi_campaign_is_required_before_publication(self) -> None:
        self.assert_cannot_publish(fixture_vectors(), [(46208,384,6),(96,0,6)], lambda *args: 1)

    def test_native_abi_campaign_preserves_boundary_arguments(self) -> None:
        exercise = getattr(CHECKER, "exercise_native_abi_cases", None)
        self.assertTrue(callable(exercise), "native ABI checks must be retained in the harness")
        calls = []

        def verifier(*args):
            calls.append(args)
            return int(len(calls) == 1)

        self.assertEqual(exercise(verifier, fixture_vectors()[0]), 14)
        self.assertEqual(len(calls), 14)
        self.assertIsNone(calls[1][0])
        self.assertIsNone(calls[2][2])
        self.assertEqual([args[1] for args in calls[3:6]], [0,47,49])
        self.assertEqual([args[3] for args in calls[6:10]], [0,548,5776,5778])
        self.assertEqual(calls[10][4:6], (None,1))
        self.assertEqual(calls[11][6:8], (None,1))
        self.assertEqual(calls[12][5], 4097)
        self.assertEqual(calls[13][7], 256)

    def test_native_abi_rejections_require_exact_zero_status(self) -> None:
        exercise = getattr(CHECKER, "exercise_native_abi_cases", None)
        self.assertTrue(callable(exercise), "native ABI checks must be retained in the harness")
        for result in (-1,1,2):
            with self.subTest(result=result):
                statuses = iter((1,result))
                with self.assertRaises(CHECKER.StatelessOracleError):
                    exercise(lambda *args: next(statuses), fixture_vectors()[0])


if __name__ == "__main__":
    unittest.main()
