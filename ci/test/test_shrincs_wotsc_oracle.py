"""Unit tests for the libshrincs WOTS+C compatibility harness."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_libshrincs_wotsc.py"
SPEC = importlib.util.spec_from_file_location("shrincs_wotsc_oracle", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def valid_case(name: str = "case0") -> str:
    values = {
        "sk_seed": "00" * 16,
        "pk_seed": "11" * 16,
        "adrs": "22" * 22,
        "msg": "33" * 32,
        "counter": "7",
        "digits": "04" * 32,
        "h_grind": "44" * 16,
        "sig": "55" * 514,
        "pk": "66" * 16,
    }
    return "\n".join([f"# {name}"] + [f"{key} = {value}" for key, value in values.items()])


class ShrincsWotscOracleTests(unittest.TestCase):
    def test_parse_valid_case(self) -> None:
        parsed = CHECKER.parse_kat_text(valid_case())
        self.assertEqual(set(parsed), {"case0"})
        self.assertEqual(parsed["case0"]["counter"], 7)
        self.assertEqual(parsed["case0"]["sig"], "55" * 514)

    def test_parse_multiple_cases(self) -> None:
        parsed = CHECKER.parse_kat_text(valid_case("a") + "\n\n" + valid_case("b"))
        self.assertEqual(set(parsed), {"a", "b"})

    def test_duplicate_case_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "duplicate"):
            CHECKER.parse_kat_text(valid_case() + "\n\n" + valid_case())

    def test_missing_field_rejected(self) -> None:
        malformed = valid_case().replace("\npk = " + "66" * 16, "")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "incomplete"):
            CHECKER.parse_kat_text(malformed)

    def test_invalid_hex_rejected(self) -> None:
        malformed = valid_case().replace("sk_seed = " + "00" * 16, "sk_seed = zz")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "invalid hex"):
            CHECKER.parse_kat_text(malformed)

    def test_constants_accept_pinned_profile(self) -> None:
        reference = SimpleNamespace(
            WOTS_C_CHAIN_BITS=4,
            WOTS_C_CHAIN_COUNT=32,
            WOTS_C_CONSTANT_SUM=240,
            WOTS_C_CHAINS_SIZE=512,
        )
        defines = {
            "SHRINCS_WOTS_SK_SEED_BYTES": 16,
            "SHRINCS_WOTS_PK_SEED_BYTES": 16,
            "SHRINCS_WOTS_MSG_BYTES": 32,
            "SHRINCS_WOTS_PK_BYTES": 16,
            "SHRINCS_WOTS_SIG_BYTES": 514,
            "SHRINCS_WOTS_ADDR_BYTES": 22,
        }
        CHECKER.validate_constants(reference, defines)

    def test_constant_drift_rejected(self) -> None:
        reference = SimpleNamespace(
            WOTS_C_CHAIN_BITS=4,
            WOTS_C_CHAIN_COUNT=32,
            WOTS_C_CONSTANT_SUM=239,
            WOTS_C_CHAINS_SIZE=512,
        )
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "WOTS_C_CONSTANT_SUM drifted"):
            CHECKER.validate_constants(reference, {})


class ShrincsWotscProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pqbtc-wotsc-provenance-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "source"
        self.repo.mkdir()
        self.git("init", "-q", "--object-format=sha1")
        (self.repo / "impl").mkdir()
        (self.repo / "impl" / "model.py").write_text("VALUE = 7\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("build/\n", encoding="utf-8")
        self.git("add", "--", ".gitignore", "impl/model.py")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.pin = self.git("rev-parse", "HEAD").strip()
        self.manifest = {"upstream": {
            "draft_specification": {"commit": self.pin},
            "libshrincs_wotsc": {"commit": self.pin},
        }}

    def git(self, *args: str) -> str:
        env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True, env=env).stdout

    def validate(self, path: Path | None = None) -> tuple[str, str]:
        checkout = self.repo if path is None else path
        return CHECKER.validate_paths(self.manifest, checkout, checkout)

    def test_clean_pinned_checkout_is_accepted(self) -> None:
        self.assertEqual(self.validate(), (self.pin, self.pin))

    def test_tracked_source_changes_are_rejected(self) -> None:
        (self.repo / "impl" / "model.py").write_text("VALUE = 8\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "tracked source differs"):
            self.validate()

    def test_index_hidden_source_changes_are_rejected(self) -> None:
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "--", "impl/model.py")
                (self.repo / "impl" / "model.py").write_text("VALUE = 8\n", encoding="utf-8")
                with self.assertRaisesRegex(CHECKER.CompatibilityError, "tracked source differs"):
                    self.validate()
                (self.repo / "impl" / "model.py").write_text("VALUE = 7\n", encoding="utf-8")
                self.git("update-index", flag.replace("--", "--no-", 1), "--", "impl/model.py")

    def test_nested_directory_cannot_borrow_parent_repository_pin(self) -> None:
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "checkout root"):
            self.validate(self.repo / "impl")

    def test_untracked_source_is_rejected(self) -> None:
        (self.repo / "injected.py").write_text("VALUE = 9\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "untracked"):
            self.validate()

    def test_ignored_untracked_source_is_rejected(self) -> None:
        (self.repo / "build").mkdir()
        (self.repo / "build" / "injected.py").write_text("VALUE = 9\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "untracked"):
            self.validate()

    def test_staged_extra_source_is_rejected(self) -> None:
        (self.repo / "injected.py").write_text("VALUE = 9\n", encoding="utf-8")
        self.git("add", "--", "injected.py")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "staged"):
            self.validate()

    def test_git_replacement_cannot_relabel_modified_source(self) -> None:
        (self.repo / "impl" / "model.py").write_text("VALUE = 8\n", encoding="utf-8")
        self.git("add", "--", "impl/model.py")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "changed")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", self.pin, replacement)
        self.git("checkout", "--detach", self.pin)
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "tracked source differs"):
            self.validate()

    def test_symlink_cannot_substitute_for_pinned_regular_source(self) -> None:
        replacement = Path(self.temp.name) / "outside.py"
        replacement.write_text("VALUE = 7\n", encoding="utf-8")
        source = self.repo / "impl" / "model.py"
        source.unlink()
        source.symlink_to(replacement)
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "regular source"):
            self.validate()

    def test_module_loading_does_not_dirty_pinned_checkout(self) -> None:
        module = CHECKER.load_module(self.repo / "impl" / "model.py", "fixture_model")
        self.assertEqual(module.VALUE, 7)
        self.assertFalse((self.repo / "impl" / "__pycache__").exists())
        self.assertEqual(self.validate(), (self.pin, self.pin))

    def test_module_loading_preserves_source_annotation_semantics(self) -> None:
        source = self.repo / "impl" / "model.py"
        source.write_text("VALUE: int = 7\n", encoding="utf-8")
        module = CHECKER.load_module(source, "fixture_annotations")
        self.assertIs(module.__annotations__["VALUE"], int)

    def test_manifest_policy_is_validated_before_loading_upstream_code(self) -> None:
        original = json.loads((REPO_ROOT / "contrib" / "shrincs" / "manifest.json").read_text())
        for field, value in (("consensus_enabled", True), ("production_backend", "unexpected"),
                             ("release_hold", False)):
            with self.subTest(field=field):
                manifest = dict(original, **{field: value})
                path = Path(self.temp.name) / "manifest.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(CHECKER.CompatibilityError):
                    CHECKER.load_manifest(path)

    def test_arbitrary_manifest_pin_is_rejected(self) -> None:
        manifest = json.loads((REPO_ROOT / "contrib" / "shrincs" / "manifest.json").read_text())
        manifest["upstream"]["draft_specification"]["commit"] = self.pin
        path = Path(self.temp.name) / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.CompatibilityError, "commit drifted"):
            CHECKER.load_manifest(path)


if __name__ == "__main__":
    unittest.main()
