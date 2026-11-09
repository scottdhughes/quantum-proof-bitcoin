"""Regression tests for compatibility-frozen specs under a release hold."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "gatekeeper", REPO_ROOT / "contrib/devtools/gatekeeper.py"
)
assert SPEC and SPEC.loader
gatekeeper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gatekeeper)
with (REPO_ROOT / "contrib/devtools/gatekeeper.yaml").open(encoding="utf-8") as rules_file:
    CONTRACT = gatekeeper.yaml.safe_load(rules_file)["frozen_doc_contract"]


FROZEN_DOC = """# Test spec

## Status: FROZEN IMPLEMENTATION - RELEASE HOLD
## Spec-ID: TEST-v1
## Frozen-By: test-compatibility-freeze
## Consensus-Relevant: YES

The implementation is compatibility-frozen; production remains on hold.
"""


class GatekeeperFrozenStatusTest(unittest.TestCase):
    def check_requirement(self, base_content: str | None, head_content: str = FROZEN_DOC,
                          *, where: str = "base") -> tuple[bool, str]:
        contents = {"base-ref": base_content, "head-ref": head_content}
        with patch.object(gatekeeper, "git_show_file", side_effect=lambda ref, path: contents[ref]):
            return gatekeeper.check_file_requirement(
                {"where": where, "file": "docs/TEST.md", "contains": ["## Status: FROZEN"]},
                "base-ref", "head-ref", CONTRACT,
            )

    def test_both_documented_frozen_statuses_satisfy_requirement(self) -> None:
        for status in ("FROZEN", "FROZEN IMPLEMENTATION - RELEASE HOLD"):
            with self.subTest(status=status):
                doc = FROZEN_DOC.replace("FROZEN IMPLEMENTATION - RELEASE HOLD", status)
                self.assertEqual(self.check_requirement(doc), (True, ""))

    def test_current_repository_specs_satisfy_full_frozen_contract(self) -> None:
        for path in ("docs/PQSIG_INTERNALS.md", "docs/PQSIG_WIRE_FORMAT.md"):
            with self.subTest(path=path):
                content = (REPO_ROOT / path).read_text(encoding="utf-8")
                self.assertEqual(self.check_requirement(content), (True, ""))

    def test_arbitrary_status_suffixes_are_not_frozen(self) -> None:
        for status in (
            "DRAFT", "FROZENISH", "FROZEN - DRAFT", "FROZEN IMPLEMENTATION",
            "FROZEN IMPLEMENTATION - RELEASE HOLD - DRAFT",
        ):
            with self.subTest(status=status):
                doc = FROZEN_DOC.replace("FROZEN IMPLEMENTATION - RELEASE HOLD", status)
                self.assertFalse(self.check_requirement(doc)[0])

    def test_inline_and_late_status_headings_are_rejected(self) -> None:
        for heading in ("## Status: FROZEN", "## Status: FROZEN IMPLEMENTATION - RELEASE HOLD"):
            for content in (f"Example: {heading}\n", "\n" * 30 + heading + "\n"):
                with self.subTest(content=content):
                    self.assertFalse(gatekeeper.is_frozen_doc(content))

    def test_first_thirty_lines_boundary_is_preserved(self) -> None:
        heading = "## Status: FROZEN IMPLEMENTATION - RELEASE HOLD\n"
        self.assertTrue(gatekeeper.is_frozen_doc("\n" * 29 + heading))
        self.assertFalse(gatekeeper.is_frozen_doc("\n" * 30 + heading))

    def test_release_hold_still_requires_every_contract_header(self) -> None:
        for header in (
            "## Spec-ID: TEST-v1\n", "## Frozen-By: test-compatibility-freeze\n",
            "## Consensus-Relevant: YES\n",
        ):
            with self.subTest(header=header):
                passed, error = self.check_requirement(FROZEN_DOC.replace(header, ""))
                self.assertFalse(passed)
                self.assertIn("missing required header", error)

    def test_release_hold_still_rejects_forbidden_tokens(self) -> None:
        for token in ("TODO", "TBD"):
            with self.subTest(token=token):
                passed, error = self.check_requirement(FROZEN_DOC + token + "\n")
                self.assertFalse(passed)
                self.assertIn("forbidden token", error)

    def test_changed_release_hold_doc_is_subject_to_contract(self) -> None:
        violations = gatekeeper.check_frozen_doc_contract(
            FROZEN_DOC + "TODO\n", "docs/TEST.md", CONTRACT
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("forbidden token", violations[0])

    def test_head_freeze_cannot_replace_base_freeze(self) -> None:
        draft = FROZEN_DOC.replace("FROZEN IMPLEMENTATION - RELEASE HOLD", "DRAFT")
        self.assertFalse(self.check_requirement(draft, FROZEN_DOC)[0])
        self.assertTrue(self.check_requirement(FROZEN_DOC, draft)[0])

    def test_missing_base_doc_cannot_be_supplied_only_on_head(self) -> None:
        passed, error = self.check_requirement(None, FROZEN_DOC)
        self.assertFalse(passed)
        self.assertIn("not found on base branch", error)

    def test_explicit_head_requirements_still_use_head(self) -> None:
        draft = FROZEN_DOC.replace("FROZEN IMPLEMENTATION - RELEASE HOLD", "DRAFT")
        self.assertTrue(self.check_requirement(draft, FROZEN_DOC, where="head")[0])
        self.assertFalse(self.check_requirement(FROZEN_DOC, draft, where="head")[0])


if __name__ == "__main__":
    unittest.main()
