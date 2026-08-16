"""Unit tests for the libshrincs WOTS+C compatibility harness."""

from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
