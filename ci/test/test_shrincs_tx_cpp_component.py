"""Architecture guards for the unwired SHRINCS transaction C++ component."""

from __future__ import annotations

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
HEADER = REPO_ROOT / "src" / "script" / "shrincs_tx_v0.h"
SOURCE = REPO_ROOT / "src" / "script" / "shrincs_tx_v0.cpp"
TEST = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_tests.cpp"
SIGNED_SEAM_TEST = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_signed_seam_tests.cpp"
SIGNED_SEAM_VECTORS = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_signed_seam_vectors.h"
TEST_CMAKE = REPO_ROOT / "src" / "test" / "CMakeLists.txt"
TOP_CMAKE = REPO_ROOT / "src" / "CMakeLists.txt"

ALLOWED_REFERENCES = {
    HEADER.resolve(),
    SOURCE.resolve(),
    TEST.resolve(),
    SIGNED_SEAM_TEST.resolve(),
    SIGNED_SEAM_VECTORS.resolve(),
    TEST_CMAKE.resolve(),
}


class ShrincsTxCppComponentTests(unittest.TestCase):
    def test_expected_files_exist(self) -> None:
        for path in (HEADER, SOURCE, TEST, SIGNED_SEAM_TEST, SIGNED_SEAM_VECTORS):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())

    def test_component_is_compiled_only_into_test_binary(self) -> None:
        test_cmake = TEST_CMAKE.read_text(encoding="utf-8")
        top_cmake = TOP_CMAKE.read_text(encoding="utf-8")
        self.assertEqual(test_cmake.count("../script/shrincs_tx_v0.cpp"), 1)
        self.assertIn("shrincs_tx_v0_tests.cpp", test_cmake)
        self.assertNotIn("shrincs_tx_v0", top_cmake)
        self.assertIn("deliberately compiled only", test_cmake)

    def test_signed_seam_is_explicit_opt_in_and_test_only(self) -> None:
        test_cmake = TEST_CMAKE.read_text(encoding="utf-8")
        self.assertIn(
            'option(PQBTC_ENABLE_SHRINCS_SIGNED_SEAM_TESTS "Build the research-only native SHRINCS transaction signed-seam suite" OFF)',
            test_cmake,
        )
        self.assertIn("shrincs_tx_v0_signed_seam_tests.cpp", test_cmake)
        self.assertIn("contrib/shrincs-ref/full_verify.c", test_cmake)
        self.assertIn("contrib/shrincs-ref/stateful_verify.c", test_cmake)
        self.assertIn("contrib/shrincs-ref/stateless_verify.c", test_cmake)
        self.assertIn("PQBTC_LIBSHRINCS_SOURCE_DIR", test_cmake)
        self.assertIn("test_pqbtc only", test_cmake)

    def test_no_other_node_source_references_component(self) -> None:
        references: list[str] = []
        for path in (REPO_ROOT / "src").rglob("*"):
            if not path.is_file() or path.resolve() in ALLOWED_REFERENCES:
                continue
            if path.suffix not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "shrincs_tx_v0" in text:
                references.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(references, [])

    def test_header_freezes_the_candidate_not_activation(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn('OUTPUT_TAG{"PQBTC/SHRINCS/OUTPUT/v0"}', header)
        self.assertIn('SIGHASH_TAG{"PQBTC/SHRINCS/SIGHASH/v0"}', header)
        self.assertIn('SIGNING_CONTEXT{"PQBTC/SHRINCS/TXSIG/v0"}', header)
        self.assertIn("PROPOSED_WITNESS_VERSION{2}", header)
        for forbidden in (
            "SCRIPT_VERIFY_SHRINCS",
            "OP_CHECKSHRINCS",
            "production_backend",
            "consensus_enabled = true",
        ):
            self.assertNotIn(forbidden, header)

    def test_source_uses_core_types_but_no_signature_fallback(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for required in (
            "TaggedHash",
            "CTransaction",
            "CTxOut",
            "CScriptWitness",
            "MoneyRange",
            "IsWitnessProgram",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "CheckECDSASignature",
            "CheckSchnorrSignature",
            "PQSigVerify",
            "VerifyScript",
            "EvalScript",
            "shrincs_verify",
        ):
            self.assertNotIn(forbidden, source)

    def test_native_tests_bind_python_and_wolfram_results(self) -> None:
        test = TEST.read_text(encoding="utf-8")
        for expected in (
            "e81658399900d55841623b54f075cebfe6c9caf307e62e5952634d16ae61f35d",
            "cdf2b774b68cdbd23a424faee209495c523a790c92fa6ea293e166ea075245e7",
            "dc00d9f169e44ad39fea3db0736ee5ec834d8a3ae8e8ac7e8997ee1eacc399d5",
            "1'725'043U",
            "3'469'818U",
        ):
            self.assertIn(expected, test)
        self.assertIn("ExpectedMutationDigests", test)
        self.assertIn("BOOST_AUTO_TEST_SUITE(shrincs_tx_v0_tests)", test)

    def test_signed_seam_binds_real_vectors_and_full_verifier(self) -> None:
        test = SIGNED_SEAM_TEST.read_text(encoding="utf-8")
        vector_header = SIGNED_SEAM_VECTORS.read_text(encoding="utf-8")
        for expected in (
            "pqbtc_shrincs_verify",
            "STATEFUL_SIGNATURE_SHA256_HEX",
            "STATELESS_SIGNATURE_SHA256_HEX",
            "TransactionMutationCases",
            "rejected, 56U",
        ):
            self.assertIn(expected, test)
        for expected in (
            "7677e9c8eab7d9955ebb64576e6c24f563cdb38b5e9624b8e3c22e72fc481697",
            "546590eaa4c4ab44ba390ba424ebfae27b8cef5e14343b66626e3acf24b9daa6",
            "dc00d9f169e44ad39fea3db0736ee5ec834d8a3ae8e8ac7e8997ee1eacc399d5",
        ):
            self.assertIn(expected, vector_header)


if __name__ == "__main__":
    unittest.main()
