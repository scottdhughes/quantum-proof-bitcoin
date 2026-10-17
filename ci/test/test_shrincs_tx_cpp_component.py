"""Architecture guards for the regtest-only SHRINCS transaction component."""

from __future__ import annotations

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
HEADER = REPO_ROOT / "src" / "script" / "shrincs_tx_v0.h"
SOURCE = REPO_ROOT / "src" / "script" / "shrincs_tx_v0.cpp"
INTERPRETER = REPO_ROOT / "src" / "script" / "interpreter.cpp"
FULL_VERIFIER = REPO_ROOT / "src" / "crypto" / "shrincs" / "full_verify.c"
TEST = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_tests.cpp"
SIGNED_SEAM_TEST = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_signed_seam_tests.cpp"
SIGNED_SEAM_VECTORS = REPO_ROOT / "src" / "test" / "shrincs_tx_v0_signed_seam_vectors.h"
TEST_CMAKE = REPO_ROOT / "src" / "test" / "CMakeLists.txt"
TOP_CMAKE = REPO_ROOT / "src" / "CMakeLists.txt"
CRYPTO_CMAKE = REPO_ROOT / "src" / "crypto" / "CMakeLists.txt"
CONSENSUS_PARAMS = REPO_ROOT / "src" / "consensus" / "params.h"
CHAINPARAMS = REPO_ROOT / "src" / "kernel" / "chainparams.cpp"
VALIDATION = REPO_ROOT / "src" / "validation.cpp"

COMPONENT_FILES = {
    HEADER.resolve(),
    SOURCE.resolve(),
    TEST.resolve(),
    SIGNED_SEAM_TEST.resolve(),
    SIGNED_SEAM_VECTORS.resolve(),
}


class ShrincsTxCppComponentTests(unittest.TestCase):
    def test_expected_files_exist(self) -> None:
        for path in (
            HEADER,
            SOURCE,
            INTERPRETER,
            FULL_VERIFIER,
            TEST,
            SIGNED_SEAM_TEST,
            SIGNED_SEAM_VECTORS,
        ):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())

    def test_component_and_verifier_are_linked_into_node_consensus(self) -> None:
        top_cmake = TOP_CMAKE.read_text(encoding="utf-8")
        crypto_cmake = CRYPTO_CMAKE.read_text(encoding="utf-8")
        test_cmake = TEST_CMAKE.read_text(encoding="utf-8")

        self.assertEqual(top_cmake.count("script/shrincs_tx_v0.cpp"), 1)
        self.assertIn("script/interpreter.cpp", top_cmake)
        for source in (
            "shrincs/full_verify.c",
            "shrincs/stateful_verify.c",
            "shrincs/stateless_verify.c",
            "shrincs/third_party/libshrincs/src/wots.c",
        ):
            self.assertIn(source, crypto_cmake)
        self.assertIn("shrincs_tx_v0_tests.cpp", test_cmake)
        self.assertIn("shrincs_tx_v0_signed_seam_tests.cpp", test_cmake)
        self.assertNotIn("PQBTC_ENABLE_SHRINCS_SIGNED_SEAM_TESTS", test_cmake)

    def test_interpreter_is_the_only_external_cpp_consumer(self) -> None:
        references: list[str] = []
        for path in (REPO_ROOT / "src").rglob("*"):
            if not path.is_file() or path.resolve() in COMPONENT_FILES:
                continue
            if path.suffix not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "shrincs_tx_v0" in text:
                references.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(references, ["src/script/interpreter.cpp"])

    def test_activation_defaults_off_and_is_assigned_only_in_regtest(self) -> None:
        consensus_params = CONSENSUS_PARAMS.read_text(encoding="utf-8")
        chainparams = CHAINPARAMS.read_text(encoding="utf-8")

        self.assertIn("bool shrincs_v0{false};", consensus_params)
        activation = "consensus.shrincs_v0 = true;"
        self.assertEqual(chainparams.count(activation), 1)
        regtest_start = chainparams.index("class CRegTestParams")
        activation_position = chainparams.index(activation)
        self.assertGreater(activation_position, regtest_start)
        self.assertIn(
            "m_chain_type = ChainType::REGTEST;",
            chainparams[regtest_start:activation_position],
        )

    def test_validation_flags_follow_consensus_scope(self) -> None:
        validation = VALIDATION.read_text(encoding="utf-8")
        self.assertIn(
            "if (m_active_chainstate.m_chainman.GetConsensus().shrincs_v0)",
            validation,
        )
        self.assertIn("if (consensusparams.shrincs_v0)", validation)
        self.assertGreaterEqual(validation.count("SCRIPT_VERIFY_SHRINCS_V0"), 2)

    def test_witness_v2_requires_explicit_flag_and_native_program(self) -> None:
        interpreter = INTERPRETER.read_text(encoding="utf-8")
        branch_start = interpreter.index(
            "witversion == shrincs_tx_v0::PROPOSED_WITNESS_VERSION"
        )
        branch = interpreter[branch_start : branch_start + 1_200]
        for required in (
            "program.size() == shrincs_tx_v0::PROGRAM_BYTES",
            "!is_p2sh",
            "flags & SCRIPT_VERIFY_SHRINCS_V0",
            "shrincs_tx_v0::ParseWitness",
            "checker.CheckSHRINCSSignature",
        ):
            self.assertIn(required, branch)

    def test_full_verifier_dispatches_only_canonical_current_modes(self) -> None:
        verifier = FULL_VERIFIER.read_text(encoding="utf-8")
        for required in (
            "PQBTC_SHRINCS_PUBLIC_KEY_BYTES 48U",
            "PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES 5776U",
            "is_canonical_stateful_length",
            "pqbtc_shrincs_stateful_verify",
            "pqbtc_shrincs_stateless_verify",
        ):
            self.assertIn(required, verifier)
        for forbidden in (
            "CheckECDSASignature",
            "CheckSchnorrSignature",
            "PQSigVerify",
            "fallback",
        ):
            self.assertNotIn(forbidden, verifier)
        self.assertTrue(verifier.rstrip().endswith("}"))
        self.assertIn("return 0;", verifier)

    def test_header_freezes_candidate_envelope_not_network_activation(self) -> None:
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
