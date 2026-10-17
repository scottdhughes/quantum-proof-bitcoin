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
        activation = "consensus.shrincs_v0 = opts.shrincs_labnet;"
        self.assertEqual(chainparams.count(activation), 1)
        regtest_start = chainparams.index("class CRegTestParams")
        activation_position = chainparams.index(activation)
        self.assertGreater(activation_position, regtest_start)
        self.assertIn("bool shrincs_labnet{false};", (REPO_ROOT / "src" / "kernel" / "chainparams.h").read_text(encoding="utf-8"))
        self.assertIn("m_chain_type = ChainType::REGTEST;", chainparams[regtest_start:activation_position])
        self.assertIn('bech32_hrp = "pqsl";', chainparams)
        self.assertIn("0x91, 0xe1, 0xca, 0xc8", chainparams)

    def test_labnet_base_directory_and_rpc_identity(self) -> None:
        base_params = (REPO_ROOT / "src" / "chainparamsbase.cpp").read_text(encoding="utf-8")
        self.assertIn('CBaseChainParams>("shrincslab", 29332)', base_params)

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
            "87edbe9bb060421d9db6c2946672e384e8914cc11f2971249e3ede1c639361f1",
            "35a53e8064324de5ba7ca312a01769a1f76a21216df0ef97a78fdb9fb0190cb0",
            "df6af2fda86516112cba860db86b7d793232796e837c85604db00827c8df17b5",
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
            "e30df62104d3f8f950105fae77304c8c390a057f4076174678e36108196b7b30",
            "dcc01ab0cda032b2ab35e3db45bfe75fd34e4324ca30a4cf42025ed6cc07c291",
            "df6af2fda86516112cba860db86b7d793232796e837c85604db00827c8df17b5",
        ):
            self.assertIn(expected, vector_header)


if __name__ == "__main__":
    unittest.main()
