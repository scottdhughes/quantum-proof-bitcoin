// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <crypto/pqsig/pqsig.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace {

std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> DerivePkScript(const std::span<const uint8_t> sk_seed)
{
    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    if (!pqsig::DerivePkScript(out, sk_seed)) {
        throw std::runtime_error("failed to derive pk script");
    }
    return out;
}

std::vector<uint8_t> SignForScript(const CMutableTransaction& tx, const CScript& script_code, const std::span<const uint8_t> pk_script)
{
    const uint256 sighash = SignatureHash(script_code, tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    const std::array<uint8_t, 32> sk_seed{0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31};
    if (!pqsig::PQSigSign(sig, std::span<const uint8_t>{sighash.begin(), sighash.size()}, sk_seed, pk_script)) {
        throw std::runtime_error("failed to generate PQ signature");
    }
    return sig;
}

class AcceptingTaprootChecker final : public BaseSignatureChecker
{
public:
    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData&, ScriptError*) const override
    {
        return sigversion == SigVersion::TAPROOT && sig.size() == 64 && pubkey.size() == 32;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_checksig_accepts_and_rejects_deterministically)
{
    const std::array<uint8_t, 32> sk_seed{0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
                                          0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31};
    const auto pk_script = DerivePkScript(sk_seed);
    const CScript script_pubkey = CScript{} << std::vector<unsigned char>{pk_script.begin(), pk_script.end()} << OP_CHECKSIG;

    const CTransaction tx_credit{BuildCreditingTransaction(script_pubkey, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, tx_credit);

    const std::vector<uint8_t> good_sig = SignForScript(tx_spend, script_pubkey, pk_script);
    tx_spend.vin[0].scriptSig = CScript{} << std::vector<unsigned char>{good_sig.begin(), good_sig.end()};

    const CTransaction tx_spend_const{tx_spend};
    const TransactionSignatureChecker checker(&tx_spend_const, 0, 0, MissingDataBehavior::FAIL);
    ScriptError err;

    BOOST_CHECK(VerifyScript(tx_spend.vin[0].scriptSig, script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    CMutableTransaction mutated_tx = tx_spend;
    mutated_tx.vout[0].nValue = 1;
    const CTransaction mutated_tx_const{mutated_tx};
    const TransactionSignatureChecker mutated_checker(&mutated_tx_const, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(mutated_tx.vin[0].scriptSig, script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, mutated_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);

    CMutableTransaction wrong_size_tx = tx_spend;
    wrong_size_tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>(pqsig::SIG_SIZE - 1, 0x42);
    const CTransaction wrong_size_tx_const{wrong_size_tx};
    const TransactionSignatureChecker wrong_size_checker(&wrong_size_tx_const, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(wrong_size_tx.vin[0].scriptSig, script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, wrong_size_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);
}

BOOST_AUTO_TEST_CASE(inherited_taproot_rejection_guard_is_explicit)
{
    constexpr unsigned int witness_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
    constexpr unsigned int guarded_flags{witness_flags | SCRIPT_VERIFY_DISALLOW_INHERITED_TAPROOT};
    const CScript taproot_script_pubkey = CScript{} << OP_1 << std::vector<unsigned char>(32, 0x03);
    CScriptWitness taproot_witness;
    taproot_witness.stack = {std::vector<unsigned char>(64, 0x04)};
    const AcceptingTaprootChecker checker;

    ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(VerifyScript(CScript{}, taproot_script_pubkey, &taproot_witness, witness_flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!VerifyScript(CScript{}, taproot_script_pubkey, &taproot_witness, guarded_flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INHERITED_TAPROOT_DISALLOWED);

    const CScript witness_script = CScript{} << OP_TRUE;
    uint256 witness_script_hash;
    CSHA256().Write(witness_script.data(), witness_script.size()).Finalize(witness_script_hash.begin());
    const CScript witness_v0_script_pubkey = CScript{} << OP_0 << std::vector<unsigned char>{witness_script_hash.begin(), witness_script_hash.end()};
    CScriptWitness witness_v0;
    witness_v0.stack = {std::vector<unsigned char>{witness_script.begin(), witness_script.end()}};

    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(VerifyScript(CScript{}, witness_v0_script_pubkey, &witness_v0, guarded_flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(VerifyScript(CScript{}, CScript{} << OP_TRUE, nullptr, guarded_flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    const CScript malformed_witness_v0_script_pubkey = CScript{} << OP_0 << std::vector<unsigned char>(31, 0x05);
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!VerifyScript(CScript{}, malformed_witness_v0_script_pubkey, &taproot_witness, guarded_flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
}

BOOST_AUTO_TEST_SUITE_END()
