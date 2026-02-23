// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/pqsig/domains.h>
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
    const std::array<std::span<const uint8_t>, 1> parts{sk_seed};
    const auto pk_seed = pqsig::domains::HashN(nullptr, "PQSIG-PK-SEED", parts);

    const std::array<std::span<const uint8_t>, 1> root_parts{std::span<const uint8_t>{pk_seed}};
    const auto pk_root = pqsig::domains::HashN(nullptr, "PQSIG-PK-ROOT", root_parts);

    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    out[0] = pqsig::ALG_ID_V1;
    std::copy(pk_seed.begin(), pk_seed.end(), out.begin() + 1);
    std::copy(pk_root.begin(), pk_root.end(), out.begin() + 1 + pk_seed.size());
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

BOOST_AUTO_TEST_SUITE_END()
