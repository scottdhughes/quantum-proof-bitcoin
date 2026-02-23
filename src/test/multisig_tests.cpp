// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> DerivePkScript(const std::array<uint8_t, 32>& sk_seed)
{
    const std::array<std::span<const uint8_t>, 1> parts{std::span<const uint8_t>{sk_seed}};
    const auto pk_seed = pqsig::domains::HashN(nullptr, "PQSIG-PK-SEED", parts);

    const std::array<std::span<const uint8_t>, 1> root_parts{std::span<const uint8_t>{pk_seed}};
    const auto pk_root = pqsig::domains::HashN(nullptr, "PQSIG-PK-ROOT", root_parts);

    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    out[0] = pqsig::ALG_ID_V1;
    std::copy(pk_seed.begin(), pk_seed.end(), out.begin() + 1);
    std::copy(pk_root.begin(), pk_root.end(), out.begin() + 1 + pk_seed.size());
    return out;
}

std::vector<uint8_t> Sign(
    const std::span<const uint8_t> sk_seed,
    const CMutableTransaction& tx,
    const CScript& script_code,
    const std::span<const uint8_t> pk_script)
{
    const uint256 sighash = SignatureHash(script_code, tx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    if (!pqsig::PQSigSign(sig, std::span<const uint8_t>{sighash.begin(), sighash.size()}, sk_seed, pk_script)) {
        throw std::runtime_error("failed to sign multisig input");
    }
    return sig;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(multisig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(multisig_verify_pq_only)
{
    const std::array<uint8_t, 32> sk1{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                                      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                                      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                                      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    const std::array<uint8_t, 32> sk2{0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
                                      0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
                                      0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
                                      0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52};

    const auto pk1 = DerivePkScript(sk1);
    const auto pk2 = DerivePkScript(sk2);

    const CScript multisig_script = CScript{}
        << OP_2
        << std::vector<unsigned char>{pk1.begin(), pk1.end()}
        << std::vector<unsigned char>{pk2.begin(), pk2.end()}
        << OP_2
        << OP_CHECKMULTISIG;

    const CTransaction tx_credit{BuildCreditingTransaction(multisig_script, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript{}, CScriptWitness{}, tx_credit);

    const std::vector<uint8_t> sig1 = Sign(sk1, tx_spend, multisig_script, pk1);
    const std::vector<uint8_t> sig2 = Sign(sk2, tx_spend, multisig_script, pk2);

    tx_spend.vin[0].scriptSig = CScript{}
        << OP_0
        << std::vector<unsigned char>{sig1.begin(), sig1.end()}
        << std::vector<unsigned char>{sig2.begin(), sig2.end()};

    ScriptError err;
    const CTransaction tx_spend_const{tx_spend};
    const TransactionSignatureChecker checker(&tx_spend_const, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(VerifyScript(tx_spend.vin[0].scriptSig, multisig_script, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    CMutableTransaction bad_sig_tx = tx_spend;
    std::vector<uint8_t> bad_sig = sig2;
    bad_sig[12] ^= 0x80;
    bad_sig_tx.vin[0].scriptSig = CScript{}
        << OP_0
        << std::vector<unsigned char>{sig1.begin(), sig1.end()}
        << std::vector<unsigned char>{bad_sig.begin(), bad_sig.end()};

    const CTransaction bad_sig_tx_const{bad_sig_tx};
    const TransactionSignatureChecker bad_checker(&bad_sig_tx_const, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(bad_sig_tx.vin[0].scriptSig, multisig_script, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, bad_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_SUITE_END()
