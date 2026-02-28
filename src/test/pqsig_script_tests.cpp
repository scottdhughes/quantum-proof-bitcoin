// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/params.h>
#include <crypto/pqsig/pqsig.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::array<uint8_t, 32> TEST_SK_SEED{
    0x07, 0x11, 0x13, 0x17, 0x19, 0x23, 0x29, 0x31,
    0x07, 0x11, 0x13, 0x17, 0x19, 0x23, 0x29, 0x31,
    0x07, 0x11, 0x13, 0x17, 0x19, 0x23, 0x29, 0x31,
    0x07, 0x11, 0x13, 0x17, 0x19, 0x23, 0x29, 0x31,
};

std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> MakePkScript()
{
    const std::array<std::span<const uint8_t>, 1> parts{std::span<const uint8_t>{TEST_SK_SEED}};
    const auto pk_seed = pqsig::domains::HashN(nullptr, "PQSIG-PK-SEED", parts);
    const std::array<std::span<const uint8_t>, 1> root_parts{std::span<const uint8_t>{pk_seed}};
    const auto pk_root = pqsig::domains::HashN(nullptr, "PQSIG-PK-ROOT", root_parts);

    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    out[0] = pqsig::ALG_ID_V1;
    std::copy(pk_seed.begin(), pk_seed.end(), out.begin() + 1);
    std::copy(pk_root.begin(), pk_root.end(), out.begin() + 1 + pk_seed.size());
    return out;
}

std::vector<uint8_t> SignForScript(const CMutableTransaction& tx, const CScript& script_code, std::span<const uint8_t> pk_script)
{
    const uint256 sighash = SignatureHash(script_code, tx, /*nIn=*/0, SIGHASH_ALL, /*amount=*/0, SigVersion::BASE);
    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    if (!pqsig::PQSigSign(sig, std::span<const uint8_t>{sighash.begin(), sighash.size()}, TEST_SK_SEED, pk_script)) {
        throw std::runtime_error("failed to produce deterministic test signature");
    }
    return sig;
}

void MutateLayerCounter(std::vector<uint8_t>& sig, const size_t layer)
{
    const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
    const size_t count_offset = layer_offset + pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
    sig[count_offset] ^= 0x01;
}

CMutableTransaction BuildSpendingTx()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout[0].nValue = 50 * COIN;
    tx.vout[0].scriptPubKey = CScript{} << OP_TRUE;
    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pqsig_script_tests)

BOOST_AUTO_TEST_CASE(checksig_accepts_valid_pqsig)
{
    const auto pk_script = MakePkScript();
    const CScript script_pubkey = CScript{} << std::vector<unsigned char>{pk_script.begin(), pk_script.end()} << OP_CHECKSIG;

    CMutableTransaction tx = BuildSpendingTx();
    const std::vector<uint8_t> sig = SignForScript(tx, script_pubkey, pk_script);
    tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>{sig.begin(), sig.end()};

    const CTransaction tx_const{tx};
    const TransactionSignatureChecker checker(&tx_const, /*nInIn=*/0, /*amountIn=*/0, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(checksig_rejects_wrong_sig_size_and_alg_id)
{
    const auto pk_script = MakePkScript();
    const CScript good_script_pubkey = CScript{} << std::vector<unsigned char>{pk_script.begin(), pk_script.end()} << OP_CHECKSIG;

    CMutableTransaction tx = BuildSpendingTx();
    const std::vector<uint8_t> good_sig = SignForScript(tx, good_script_pubkey, pk_script);

    const CTransaction tx_const{tx};
    const TransactionSignatureChecker checker(&tx_const, /*nInIn=*/0, /*amountIn=*/0, MissingDataBehavior::FAIL);

    ScriptError err;

    // Wrong signature size is rejected during script encoding checks.
    tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>(pqsig::SIG_SIZE - 1, 0xAA);
    BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, good_script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SIG_DER);

    // Wrong pubkey script length is rejected deterministically.
    std::vector<unsigned char> short_pk{pk_script.begin(), pk_script.end() - 1};
    const CScript short_pk_script_pubkey = CScript{} << short_pk << OP_CHECKSIG;
    tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>{good_sig.begin(), good_sig.end()};
    BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, short_pk_script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);

    // Wrong algorithm identifier in the pubkey script is rejected deterministically.
    auto bad_pk_script = pk_script;
    bad_pk_script[0] = 0x01;
    const CScript bad_script_pubkey = CScript{} << std::vector<unsigned char>{bad_pk_script.begin(), bad_pk_script.end()} << OP_CHECKSIG;
    tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>{good_sig.begin(), good_sig.end()};
    BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, bad_script_pubkey, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUBKEYTYPE);
}

BOOST_AUTO_TEST_CASE(checkmultisig_accepts_valid_and_rejects_wrong_sighash)
{
    const auto pk_script = MakePkScript();
    const CScript multisig_script = CScript{} << OP_1 << std::vector<unsigned char>{pk_script.begin(), pk_script.end()} << OP_1 << OP_CHECKMULTISIG;

    CMutableTransaction tx = BuildSpendingTx();
    const std::vector<uint8_t> sig = SignForScript(tx, multisig_script, pk_script);
    tx.vin[0].scriptSig = CScript{} << OP_0 << std::vector<unsigned char>{sig.begin(), sig.end()};

    const CTransaction tx_const{tx};
    const TransactionSignatureChecker checker(&tx_const, /*nInIn=*/0, /*amountIn=*/0, MissingDataBehavior::FAIL);
    ScriptError err;

    BOOST_CHECK(VerifyScript(tx.vin[0].scriptSig, multisig_script, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Mutating a layer counter triggers strict internal signature rejection.
    std::vector<uint8_t> malformed_sig = sig;
    MutateLayerCounter(malformed_sig, 0);
    tx.vin[0].scriptSig = CScript{} << OP_0 << std::vector<unsigned char>{malformed_sig.begin(), malformed_sig.end()};
    BOOST_CHECK(!VerifyScript(tx.vin[0].scriptSig, multisig_script, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);

    // Restore valid scriptSig before sighash mismatch check.
    tx.vin[0].scriptSig = CScript{} << OP_0 << std::vector<unsigned char>{sig.begin(), sig.end()};

    // Mutate the transaction after signing to force a sighash mismatch.
    CMutableTransaction mutated_tx{tx};
    mutated_tx.vout[0].nValue -= 1;
    const CTransaction mutated_tx_const{mutated_tx};
    const TransactionSignatureChecker mutated_checker(&mutated_tx_const, /*nInIn=*/0, /*amountIn=*/0, MissingDataBehavior::FAIL);

    BOOST_CHECK(!VerifyScript(mutated_tx.vin[0].scriptSig, multisig_script, nullptr, MANDATORY_SCRIPT_VERIFY_FLAGS, mutated_checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_SUITE_END()
