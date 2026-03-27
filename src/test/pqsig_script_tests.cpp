// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <crypto/pqsig/params.h>
#include <crypto/pqsig/pqsig.h>
#include <psbt.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
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
    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    if (!pqsig::DerivePkScript(out, TEST_SK_SEED)) {
        throw std::runtime_error("failed to derive deterministic test pk script");
    }
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

CScript MakeWitnessScript(const std::array<uint8_t, pqsig::PK_SCRIPT_SIZE>& pk_script)
{
    return CScript{} << std::vector<unsigned char>{pk_script.begin(), pk_script.end()} << OP_CHECKSIG;
}

FlatSigningProvider MakePQSigningProvider(const std::array<uint8_t, pqsig::PK_SCRIPT_SIZE>& pk_script)
{
    FlatSigningProvider provider;
    const CScript witness_script = MakeWitnessScript(pk_script);
    provider.scripts.emplace(CScriptID(witness_script), witness_script);
    provider.pq_keys.emplace(pk_script, TEST_SK_SEED);
    return provider;
}

} // namespace

BOOST_AUTO_TEST_SUITE(pqsig_script_tests)

BOOST_AUTO_TEST_CASE(alg_id_registry_is_frozen_for_current_release)
{
    const auto reserved = pqsig::GetALGIDInfo(0x00);
    BOOST_CHECK_EQUAL(reserved.alg_id, 0x00);
    BOOST_CHECK(reserved.state == pqsig::ALGIDState::RESERVED_INVALID);
    BOOST_CHECK(!pqsig::IsValidALGID(0x00));
    BOOST_CHECK_EQUAL(reserved.sig_size, 0U);
    BOOST_CHECK_EQUAL(reserved.pk_script_size, 0U);

    const auto active = pqsig::GetALGIDInfo(pqsig::ALG_ID_RC2);
    BOOST_CHECK_EQUAL(active.alg_id, pqsig::ALG_ID_RC2);
    BOOST_CHECK(active.state == pqsig::ALGIDState::ACTIVE);
    BOOST_CHECK(pqsig::IsValidALGID(pqsig::ALG_ID_RC2));
    BOOST_CHECK_EQUAL(active.sig_size, pqsig::SIG_SIZE);
    BOOST_CHECK_EQUAL(active.pk_script_size, pqsig::PK_SCRIPT_SIZE);

    const auto unallocated = pqsig::GetALGIDInfo(0x02);
    BOOST_CHECK_EQUAL(unallocated.alg_id, 0x02);
    BOOST_CHECK(unallocated.state == pqsig::ALGIDState::UNALLOCATED);
    BOOST_CHECK(!pqsig::IsValidALGID(0x02));
    BOOST_CHECK_EQUAL(unallocated.sig_size, 0U);
    BOOST_CHECK_EQUAL(unallocated.pk_script_size, 0U);
}

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
    bad_pk_script[0] = 0x00;
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

BOOST_AUTO_TEST_CASE(produce_signature_builds_valid_p2wsh_pq_witness)
{
    const auto pk_script = MakePkScript();
    const CScript witness_script = MakeWitnessScript(pk_script);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    const CAmount amount = 50 * COIN;

    CMutableTransaction tx = BuildSpendingTx();
    SignatureData sigdata;
    const auto provider = MakePQSigningProvider(pk_script);

    BOOST_REQUIRE(ProduceSignature(provider, MutableTransactionSignatureCreator(tx, 0, amount, SIGHASH_ALL), script_pubkey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 2U);
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[0].size(), pqsig::SIG_SIZE);
    BOOST_CHECK(sigdata.scriptWitness.stack[1] == std::vector<unsigned char>(witness_script.begin(), witness_script.end()));

    tx.vin[0].scriptWitness = sigdata.scriptWitness;
    const CTransaction tx_const{tx};
    const TransactionSignatureChecker checker(&tx_const, /*nInIn=*/0, amount, MissingDataBehavior::FAIL);

    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript{}, script_pubkey, &tx.vin[0].scriptWitness, MANDATORY_SCRIPT_VERIFY_FLAGS, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(dummy_and_non_all_pq_signing_paths)
{
    const auto pk_script = MakePkScript();
    const CScript witness_script = MakeWitnessScript(pk_script);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    const CAmount amount = 50 * COIN;
    const auto provider = MakePQSigningProvider(pk_script);

    SignatureData dummy_sigdata;
    BOOST_REQUIRE(ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, script_pubkey, dummy_sigdata));
    BOOST_REQUIRE_EQUAL(dummy_sigdata.scriptWitness.stack.size(), 2U);
    BOOST_CHECK_EQUAL(dummy_sigdata.scriptWitness.stack[0].size(), pqsig::SIG_SIZE);
    BOOST_CHECK(dummy_sigdata.scriptWitness.stack[1] == std::vector<unsigned char>(witness_script.begin(), witness_script.end()));

    SignatureData rejected_sigdata;
    CMutableTransaction tx = BuildSpendingTx();
    BOOST_CHECK(!ProduceSignature(provider, MutableTransactionSignatureCreator(tx, 0, amount, SIGHASH_NONE), script_pubkey, rejected_sigdata));
}

BOOST_AUTO_TEST_CASE(psbt_roundtrips_pq_proprietary_partial_sig_and_finalizes)
{
    const auto pk_script = MakePkScript();
    const CScript witness_script = MakeWitnessScript(pk_script);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    const CAmount amount = 50 * COIN;

    CMutableTransaction tx = BuildSpendingTx();
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = CTxOut(amount, script_pubkey);

    const auto provider = MakePQSigningProvider(pk_script);
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    BOOST_CHECK(static_cast<int>(SignPSBTInput(provider, psbt, 0, &txdata, std::nullopt, nullptr, /*finalize=*/false)) == static_cast<int>(PSBTError::OK));
    BOOST_CHECK(psbt.inputs[0].final_script_witness.IsNull());
    BOOST_REQUIRE_EQUAL(psbt.inputs[0].m_proprietary.size(), 1U);

    DataStream ss{};
    ss << psbt;
    PartiallySignedTransaction roundtrip;
    ss >> roundtrip;

    BOOST_REQUIRE_EQUAL(roundtrip.inputs[0].m_proprietary.size(), 1U);
    const auto& prop = *roundtrip.inputs[0].m_proprietary.begin();
    BOOST_CHECK(prop.identifier == std::vector<unsigned char>({'p', 'q', 'b', 't', 'c'}));
    BOOST_CHECK_EQUAL(prop.subtype, 1U);
    BOOST_CHECK_EQUAL(prop.value.size(), pqsig::SIG_SIZE);

    BOOST_CHECK(FinalizePSBT(roundtrip));
    BOOST_REQUIRE_EQUAL(roundtrip.inputs[0].final_script_witness.stack.size(), 2U);
    BOOST_CHECK_EQUAL(roundtrip.inputs[0].final_script_witness.stack[0].size(), pqsig::SIG_SIZE);
    BOOST_CHECK(roundtrip.inputs[0].final_script_witness.stack[1] == std::vector<unsigned char>(witness_script.begin(), witness_script.end()));
}

BOOST_AUTO_TEST_SUITE_END()
