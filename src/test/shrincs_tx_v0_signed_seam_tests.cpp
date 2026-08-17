// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/shrincs_tx_v0.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>

#include <test/shrincs_tx_v0_signed_seam_vectors.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern "C" int pqbtc_shrincs_verify(const std::uint8_t* public_key,
                                     std::size_t public_key_len,
                                     const std::uint8_t* signature,
                                     std::size_t signature_len,
                                     const std::uint8_t* message,
                                     std::size_t message_len,
                                     const std::uint8_t* context,
                                     std::size_t context_len);

BOOST_AUTO_TEST_SUITE(shrincs_tx_v0_signed_seam_tests)

namespace {

namespace vectors = shrincs_tx_v0_signed_seam_vectors;

struct EnvelopeCase {
    CMutableTransaction tx;
    std::vector<CTxOut> spent_outputs;
    std::uint32_t input_index{0};
    uint256 chain_id;
};

struct SignedVectors {
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> context;
    std::vector<unsigned char> stateful_signature;
    std::vector<unsigned char> stateless_signature;
};

uint256 HashText(const std::string_view text)
{
    HashWriter writer;
    writer.write(std::as_bytes(std::span<const char>{text.data(), text.size()}));
    return writer.GetSHA256();
}

std::string RawHex(const uint256& value)
{
    return HexStr(std::span<const unsigned char>{value.begin(), value.size()});
}

std::string Sha256Hex(std::span<const unsigned char> bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest{};
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.data());
    return HexStr(digest);
}

CScript WitnessV0KeyHashScript(const std::string_view label)
{
    const uint256 digest{HashText(label)};
    std::vector<unsigned char> bytes{0x00, 0x14};
    bytes.insert(bytes.end(), digest.begin(), digest.begin() + 20);
    return CScript{bytes.begin(), bytes.end()};
}

CScript OpReturnScript(const std::string_view payload)
{
    const std::vector<unsigned char> bytes{payload.begin(), payload.end()};
    CScript script;
    script << OP_RETURN << bytes;
    return script;
}

EnvelopeCase BuildEnvelopeCase(std::span<const unsigned char> public_key)
{
    const std::optional<CScript> candidate_script{shrincs_tx_v0::BuildScriptPubKey(public_key)};
    if (!candidate_script) throw std::runtime_error{"invalid SHRINCS public key"};

    EnvelopeCase result;
    result.chain_id = HashText("PQBTC-SHRINCS-TX-V0-TEST-CHAIN");
    result.tx.version = 2;
    result.tx.nLockTime = 840'000;
    result.tx.vin.emplace_back(
        COutPoint{Txid::FromUint256(HashText("prevout-0")), 3},
        CScript{},
        0xfffffffdU);
    result.tx.vin.emplace_back(
        COutPoint{Txid::FromUint256(HashText("prevout-1")), 1},
        CScript{},
        0xfffffffeU);
    result.tx.vout.emplace_back(150'000, *candidate_script);
    result.tx.vout.emplace_back(49'000, OpReturnScript("PQV0"));

    result.spent_outputs.emplace_back(125'000, *candidate_script);
    result.spent_outputs.emplace_back(75'000, WitnessV0KeyHashScript("witness-input"));
    return result;
}

uint256 RequireDigest(const EnvelopeCase& test_case)
{
    const CTransaction tx{test_case.tx};
    const std::optional<uint256> digest{shrincs_tx_v0::SignatureHash(
        tx,
        std::span<const CTxOut>{test_case.spent_outputs.data(), test_case.spent_outputs.size()},
        test_case.input_index,
        test_case.chain_id)};
    if (!digest) throw std::runtime_error{"SHRINCS transaction digest rejected"};
    return *digest;
}

std::string SerializeStripped(const CMutableTransaction& mutable_tx)
{
    const CTransaction tx{mutable_tx};
    DataStream stream;
    stream << TX_NO_WITNESS(tx);
    const std::string bytes{stream.str()};
    return HexStr(std::span<const char>{bytes.data(), bytes.size()});
}

void FlipTxidByte(Txid& txid, const std::size_t offset)
{
    uint256 raw{txid.ToUint256()};
    if (offset >= raw.size()) throw std::runtime_error{"txid mutation offset out of range"};
    raw.begin()[offset] ^= 1;
    txid = Txid::FromUint256(raw);
}

std::map<std::string, EnvelopeCase> TransactionMutationCases(const EnvelopeCase& base)
{
    std::map<std::string, EnvelopeCase> mutations;
    auto add = [&](std::string name, auto&& mutate) {
        EnvelopeCase test_case{base};
        mutate(test_case);
        mutations.emplace(std::move(name), std::move(test_case));
    };

    add("version", [](EnvelopeCase& item) { ++item.tx.version; });
    add("lock_time", [](EnvelopeCase& item) { ++item.tx.nLockTime; });
    add("input0_prevout_txid", [](EnvelopeCase& item) { FlipTxidByte(item.tx.vin[0].prevout.hash, 0); });
    add("input0_prevout_index", [](EnvelopeCase& item) { ++item.tx.vin[0].prevout.n; });
    add("input0_amount", [](EnvelopeCase& item) { ++item.spent_outputs[0].nValue; });
    add("input0_script", [](EnvelopeCase& item) { item.spent_outputs[0].scriptPubKey.push_back(0); });
    add("input0_sequence", [](EnvelopeCase& item) { --item.tx.vin[0].nSequence; });
    add("input1_prevout_txid", [](EnvelopeCase& item) { FlipTxidByte(item.tx.vin[1].prevout.hash, 31); });
    add("input1_prevout_index", [](EnvelopeCase& item) { ++item.tx.vin[1].prevout.n; });
    add("input1_amount", [](EnvelopeCase& item) { ++item.spent_outputs[1].nValue; });
    add("input1_script", [](EnvelopeCase& item) { item.spent_outputs[1].scriptPubKey.push_back(0); });
    add("input1_sequence", [](EnvelopeCase& item) { --item.tx.vin[1].nSequence; });
    add("input_order", [](EnvelopeCase& item) {
        std::swap(item.tx.vin[0], item.tx.vin[1]);
        std::swap(item.spent_outputs[0], item.spent_outputs[1]);
    });
    add("input_removed", [](EnvelopeCase& item) {
        item.tx.vin.resize(1);
        item.spent_outputs.resize(1);
    });
    add("input_added", [](EnvelopeCase& item) {
        item.tx.vin.emplace_back(
            COutPoint{Txid::FromUint256(HashText("prevout-2")), 7},
            CScript{},
            0xfffffffcU);
        item.spent_outputs.emplace_back(50'000, WitnessV0KeyHashScript("third-input"));
    });
    add("output0_amount", [](EnvelopeCase& item) { ++item.tx.vout[0].nValue; });
    add("output0_script", [](EnvelopeCase& item) { item.tx.vout[0].scriptPubKey.push_back(0); });
    add("output1_amount", [](EnvelopeCase& item) { ++item.tx.vout[1].nValue; });
    add("output1_script", [](EnvelopeCase& item) { item.tx.vout[1].scriptPubKey.push_back(0); });
    add("output_order", [](EnvelopeCase& item) { std::swap(item.tx.vout[0], item.tx.vout[1]); });
    add("output_removed", [](EnvelopeCase& item) { item.tx.vout.resize(1); });
    add("output_added", [](EnvelopeCase& item) {
        item.tx.vout.emplace_back(1'000, OpReturnScript("EXTRA"));
    });
    return mutations;
}

SignedVectors LoadSignedVectors()
{
    SignedVectors result;
    result.public_key = ParseHex(vectors::PUBLIC_KEY_HEX);
    result.context = ParseHex(vectors::CONTEXT_HEX);
    result.stateful_signature = ParseHex(vectors::STATEFUL_SIGNATURE_HEX);
    result.stateless_signature = ParseHex(vectors::STATELESS_SIGNATURE_HEX);
    if (result.public_key.size() != shrincs_tx_v0::PUBLIC_KEY_BYTES ||
        result.context.size() != shrincs_tx_v0::SIGNING_CONTEXT.size() ||
        result.stateful_signature.size() != shrincs_tx_v0::STATEFUL_SIGNATURE_MIN ||
        result.stateless_signature.size() != shrincs_tx_v0::STATELESS_SIGNATURE_BYTES) {
        throw std::runtime_error{"SHRINCS signed-seam vector length drifted"};
    }
    return result;
}

bool Verify(const std::vector<unsigned char>& public_key,
            const std::vector<unsigned char>& signature,
            const uint256& message,
            const std::vector<unsigned char>& context)
{
    return pqbtc_shrincs_verify(
               public_key.data(),
               public_key.size(),
               signature.data(),
               signature.size(),
               message.begin(),
               message.size(),
               context.data(),
               context.size()) == 1;
}

} // namespace

BOOST_AUTO_TEST_CASE(authenticated_vectors_verify_against_native_transaction_digest)
{
    const SignedVectors signed_vectors{LoadSignedVectors()};
    const EnvelopeCase test_case{BuildEnvelopeCase(signed_vectors.public_key)};
    const uint256 digest{RequireDigest(test_case)};

    BOOST_CHECK_EQUAL(RawHex(test_case.chain_id), vectors::CHAIN_ID_HEX);
    BOOST_CHECK_EQUAL(RawHex(digest), vectors::TRANSACTION_DIGEST_HEX);
    BOOST_CHECK_EQUAL(SerializeStripped(test_case.tx), vectors::STRIPPED_TRANSACTION_HEX);
    BOOST_CHECK_EQUAL(
        (std::string{signed_vectors.context.begin(), signed_vectors.context.end()}),
        std::string{shrincs_tx_v0::SIGNING_CONTEXT});
    BOOST_CHECK_EQUAL(Sha256Hex(signed_vectors.public_key), vectors::PUBLIC_KEY_SHA256_HEX);
    BOOST_CHECK_EQUAL(Sha256Hex(signed_vectors.stateful_signature), vectors::STATEFUL_SIGNATURE_SHA256_HEX);
    BOOST_CHECK_EQUAL(Sha256Hex(signed_vectors.stateless_signature), vectors::STATELESS_SIGNATURE_SHA256_HEX);

    const std::optional<uint256> program{shrincs_tx_v0::OutputCommitment(signed_vectors.public_key)};
    BOOST_REQUIRE(program.has_value());
    BOOST_CHECK_EQUAL(RawHex(*program), vectors::OUTPUT_COMMITMENT_HEX);

    const std::array<const std::vector<unsigned char>*, 2> signatures{
        &signed_vectors.stateful_signature,
        &signed_vectors.stateless_signature,
    };
    const std::array<shrincs_tx_v0::SignatureMode, 2> modes{
        shrincs_tx_v0::SignatureMode::STATEFUL,
        shrincs_tx_v0::SignatureMode::STATELESS,
    };
    for (std::size_t index = 0; index < signatures.size(); ++index) {
        CScriptWitness witness;
        witness.stack = {*signatures[index], signed_vectors.public_key};
        const auto parsed{shrincs_tx_v0::ParseWitness(
            witness,
            std::span<const unsigned char>{program->begin(), program->size()})};
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(parsed->mode == modes[index]);
        BOOST_CHECK(Verify(signed_vectors.public_key, *signatures[index], digest, signed_vectors.context));
    }
}

BOOST_AUTO_TEST_CASE(all_python_signed_seam_negatives_reject_natively)
{
    const SignedVectors signed_vectors{LoadSignedVectors()};
    const EnvelopeCase base{BuildEnvelopeCase(signed_vectors.public_key)};
    const uint256 digest{RequireDigest(base)};
    const std::array<const std::vector<unsigned char>*, 2> signatures{
        &signed_vectors.stateful_signature,
        &signed_vectors.stateless_signature,
    };
    std::size_t rejected{0};

    auto reject_both = [&](const uint256& candidate_digest,
                           const std::vector<unsigned char>& candidate_context) {
        for (const auto* signature : signatures) {
            BOOST_CHECK(!Verify(
                signed_vectors.public_key,
                *signature,
                candidate_digest,
                candidate_context));
            ++rejected;
        }
    };

    const std::map<std::string, EnvelopeCase> mutations{TransactionMutationCases(base)};
    BOOST_REQUIRE_EQUAL(mutations.size(), 22U);
    for (const auto& [name, mutation] : mutations) {
        const uint256 mutated_digest{RequireDigest(mutation)};
        BOOST_REQUIRE_MESSAGE(mutated_digest != digest, name << " did not change the digest");
        reject_both(mutated_digest, signed_vectors.context);
    }

    EnvelopeCase alternate_input{base};
    alternate_input.input_index = 1;
    const uint256 alternate_input_digest{RequireDigest(alternate_input)};
    BOOST_REQUIRE(alternate_input_digest != digest);
    reject_both(alternate_input_digest, signed_vectors.context);

    EnvelopeCase changed_chain{base};
    changed_chain.chain_id.begin()[0] ^= 1;
    const uint256 changed_chain_digest{RequireDigest(changed_chain)};
    BOOST_REQUIRE(changed_chain_digest != digest);
    reject_both(changed_chain_digest, signed_vectors.context);

    std::vector<unsigned char> changed_context{signed_vectors.context};
    changed_context.push_back(static_cast<unsigned char>('x'));
    reject_both(digest, changed_context);

    for (const auto* signature : signatures) {
        std::vector<unsigned char> mutated_signature{*signature};
        mutated_signature[mutated_signature.size() / 2] ^= 1;
        BOOST_CHECK(!Verify(
            signed_vectors.public_key,
            mutated_signature,
            digest,
            signed_vectors.context));
        ++rejected;
    }

    const std::optional<uint256> program{shrincs_tx_v0::OutputCommitment(signed_vectors.public_key)};
    BOOST_REQUIRE(program.has_value());
    std::vector<unsigned char> mutated_key{signed_vectors.public_key};
    mutated_key[0] ^= 1;
    const std::optional<uint256> mutated_program{shrincs_tx_v0::OutputCommitment(mutated_key)};
    BOOST_REQUIRE(mutated_program.has_value());

    for (const auto* signature : signatures) {
        CScriptWitness witness;
        witness.stack = {*signature, mutated_key};
        BOOST_CHECK(!shrincs_tx_v0::ParseWitness(
            witness,
            std::span<const unsigned char>{program->begin(), program->size()}));
        ++rejected;

        const auto parsed{shrincs_tx_v0::ParseWitness(
            witness,
            std::span<const unsigned char>{mutated_program->begin(), mutated_program->size()})};
        BOOST_REQUIRE(parsed.has_value());
        BOOST_CHECK(!Verify(mutated_key, *signature, digest, signed_vectors.context));
        ++rejected;
    }

    BOOST_CHECK_EQUAL(rejected, 56U);
}

BOOST_AUTO_TEST_CASE(regtest_witness_v2_executes_full_verifier)
{
    const SignedVectors signed_vectors{LoadSignedVectors()};
    const EnvelopeCase envelope{BuildEnvelopeCase(signed_vectors.public_key)};

    auto run = [&](const std::vector<unsigned char>& signature,
                   const std::vector<unsigned char>& public_key,
                   unsigned int flags,
                   ScriptError* error) {
        CMutableTransaction mutable_tx{envelope.tx};
        mutable_tx.vin[0].scriptWitness.stack = {signature, public_key};
        const CTransaction tx{mutable_tx};

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{envelope.spent_outputs}, /*force=*/true);
        TransactionSignatureChecker checker{
            &tx,
            /*nInIn=*/0,
            envelope.spent_outputs[0].nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL};

        return VerifyScript(
            tx.vin[0].scriptSig,
            envelope.spent_outputs[0].scriptPubKey,
            &tx.vin[0].scriptWitness,
            flags,
            checker,
            error);
    };

    constexpr unsigned int active_flags{
        SCRIPT_VERIFY_P2SH |
        SCRIPT_VERIFY_WITNESS |
        SCRIPT_VERIFY_SHRINCS_V0};

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(run(
        signed_vectors.stateful_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(run(
        signed_vectors.stateless_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    std::vector<unsigned char> mutated_signature{signed_vectors.stateful_signature};
    mutated_signature[mutated_signature.size() / 2] ^= 1;
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!run(
        mutated_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_EVAL_FALSE);

    std::vector<unsigned char> wrong_key{signed_vectors.public_key};
    wrong_key[0] ^= 1;
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!run(
        signed_vectors.stateful_signature,
        wrong_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    // Without the regtest activation flag, witness v2 retains ordinary
    // future-version behavior. This prevents accidental inherited-network
    // activation by the verifier merely being present in the binary.
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(run(
        signed_vectors.stateful_signature,
        signed_vectors.public_key,
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
