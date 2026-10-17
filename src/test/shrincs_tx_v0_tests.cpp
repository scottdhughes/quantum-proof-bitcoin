// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/shrincs_tx_v0.h>

#include <consensus/amount.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(shrincs_tx_v0_tests)

namespace {

struct EnvelopeCase {
    CMutableTransaction tx;
    std::vector<CTxOut> spent_outputs;
    std::uint32_t input_index{0};
    uint256 chain_id;
};

uint256 HashText(const std::string_view text)
{
    HashWriter writer;
    writer.write(std::as_bytes(std::span<const char>{text.data(), text.size()}));
    return writer.GetSHA256();
}

uint256 RawUint256(const std::string_view hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    if (bytes.size() != uint256::size()) throw std::runtime_error{"expected 32 raw bytes"};
    return uint256{std::span<const unsigned char>{bytes.data(), bytes.size()}};
}

std::string RawHex(const uint256& value)
{
    return HexStr(std::span<const unsigned char>{value.begin(), value.size()});
}

CScript ScriptFromHex(const std::string_view hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    return CScript{bytes.begin(), bytes.end()};
}

std::vector<unsigned char> SequentialPublicKey()
{
    std::vector<unsigned char> public_key(shrincs_tx_v0::PUBLIC_KEY_BYTES);
    for (std::size_t index = 0; index < public_key.size(); ++index) {
        public_key[index] = static_cast<unsigned char>(index);
    }
    return public_key;
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
    result.chain_id = shrincs_tx_v0::ShrincsLabChainId();
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

const std::map<std::string, std::string>& ExpectedMutationDigests()
{
    static const std::map<std::string, std::string> expected{
        {"version", "ab688118a5ec57448784f50217c6e5934d5b899e8d7e1bfc33022a0501cba706"},
        {"lock_time", "3aa20139d00899b3cec6e063daa8daeac7870a3fb70ef0e95445fa3101be40cb"},
        {"input0_prevout_txid", "9ab690225bba3d82bc1da407dc31cf9aceaa7b9a907980da01c80b939dcb10a0"},
        {"input0_prevout_index", "875b2439d610da27773b3db83a45d0f3b583290b3edbfaf81e9ae81f439521f0"},
        {"input0_amount", "26113870a7c6ad56755ef6b152cc5dac192143b9e75498e915fc9c030080f1da"},
        {"input0_script", "517a8ef7914683cd9b6e64a342d244f64fe97398d7b668b19a1e4b5b9ffef5d7"},
        {"input0_sequence", "c68c8708d58839458b3d0291c3657f65075bd21ba12c3169881d389f05e28cca"},
        {"input1_prevout_txid", "5822a1133356047a3c85ba6c6c41909241a881b20e8644948e069376c4b01c8e"},
        {"input1_prevout_index", "f521455dfbca3c78779dceef19eb42b2e5baf5fdb85ebc2a1d03d49a3c55ba34"},
        {"input1_amount", "73e1d1edf417de7a90e9437516a563c6cf069cfcb7622786ecc9390533fcaad0"},
        {"input1_script", "92166a8898eb7e1fe92c45deeaed3a3450727fa021454530dd30c55eaf360a17"},
        {"input1_sequence", "1aae3a0e04337e332c27caf032aee5e28a36846120884cc3038260f877080553"},
        {"input_order", "0d86e7ba927a09fc5a26e7ba0693a88d82d4f7430de87651f1ba5864a6599220"},
        {"input_removed", "878c309fee385c11751a3aa30f5d39513a47e72321f0921aee55f87bfa164566"},
        {"input_added", "05896a91c2bed4067fced0005296333ec06e354e5c1d84bda215acd4e6a800b5"},
        {"output0_amount", "6c8c81132b477915ba240c4e0c0aa3709ca9134366e7ba47f41c76827ae384b0"},
        {"output0_script", "cfa4d4b073c1aa860e928a82d5751a83d3a7b26df40b006fa348fa8d44c9e398"},
        {"output1_amount", "7b6c816cdeefe4f263ff7e125d77d50e97dee718d354ebf15e41130d80bf79d1"},
        {"output1_script", "4177012835fc69ecd8a6bb278537c7093f0f288fa45e090e9049af9845d64c90"},
        {"output_order", "31a40e7c12a3a45d4f81ffa41fa896b49cfd72c4c7cf8d1bc3a89d889a439c09"},
        {"output_removed", "8cccd781bfcf9037d91a20e9621201312c3c5d253520b4d0d8cc7088c03d36bf"},
        {"output_added", "04f9078c2a8dc1e580a33cb315251dd1cab45da00940e392c4b4cf3e4e71339b"},
    };
    return expected;
}

} // namespace

BOOST_AUTO_TEST_CASE(cpp_matches_python_design_and_signed_seam_vectors)
{
    const std::vector<unsigned char> public_key{SequentialPublicKey()};
    const EnvelopeCase test_case{BuildEnvelopeCase(public_key)};

    BOOST_CHECK(test_case.chain_id == RawUint256("db0e425cda8dcebc9e64203d2a5dfde2e954954f3dc95b8b9807590103d07652"));
    BOOST_CHECK_EQUAL(
        SerializeStripped(test_case.tx),
        "0200000002537b9332eb572ede46a4cf44321cf733a0c76ab6a9cf2d19cd7f3e1ea451c54b0300000000fdffffff21f5e2d90566de1e49bb495dc18bd495be7ee3ba896855982799c940dafcd0070100000000feffffff02f049020000000000225220e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb9768bf000000000000066a045051563040d10c00");

    const std::optional<uint256> commitment{shrincs_tx_v0::OutputCommitment(public_key)};
    BOOST_REQUIRE(commitment.has_value());
    BOOST_CHECK_EQUAL(RawHex(*commitment), "e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb97");

    BOOST_CHECK_EQUAL(RawHex(RequireDigest(test_case)), "87edbe9bb060421d9db6c2946672e384e8914cc11f2971249e3ede1c639361f1");
    EnvelopeCase second_input{test_case};
    second_input.input_index = 1;
    BOOST_CHECK_EQUAL(RawHex(RequireDigest(second_input)), "35a53e8064324de5ba7ca312a01769a1f76a21216df0ef97a78fdb9fb0190cb0");

    const std::vector<unsigned char> signed_public_key{ParseHex(
        "abd9967c038df9b774b48e0360d7cad25ad8c4073c7d3973d4ce8b8cdcc3f12bf784a8a40fb8c98d39ee302e705ae7da")};
    const EnvelopeCase signed_case{BuildEnvelopeCase(signed_public_key)};
    const std::optional<uint256> signed_commitment{shrincs_tx_v0::OutputCommitment(signed_public_key)};
    BOOST_REQUIRE(signed_commitment.has_value());
    BOOST_CHECK_EQUAL(RawHex(*signed_commitment), "d23ac81a74411a8645d375abd22acf8d10e3e18b96b173ec99d8fb1496759665");
    BOOST_CHECK_EQUAL(RawHex(RequireDigest(signed_case)), "df6af2fda86516112cba860db86b7d793232796e837c85604db00827c8df17b5");
    BOOST_CHECK_EQUAL(
        SerializeStripped(signed_case.tx),
        "0200000002537b9332eb572ede46a4cf44321cf733a0c76ab6a9cf2d19cd7f3e1ea451c54b0300000000fdffffff21f5e2d90566de1e49bb495dc18bd495be7ee3ba896855982799c940dafcd0070100000000feffffff02f049020000000000225220d23ac81a74411a8645d375abd22acf8d10e3e18b96b173ec99d8fb149675966568bf000000000000066a045051563040d10c00");
}

BOOST_AUTO_TEST_CASE(candidate_script_and_witness_parser_are_strict)
{
    const std::vector<unsigned char> public_key{SequentialPublicKey()};
    const std::optional<CScript> script{shrincs_tx_v0::BuildScriptPubKey(public_key)};
    BOOST_REQUIRE(script.has_value());
    BOOST_CHECK(*script == ScriptFromHex(
        "5220e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb97"));

    std::array<unsigned char, shrincs_tx_v0::PROGRAM_BYTES> program{};
    BOOST_CHECK(shrincs_tx_v0::IsScriptPubKey(*script, &program));
    BOOST_CHECK_EQUAL(HexStr(program), "e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb97");
    BOOST_CHECK(!shrincs_tx_v0::IsScriptPubKey(CScript{}));
    BOOST_CHECK(!shrincs_tx_v0::BuildScriptPubKey(std::span<const unsigned char>{public_key.data(), public_key.size() - 1}));

    CScriptWitness witness;
    witness.stack = {std::vector<unsigned char>(554), public_key};
    std::optional<shrincs_tx_v0::ParsedWitness> parsed{shrincs_tx_v0::ParseWitness(witness, program)};
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->mode == shrincs_tx_v0::SignatureMode::STATEFUL);
    BOOST_CHECK_EQUAL(parsed->signature.size(), 554U);
    BOOST_CHECK_EQUAL(parsed->public_key.size(), 48U);

    witness.stack[0].resize(5776);
    parsed = shrincs_tx_v0::ParseWitness(witness, program);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->mode == shrincs_tx_v0::SignatureMode::STATELESS);

    for (const std::size_t invalid_size : {0U, 64U, 553U, 555U, 4619U, 4480U, 5775U, 5777U}) {
        witness.stack[0].resize(invalid_size);
        BOOST_CHECK(!shrincs_tx_v0::ParseWitness(witness, program));
    }

    witness.stack = {std::vector<unsigned char>(554)};
    BOOST_CHECK(!shrincs_tx_v0::ParseWitness(witness, program));
    witness.stack = {std::vector<unsigned char>(554), public_key, {0}};
    BOOST_CHECK(!shrincs_tx_v0::ParseWitness(witness, program));

    witness.stack = {std::vector<unsigned char>(554), public_key};
    witness.stack[1][0] ^= 1;
    BOOST_CHECK(!shrincs_tx_v0::ParseWitness(witness, program));
    BOOST_CHECK(!shrincs_tx_v0::ParseWitness(
        witness,
        std::span<const unsigned char>{program.data(), program.size() - 1}));
}

BOOST_AUTO_TEST_CASE(cpp_digest_matches_all_python_mutation_vectors)
{
    const EnvelopeCase base{BuildEnvelopeCase(SequentialPublicKey())};
    const std::map<std::string, EnvelopeCase> mutations{TransactionMutationCases(base)};
    const auto& expected{ExpectedMutationDigests()};
    BOOST_REQUIRE_EQUAL(mutations.size(), 22U);
    BOOST_REQUIRE_EQUAL(mutations.size(), expected.size());

    for (const auto& [name, test_case] : mutations) {
        const auto expected_it{expected.find(name)};
        BOOST_REQUIRE(expected_it != expected.end());
        BOOST_CHECK_EQUAL(RawHex(RequireDigest(test_case)), expected_it->second);
    }

    EnvelopeCase changed_chain{base};
    changed_chain.chain_id.begin()[0] ^= 1;
    BOOST_CHECK(RequireDigest(changed_chain) != RequireDigest(base));
}

BOOST_AUTO_TEST_CASE(invalid_transaction_inputs_fail_closed)
{
    const EnvelopeCase base{BuildEnvelopeCase(SequentialPublicKey())};
    auto digest = [](const EnvelopeCase& test_case) {
        const CTransaction tx{test_case.tx};
        return shrincs_tx_v0::SignatureHash(
            tx,
            std::span<const CTxOut>{test_case.spent_outputs.data(), test_case.spent_outputs.size()},
            test_case.input_index,
            test_case.chain_id);
    };

    EnvelopeCase mismatch{base};
    mismatch.spent_outputs.pop_back();
    BOOST_CHECK(!digest(mismatch));

    EnvelopeCase bad_index{base};
    bad_index.input_index = 2;
    BOOST_CHECK(!digest(bad_index));

    EnvelopeCase script_sig{base};
    script_sig.tx.vin[0].scriptSig << OP_1;
    BOOST_CHECK(!digest(script_sig));

    EnvelopeCase negative_spent{base};
    negative_spent.spent_outputs[0].nValue = -1;
    BOOST_CHECK(!digest(negative_spent));

    EnvelopeCase excessive_spent{base};
    excessive_spent.spent_outputs[0].nValue = MAX_MONEY + 1;
    BOOST_CHECK(!digest(excessive_spent));

    EnvelopeCase negative_output{base};
    negative_output.tx.vout[0].nValue = -1;
    BOOST_CHECK(!digest(negative_output));

    EnvelopeCase oversized_spent_script{base};
    oversized_spent_script.spent_outputs[0].scriptPubKey.resize(MAX_SCRIPT_SIZE + 1);
    BOOST_CHECK(!digest(oversized_spent_script));

    EnvelopeCase oversized_output_script{base};
    oversized_output_script.tx.vout[0].scriptPubKey.resize(MAX_SCRIPT_SIZE + 1);
    BOOST_CHECK(!digest(oversized_output_script));

    EnvelopeCase no_inputs{base};
    no_inputs.tx.vin.clear();
    no_inputs.spent_outputs.clear();
    BOOST_CHECK(!digest(no_inputs));

    EnvelopeCase no_outputs{base};
    no_outputs.tx.vout.clear();
    BOOST_CHECK(!digest(no_outputs));
}

BOOST_AUTO_TEST_CASE(wolfram_checked_resource_invariants_hold_exactly)
{
    BOOST_CHECK_EQUAL(shrincs_tx_v0::STATEFUL_SIGNATURE_MIN % 16U, 10U);
    BOOST_CHECK_EQUAL(shrincs_tx_v0::STATEFUL_SIGNATURE_MAX % 16U, 10U);
    BOOST_CHECK_EQUAL(shrincs_tx_v0::STATELESS_SIGNATURE_BYTES % 16U, 0U);
    BOOST_CHECK_EQUAL(
        shrincs_tx_v0::STATELESS_SIGNATURE_BYTES - shrincs_tx_v0::STATEFUL_SIGNATURE_MAX,
        1'158U);

    const auto stateless_mode{shrincs_tx_v0::ClassifySignature(shrincs_tx_v0::STATELESS_SIGNATURE_BYTES)};
    BOOST_REQUIRE(stateless_mode.has_value());
    BOOST_CHECK(*stateless_mode == shrincs_tx_v0::SignatureMode::STATELESS);
    BOOST_CHECK(!shrincs_tx_v0::StatefulDepth(shrincs_tx_v0::STATELESS_SIGNATURE_BYTES));

    std::uint64_t maximum_stateful_block_work{0};
    std::uint16_t maximizing_depth{0};

    for (std::uint16_t depth = 1; depth <= 255; ++depth) {
        const std::size_t signature_size{
            shrincs_tx_v0::STATEFUL_SIGNATURE_BASE +
            shrincs_tx_v0::STATEFUL_SIGNATURE_STEP * static_cast<std::size_t>(depth)};
        const auto mode{shrincs_tx_v0::ClassifySignature(signature_size)};
        const auto recovered_depth{shrincs_tx_v0::StatefulDepth(signature_size)};
        const auto compressions{shrincs_tx_v0::VerifierCompressions(signature_size)};
        const auto weight{shrincs_tx_v0::OneInputTwoOutputWeight(signature_size)};
        const auto block_work{shrincs_tx_v0::BlockVerifierCompressions(signature_size)};
        BOOST_REQUIRE(mode.has_value());
        BOOST_REQUIRE(recovered_depth.has_value());
        BOOST_REQUIRE(compressions.has_value());
        BOOST_REQUIRE(weight.has_value());
        BOOST_REQUIRE(block_work.has_value());
        BOOST_CHECK(*mode == shrincs_tx_v0::SignatureMode::STATEFUL);
        BOOST_CHECK_EQUAL(*recovered_depth, depth);
        BOOST_CHECK_EQUAL(signature_size % 16U, 10U);
        BOOST_CHECK_EQUAL(*compressions, 497U + 2U * depth);
        BOOST_CHECK_EQUAL(*weight, 1141U + 16U * depth);
        BOOST_CHECK_EQUAL(signature_size - *compressions, 41U + 14U * depth);

        if (depth < 255) {
            const std::size_t next_size{signature_size + shrincs_tx_v0::STATEFUL_SIGNATURE_STEP};
            const std::uint64_t next_compressions{*shrincs_tx_v0::VerifierCompressions(next_size)};
            const std::uint64_t next_weight{*shrincs_tx_v0::OneInputTwoOutputWeight(next_size)};
            BOOST_CHECK(next_compressions * *weight < *compressions * next_weight);
        }

        if (*block_work > maximum_stateful_block_work) {
            maximum_stateful_block_work = *block_work;
            maximizing_depth = depth;
        }
    }

    BOOST_CHECK_EQUAL(maximizing_depth, 1U);
    BOOST_CHECK_EQUAL(maximum_stateful_block_work, 1'725'043U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::BlockVerifierCompressions(4618), 771'362U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::BlockVerifierCompressions(5776), 3'469'818U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::WorstCaseBlockVerifierCompressions(), 3'469'818U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::OneInputTwoOutputWeight(554), 1'157U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::OneInputTwoOutputWeight(4618), 5'221U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::OneInputTwoOutputWeight(5776), 6'379U);
    BOOST_CHECK_EQUAL(*shrincs_tx_v0::BlockVerifierCompressions(554, 0), 0U);

    for (const std::size_t invalid_size : {0U, 553U, 555U, 4619U, 5775U, 5777U}) {
        BOOST_CHECK(!shrincs_tx_v0::VerifierCompressions(invalid_size));
        BOOST_CHECK(!shrincs_tx_v0::OneInputTwoOutputWeight(invalid_size));
        BOOST_CHECK(!shrincs_tx_v0::BlockVerifierCompressions(invalid_size));
    }
}

BOOST_AUTO_TEST_SUITE_END()
