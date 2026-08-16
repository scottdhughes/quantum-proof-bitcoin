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

const std::map<std::string, std::string>& ExpectedMutationDigests()
{
    static const std::map<std::string, std::string> expected{
        {"version", "f0a88b084ae764f57005649125ff40b9a8809973d4a8391f6f323e99e295c818"},
        {"lock_time", "89adb3edb1d247dd2bdef96f1a50424de7ae86a86230aad08047707eb37a03fd"},
        {"input0_prevout_txid", "63b6b437b73e98fb794d4519e136c729a3673a2da58c9dbe59cf9bbc5ac17fae"},
        {"input0_prevout_index", "d6f46f8a93b0ca84082bce9f68aaedaa0ec27bc1fae932590f98c65d12862591"},
        {"input0_amount", "25d76e3dfde70967dbf069462e904870c2d0e1edf4676b889fcf13dfd99f6b04"},
        {"input0_script", "1f02eb074275eb8c81a4456b85ac08d453f0b14414d0355fc3b06fcdc28d1383"},
        {"input0_sequence", "d75c90f0fa186b0ed956d849f65c227c367179be4f10e4ce581ba32045833bb2"},
        {"input1_prevout_txid", "16817e99e5d91cdefdec9976647ffee024785e8c71b1573b8f811fc586a404aa"},
        {"input1_prevout_index", "aad8ded0c68fcd781dd213539fee5b09256fc6a5036ae724fbc2c496635f8558"},
        {"input1_amount", "5133fdfb421c75052a0ea3ccb83800037d06b1d3c2188b984f6dd464c64d9045"},
        {"input1_script", "06450f8864e90463075bf98ee1a4d4a2c540bb6e5cd4a85fa6dfed89b67e0988"},
        {"input1_sequence", "59ff024ec0ede20ea1af03150a15195e797232f7f72a913d5c258eb27bc1210d"},
        {"input_order", "44f061b771ca1d911883ba99045ca98325fbd007d53ad5e3e2189886fa3d9d90"},
        {"input_removed", "a977cb22b9dc90e6a86a888d5be37f81dee85c9202a89d21d2e9adf264147e12"},
        {"input_added", "49d5c0bc340070c2a1b5af4e87e2524e25e86214025d4d2623d835be86ee2ae6"},
        {"output0_amount", "04bd785d232039afb2cece0bdbff94b5566bf33618988c0abc649037ecc27e92"},
        {"output0_script", "7be4ea4ca59a9c7d07d6866dca82cdc5a02e0b6c90edf3a3f3804c1b3323c2a1"},
        {"output1_amount", "be8cd212318d44c41492126fb2feb4194fb97fbe928125241ad5b39b0d742a31"},
        {"output1_script", "f848fe177c50411fbbfccd15ae9c3ae5ab8a8adc4f42062a879530061bd9e585"},
        {"output_order", "6b3d05a5774d5f7fd0c013719e64043423a6d645de86ea55152ea565948acca0"},
        {"output_removed", "d5ed7cc043381d4b4c20309aab9c2b3fb1dcbf968ac50928ad2eaa34c83c7dac"},
        {"output_added", "71110447afe6534844d48e6fa949d1f1dee39fd4cf1759c904092d30b6ee69b1"},
    };
    return expected;
}

} // namespace

BOOST_AUTO_TEST_CASE(cpp_matches_python_design_and_signed_seam_vectors)
{
    const std::vector<unsigned char> public_key{SequentialPublicKey()};
    const EnvelopeCase test_case{BuildEnvelopeCase(public_key)};

    BOOST_CHECK(test_case.chain_id == RawUint256("5ac90260b854c448631456ad49ca4988c20a13eeec3e283f59afac1f8cb29486"));
    BOOST_CHECK_EQUAL(
        SerializeStripped(test_case.tx),
        "0200000002537b9332eb572ede46a4cf44321cf733a0c76ab6a9cf2d19cd7f3e1ea451c54b0300000000fdffffff21f5e2d90566de1e49bb495dc18bd495be7ee3ba896855982799c940dafcd0070100000000feffffff02f049020000000000225220e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb9768bf000000000000066a045051563040d10c00");

    const std::optional<uint256> commitment{shrincs_tx_v0::OutputCommitment(public_key)};
    BOOST_REQUIRE(commitment.has_value());
    BOOST_CHECK_EQUAL(RawHex(*commitment), "e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb97");

    BOOST_CHECK_EQUAL(RawHex(RequireDigest(test_case)), "e81658399900d55841623b54f075cebfe6c9caf307e62e5952634d16ae61f35d");
    EnvelopeCase second_input{test_case};
    second_input.input_index = 1;
    BOOST_CHECK_EQUAL(RawHex(RequireDigest(second_input)), "cdf2b774b68cdbd23a424faee209495c523a790c92fa6ea293e166ea075245e7");

    const std::vector<unsigned char> signed_public_key{ParseHex(
        "abd9967c038df9b774b48e0360d7cad25ad8c4073c7d3973d4ce8b8cdcc3f12bf784a8a40fb8c98d39ee302e705ae7da")};
    const EnvelopeCase signed_case{BuildEnvelopeCase(signed_public_key)};
    const std::optional<uint256> signed_commitment{shrincs_tx_v0::OutputCommitment(signed_public_key)};
    BOOST_REQUIRE(signed_commitment.has_value());
    BOOST_CHECK_EQUAL(RawHex(*signed_commitment), "d23ac81a74411a8645d375abd22acf8d10e3e18b96b173ec99d8fb1496759665");
    BOOST_CHECK_EQUAL(RawHex(RequireDigest(signed_case)), "dc00d9f169e44ad39fea3db0736ee5ec834d8a3ae8e8ac7e8997ee1eacc399d5");
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
