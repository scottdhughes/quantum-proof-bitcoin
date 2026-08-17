// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/shrincs_tx_v0.h>

#include <consensus/amount.h>
#include <hash.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace shrincs_tx_v0 {
namespace {

uint256 HashPrevouts(const CTransaction& tx)
{
    HashWriter writer;
    for (const CTxIn& input : tx.vin) {
        writer << input.prevout;
    }
    return writer.GetSHA256();
}

uint256 HashAmounts(std::span<const CTxOut> spent_outputs)
{
    HashWriter writer;
    for (const CTxOut& spent : spent_outputs) {
        writer << spent.nValue;
    }
    return writer.GetSHA256();
}

uint256 HashScriptPubKeys(std::span<const CTxOut> spent_outputs)
{
    HashWriter writer;
    for (const CTxOut& spent : spent_outputs) {
        writer << spent.scriptPubKey;
    }
    return writer.GetSHA256();
}

uint256 HashSequences(const CTransaction& tx)
{
    HashWriter writer;
    for (const CTxIn& input : tx.vin) {
        writer << input.nSequence;
    }
    return writer.GetSHA256();
}

uint256 HashOutputs(const CTransaction& tx)
{
    HashWriter writer;
    for (const CTxOut& output : tx.vout) {
        writer << output;
    }
    return writer.GetSHA256();
}

bool IsValidEnvelopeTransaction(
    const CTransaction& tx,
    std::span<const CTxOut> spent_outputs,
    std::uint32_t input_index)
{
    if (tx.vin.empty() || tx.vout.empty()) return false;
    if (spent_outputs.size() != tx.vin.size()) return false;
    if (input_index >= tx.vin.size()) return false;

    for (std::size_t index = 0; index < tx.vin.size(); ++index) {
        if (!tx.vin[index].scriptSig.empty()) return false;
        const CTxOut& spent = spent_outputs[index];
        if (!MoneyRange(spent.nValue)) return false;
        if (spent.scriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
    }

    for (const CTxOut& output : tx.vout) {
        if (!MoneyRange(output.nValue)) return false;
        if (output.scriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
    }

    return true;
}

} // namespace

std::optional<SignatureMode> ClassifySignature(const std::size_t signature_size)
{
    if (signature_size == STATELESS_SIGNATURE_BYTES) {
        return SignatureMode::STATELESS;
    }
    if (signature_size < STATEFUL_SIGNATURE_MIN || signature_size > STATEFUL_SIGNATURE_MAX) {
        return std::nullopt;
    }
    const std::size_t delta{signature_size - STATEFUL_SIGNATURE_BASE};
    if (delta % STATEFUL_SIGNATURE_STEP != 0) return std::nullopt;
    const std::size_t depth{delta / STATEFUL_SIGNATURE_STEP};
    if (depth < 1 || depth > 255) return std::nullopt;
    return SignatureMode::STATEFUL;
}

std::optional<std::uint16_t> StatefulDepth(const std::size_t signature_size)
{
    const std::optional<SignatureMode> mode{ClassifySignature(signature_size)};
    if (!mode || *mode != SignatureMode::STATEFUL) return std::nullopt;
    return static_cast<std::uint16_t>((signature_size - STATEFUL_SIGNATURE_BASE) / STATEFUL_SIGNATURE_STEP);
}

uint256 RegtestChainId()
{
    HashWriter writer;
    writer.write(std::as_bytes(std::span<const char>{
        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));
    return writer.GetSHA256();
}

std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key)
{
    if (public_key.size() != PUBLIC_KEY_BYTES) return std::nullopt;
    HashWriter writer{TaggedHash(std::string{OUTPUT_TAG})};
    writer.write(std::as_bytes(public_key));
    return writer.GetSHA256();
}

std::optional<CScript> BuildScriptPubKey(std::span<const unsigned char> public_key)
{
    const std::optional<uint256> commitment{OutputCommitment(public_key)};
    if (!commitment) return std::nullopt;

    const std::vector<unsigned char> program{commitment->begin(), commitment->end()};
    CScript script;
    script << CScript::EncodeOP_N(PROPOSED_WITNESS_VERSION) << program;
    return script;
}

bool IsScriptPubKey(
    const CScript& script_pubkey,
    std::array<unsigned char, PROGRAM_BYTES>* program)
{
    int version{-1};
    std::vector<unsigned char> candidate;
    if (!script_pubkey.IsWitnessProgram(version, candidate)) return false;
    if (version != PROPOSED_WITNESS_VERSION || candidate.size() != PROGRAM_BYTES) return false;
    if (program != nullptr) {
        std::copy(candidate.begin(), candidate.end(), program->begin());
    }
    return true;
}

std::optional<ParsedWitness> ParseWitness(
    const CScriptWitness& witness,
    std::span<const unsigned char> expected_program)
{
    if (expected_program.size() != PROGRAM_BYTES) return std::nullopt;
    if (witness.stack.size() != 2) return std::nullopt;

    const std::vector<unsigned char>& signature{witness.stack[0]};
    const std::vector<unsigned char>& public_key{witness.stack[1]};
    if (public_key.size() != PUBLIC_KEY_BYTES) return std::nullopt;

    const std::optional<SignatureMode> mode{ClassifySignature(signature.size())};
    if (!mode) return std::nullopt;

    const std::optional<uint256> commitment{OutputCommitment(public_key)};
    if (!commitment) return std::nullopt;
    if (!std::equal(commitment->begin(), commitment->end(), expected_program.begin(), expected_program.end())) {
        return std::nullopt;
    }

    return ParsedWitness{
        .signature = std::span<const unsigned char>{signature.data(), signature.size()},
        .public_key = std::span<const unsigned char>{public_key.data(), public_key.size()},
        .mode = *mode,
    };
}

std::optional<uint256> SignatureHash(
    const CTransaction& tx,
    std::span<const CTxOut> spent_outputs,
    const std::uint32_t input_index,
    const uint256& chain_id)
{
    if (!IsValidEnvelopeTransaction(tx, spent_outputs, input_index)) return std::nullopt;

    const uint256 hash_prevouts{HashPrevouts(tx)};
    const uint256 hash_amounts{HashAmounts(spent_outputs)};
    const uint256 hash_scriptpubkeys{HashScriptPubKeys(spent_outputs)};
    const uint256 hash_sequences{HashSequences(tx)};
    const uint256 hash_outputs{HashOutputs(tx)};

    HashWriter writer{TaggedHash(std::string{SIGHASH_TAG})};
    writer << SIGHASH_EPOCH
           << SIGHASH_ALL
           << chain_id
           << tx.version
           << tx.nLockTime
           << hash_prevouts
           << hash_amounts
           << hash_scriptpubkeys
           << hash_sequences
           << hash_outputs
           << SPEND_TYPE
           << input_index;
    return writer.GetSHA256();
}

std::optional<std::uint64_t> VerifierCompressions(const std::size_t signature_size)
{
    const std::optional<SignatureMode> mode{ClassifySignature(signature_size)};
    if (!mode) return std::nullopt;
    if (*mode == SignatureMode::STATELESS) return STATELESS_COMPRESSIONS;

    const std::optional<std::uint16_t> depth{StatefulDepth(signature_size)};
    if (!depth) return std::nullopt;
    return STATEFUL_COMPRESSION_BASE + 2 * static_cast<std::uint64_t>(*depth);
}

std::optional<std::uint64_t> OneInputTwoOutputWeight(const std::size_t signature_size)
{
    const std::optional<SignatureMode> mode{ClassifySignature(signature_size)};
    if (!mode) return std::nullopt;
    if (*mode == SignatureMode::STATELESS) return STATELESS_WEIGHT;

    const std::optional<std::uint16_t> depth{StatefulDepth(signature_size)};
    if (!depth) return std::nullopt;
    return STATEFUL_WEIGHT_BASE + STATEFUL_SIGNATURE_STEP * static_cast<std::uint64_t>(*depth);
}

std::optional<std::uint64_t> BlockVerifierCompressions(
    const std::size_t signature_size,
    const std::uint64_t block_weight)
{
    const std::optional<std::uint64_t> weight{OneInputTwoOutputWeight(signature_size)};
    const std::optional<std::uint64_t> compressions{VerifierCompressions(signature_size)};
    if (!weight || !compressions || *weight == 0) return std::nullopt;

    const std::uint64_t transactions{block_weight / *weight};
    if (*compressions != 0 && transactions > std::numeric_limits<std::uint64_t>::max() / *compressions) {
        return std::nullopt;
    }
    return transactions * *compressions;
}

std::optional<std::uint64_t> WorstCaseBlockVerifierCompressions(const std::uint64_t block_weight)
{
    std::uint64_t maximum{0};
    for (std::uint16_t depth = 1; depth <= 255; ++depth) {
        const std::size_t signature_size{
            STATEFUL_SIGNATURE_BASE + STATEFUL_SIGNATURE_STEP * static_cast<std::size_t>(depth)};
        const std::optional<std::uint64_t> work{BlockVerifierCompressions(signature_size, block_weight)};
        if (!work) return std::nullopt;
        maximum = std::max(maximum, *work);
    }

    const std::optional<std::uint64_t> stateless{
        BlockVerifierCompressions(STATELESS_SIGNATURE_BYTES, block_weight)};
    if (!stateless) return std::nullopt;
    return std::max(maximum, *stateless);
}

} // namespace shrincs_tx_v0
