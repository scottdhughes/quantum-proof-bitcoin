// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_SCRIPT_SHRINCS_TX_V0_H
#define BITCOIN_SCRIPT_SHRINCS_TX_V0_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace shrincs_tx_v0 {

inline constexpr std::size_t PUBLIC_KEY_BYTES{48};
inline constexpr std::size_t PROGRAM_BYTES{32};
inline constexpr std::size_t STATEFUL_SIGNATURE_MIN{554};
inline constexpr std::size_t STATEFUL_SIGNATURE_MAX{4618};
inline constexpr std::size_t STATEFUL_SIGNATURE_BASE{538};
inline constexpr std::size_t STATEFUL_SIGNATURE_STEP{16};
inline constexpr std::size_t STATELESS_SIGNATURE_BYTES{5776};
inline constexpr std::uint8_t PROPOSED_WITNESS_VERSION{2};
inline constexpr std::uint8_t SIGHASH_ALL{1};
inline constexpr std::uint8_t SIGHASH_EPOCH{0};
inline constexpr std::uint8_t SPEND_TYPE{0};
inline constexpr std::uint64_t STATEFUL_WEIGHT_BASE{1141};
inline constexpr std::uint64_t STATEFUL_COMPRESSION_BASE{497};
inline constexpr std::uint64_t STATELESS_WEIGHT{6379};
inline constexpr std::uint64_t STATELESS_COMPRESSIONS{5534};
inline constexpr std::uint64_t DEFAULT_BLOCK_WEIGHT{4'000'000};

inline constexpr std::string_view OUTPUT_TAG{"PQBTC/SHRINCS/OUTPUT/v0"};
inline constexpr std::string_view SIGHASH_TAG{"PQBTC/SHRINCS/SIGHASH/v0"};
inline constexpr std::string_view SIGNING_CONTEXT{"PQBTC/SHRINCS/TXSIG/v0"};

static_assert(STATEFUL_SIGNATURE_MIN == STATEFUL_SIGNATURE_BASE + STATEFUL_SIGNATURE_STEP);
static_assert(STATEFUL_SIGNATURE_MAX == STATEFUL_SIGNATURE_BASE + 255 * STATEFUL_SIGNATURE_STEP);

enum class SignatureMode {
    STATEFUL,
    STATELESS,
};

/** Non-owning view into a caller-owned CScriptWitness. */
struct ParsedWitness {
    std::span<const unsigned char> signature;
    std::span<const unsigned char> public_key;
    SignatureMode mode;
};

/** Return the unique canonical SHRINCS-v0 mode implied by serialized length. */
std::optional<SignatureMode> ClassifySignature(std::size_t signature_size);

/** Return the FXMSS authentication depth encoded by a canonical stateful length. */
std::optional<std::uint16_t> StatefulDepth(std::size_t signature_size);

/** Tagged commitment to one exact 48-byte current-draft SHRINCS public key. */
std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key);

/** Construct the candidate, currently inactive OP_2 PUSH32 output. */
std::optional<CScript> BuildScriptPubKey(std::span<const unsigned char> public_key);

/** Recognize the candidate byte shape without assigning consensus semantics to it. */
bool IsScriptPubKey(const CScript& script_pubkey, std::array<unsigned char, PROGRAM_BYTES>* program = nullptr);

/** Strictly parse [canonical signature, 48-byte public key] against a commitment. */
std::optional<ParsedWitness> ParseWitness(
    const CScriptWitness& witness,
    std::span<const unsigned char> expected_program);

/**
 * Compute the consensus-disabled fixed-SIGHASH_ALL candidate digest using
 * Bitcoin Core transaction and spent-output types.
 *
 * The caller supplies one spent output for every transaction input. Invalid
 * counts, input indices, amounts, scripts, or nonempty scriptSigs fail closed.
 */
std::optional<uint256> SignatureHash(
    const CTransaction& tx,
    std::span<const CTxOut> spent_outputs,
    std::uint32_t input_index,
    const uint256& chain_id);

/** Portable verifier work model for one canonical signature. */
std::optional<std::uint64_t> VerifierCompressions(std::size_t signature_size);

/** Minimal one-input/two-output transaction weight used only for architecture tests. */
std::optional<std::uint64_t> OneInputTwoOutputWeight(std::size_t signature_size);

/** Floor(block_weight / tx_weight) multiplied by per-signature verifier work. */
std::optional<std::uint64_t> BlockVerifierCompressions(
    std::size_t signature_size,
    std::uint64_t block_weight = DEFAULT_BLOCK_WEIGHT);

/** Maximum over all 255 stateful depths and the stateless recovery path. */
std::optional<std::uint64_t> WorstCaseBlockVerifierCompressions(
    std::uint64_t block_weight = DEFAULT_BLOCK_WEIGHT);

} // namespace shrincs_tx_v0

#endif // BITCOIN_SCRIPT_SHRINCS_TX_V0_H
