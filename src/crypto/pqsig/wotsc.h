// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_WOTSC_H
#define BITCOIN_CRYPTO_PQSIG_WOTSC_H

#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/params.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span.h>

namespace pqsig {
namespace wotsc {

inline uint8_t MessageNibble(const std::span<const uint8_t> msg16, const size_t n)
{
    const uint8_t v = msg16[n / 2];
    return (n & 1U) == 0 ? static_cast<uint8_t>(v >> 4) : static_cast<uint8_t>(v & 0x0f);
}

inline std::array<uint8_t, params::N> ChainStep(
    const std::span<const uint8_t> node,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    const uint32_t chunk_index,
    const uint32_t step,
    PQSigMetrics* metrics)
{
    const auto layer_le = domains::U32ToLE(layer);
    const auto leaf_le = domains::U16ToLE(leaf_index);
    const auto chunk_le = domains::U32ToLE(chunk_index);
    const auto step_le = domains::U32ToLE(step);
    const std::array<std::span<const uint8_t>, 6> parts{
        node,
        pk_seed,
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{leaf_le},
        std::span<const uint8_t>{chunk_le},
        std::span<const uint8_t>{step_le},
    };
    return domains::HashN(metrics, "PQSIG-WOTS-STEP", parts);
}

inline std::array<uint8_t, params::N> AdvanceChain(
    const std::span<const uint8_t> start_node,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    const uint32_t chunk_index,
    const uint32_t start_step,
    const uint32_t steps,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::N> node{};
    std::copy_n(start_node.begin(), params::N, node.begin());
    for (uint32_t i = 0; i < steps; ++i) {
        node = ChainStep(std::span<const uint8_t>{node}, pk_seed, layer, leaf_index, chunk_index, start_step + i, metrics);
    }
    return node;
}

inline std::array<uint8_t, params::N> DeriveSecretChunk(
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    const uint32_t chunk_index,
    PQSigMetrics* metrics)
{
    const auto layer_le = domains::U32ToLE(layer);
    const auto leaf_le = domains::U16ToLE(leaf_index);
    const auto chunk_le = domains::U32ToLE(chunk_index);
    const std::array<std::span<const uint8_t>, 5> parts{
        sk_seed,
        pk_seed,
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{leaf_le},
        std::span<const uint8_t>{chunk_le},
    };
    return domains::HashN(metrics, "PQSIG-WOTS-SECRET", parts);
}

inline std::array<uint8_t, params::N> CommitPublicChunks(
    const std::span<const uint8_t> public_chunks,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    const auto layer_le = domains::U32ToLE(layer);
    const auto leaf_le = domains::U16ToLE(leaf_index);
    const std::array<std::span<const uint8_t>, 4> parts{
        public_chunks,
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{leaf_le},
        pk_seed,
    };
    return domains::HashN(metrics, "PQSIG-WOTS-PK", parts);
}

inline void FillLayerSignature(
    const std::span<uint8_t> wots_sig,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint16_t leaf_index,
    PQSigMetrics* metrics)
{
    if (wots_sig.size() != params::HT_WOTS_SIZE || msg16.size() != params::N) return;

    for (size_t i = 0; i < params::L; ++i) {
        const uint32_t chunk_index = static_cast<uint32_t>(i);
        const uint8_t nibble = MessageNibble(msg16, i);
        const auto secret = DeriveSecretChunk(sk_seed, pk_seed, layer, leaf_index, chunk_index, metrics);
        const auto sig_chunk = AdvanceChain(std::span<const uint8_t>{secret}, pk_seed, layer, leaf_index, chunk_index, 0, nibble, metrics);
        std::copy(sig_chunk.begin(), sig_chunk.end(), wots_sig.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
}

inline void ReconstructPublicChunks(
    std::array<uint8_t, params::HT_WOTS_SIZE>& public_chunks,
    const std::span<const uint8_t> wots_sig,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    for (size_t i = 0; i < params::L; ++i) {
        const uint32_t chunk_index = static_cast<uint32_t>(i);
        const uint8_t nibble = MessageNibble(msg16, i);
        const auto sig_chunk = wots_sig.subspan(i * params::N, params::N);
        const auto public_chunk = AdvanceChain(sig_chunk, pk_seed, layer, leaf_index, chunk_index, nibble, params::W - 1 - nibble, metrics);
        std::copy(public_chunk.begin(), public_chunk.end(), public_chunks.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
}

inline std::array<uint8_t, params::N> DeriveLeafPublicKey(
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::HT_WOTS_SIZE> public_chunks{};
    for (size_t i = 0; i < params::L; ++i) {
        const uint32_t chunk_index = static_cast<uint32_t>(i);
        const auto secret = DeriveSecretChunk(sk_seed, pk_seed, layer, leaf_index, chunk_index, metrics);
        const auto public_chunk = AdvanceChain(std::span<const uint8_t>{secret}, pk_seed, layer, leaf_index, chunk_index, 0, params::W - 1, metrics);
        std::copy(public_chunk.begin(), public_chunk.end(), public_chunks.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
    return CommitPublicChunks(std::span<const uint8_t>{public_chunks}, layer, leaf_index, pk_seed, metrics);
}

inline std::array<uint8_t, params::N> CommitLayerSignature(
    const std::span<const uint8_t> wots_sig,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::HT_WOTS_SIZE> public_chunks{};
    ReconstructPublicChunks(public_chunks, wots_sig, msg16, layer, leaf_index, pk_seed, metrics);
    return CommitPublicChunks(std::span<const uint8_t>{public_chunks}, layer, leaf_index, pk_seed, metrics);
}

} // namespace wotsc
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_WOTSC_H
