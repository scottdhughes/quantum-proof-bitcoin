// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_HYPERTREE_H
#define BITCOIN_CRYPTO_PQSIG_HYPERTREE_H

#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/params.h>
#include <crypto/pqsig/wotsc.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span.h>

namespace pqsig {
namespace hypertree {

inline std::array<uint32_t, params::D> DeriveLayerCounts(const std::span<const uint8_t> hmsg)
{
    std::array<uint32_t, params::D> counts{};
    constexpr size_t offset = 32;
    if (hmsg.size() < offset + (params::D * 4)) return counts;

    for (size_t i = 0; i < params::D; ++i) {
        const uint32_t raw = domains::U32FromLE(hmsg.data() + offset + i * 4);
        counts[i] = raw % (params::SWN + 1);
    }
    return counts;
}

inline std::array<uint16_t, params::D> DeriveLeafIndices(const std::span<const uint8_t> hmsg)
{
    std::array<uint16_t, params::D> leaves{};
    constexpr size_t offset = 48;
    if (hmsg.size() < offset + (params::D * 2)) return leaves;

    constexpr uint16_t mask = static_cast<uint16_t>((1U << params::HT_HEIGHT) - 1U);
    for (size_t i = 0; i < params::D; ++i) {
        const uint16_t raw = domains::U16FromLE(hmsg.data() + offset + i * 2);
        leaves[i] = static_cast<uint16_t>(raw & mask);
    }
    return leaves;
}

inline void FillAuthPath(
    const std::span<uint8_t> auth_path,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<const uint8_t> r,
    PQSigMetrics* metrics)
{
    if (auth_path.size() != params::HT_AUTH_SIZE || msg16.size() != params::N) return;

    const auto layer_le = domains::U32ToLE(layer);
    const auto leaf_le = domains::U16ToLE(leaf_index);

    for (size_t depth = 0; depth < params::HT_HEIGHT; ++depth) {
        const auto depth_le = domains::U32ToLE(static_cast<uint32_t>(depth));
        const std::array<std::span<const uint8_t>, 7> parts{
            sk_seed,
            pk_seed,
            msg16,
            std::span<const uint8_t>{layer_le},
            std::span<const uint8_t>{leaf_le},
            std::span<const uint8_t>{depth_le},
            r,
        };
        const auto node = domains::HashN(metrics, "PQSIG-HT-AUTH", parts);
        std::copy(node.begin(), node.end(), auth_path.begin() + static_cast<ptrdiff_t>(depth * params::N));
    }
}

inline std::array<uint8_t, params::N> ComputeLayerRoot(
    const std::span<const uint8_t> msg16,
    const std::span<const uint8_t> wots_sig,
    const std::span<const uint8_t> auth_path,
    const uint32_t layer,
    const uint16_t leaf_index,
    const uint32_t count,
    const std::span<const uint8_t> r,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    const auto wots_commit = wotsc::CommitLayerSignature(wots_sig, msg16, layer, count, r, pk_seed, metrics);

    const auto layer_le = domains::U32ToLE(layer);
    const auto leaf_le = domains::U16ToLE(leaf_index);
    const auto count_le = domains::U32ToLE(count);

    const std::array<std::span<const uint8_t>, 4> leaf_parts{
        std::span<const uint8_t>{wots_commit},
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{leaf_le},
        std::span<const uint8_t>{count_le},
    };
    std::array<uint8_t, params::N> node = domains::HashN(metrics, "PQSIG-HT-LEAF", leaf_parts);

    if (auth_path.size() != params::HT_AUTH_SIZE) return node;

    for (size_t depth = 0; depth < params::HT_HEIGHT; ++depth) {
        const auto depth_le = domains::U32ToLE(static_cast<uint32_t>(depth));
        const auto sibling = auth_path.subspan(depth * params::N, params::N);
        const bool odd = ((leaf_index >> depth) & 1U) != 0;

        const std::array<std::span<const uint8_t>, 5> node_parts{
            std::span<const uint8_t>{layer_le},
            std::span<const uint8_t>{depth_le},
            odd ? sibling : std::span<const uint8_t>{node},
            odd ? std::span<const uint8_t>{node} : sibling,
            std::span<const uint8_t>{count_le},
        };
        node = domains::HashN(metrics, "PQSIG-HT-NODE", node_parts);
    }

    return node;
}

} // namespace hypertree
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_HYPERTREE_H
