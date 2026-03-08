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
#include <vector>
#include <span.h>

namespace pqsig {
namespace hypertree {

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

inline std::array<uint8_t, params::N> HashTreeNode(
    const std::span<const uint8_t> left,
    const std::span<const uint8_t> right,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint32_t depth,
    const uint32_t node_index,
    PQSigMetrics* metrics)
{
    const auto layer_le = domains::U32ToLE(layer);
    const auto depth_le = domains::U32ToLE(depth);
    const auto node_le = domains::U32ToLE(node_index);
    const std::array<std::span<const uint8_t>, 6> parts{
        left,
        right,
        pk_seed,
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{depth_le},
        std::span<const uint8_t>{node_le},
    };
    return domains::HashN(metrics, "PQSIG-HT-NODE", parts);
}

inline std::array<uint8_t, params::N> ComputeLayerRoot(
    const std::span<const uint8_t> msg16,
    const std::span<const uint8_t> wots_sig,
    const std::span<const uint8_t> auth_path,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::N> node =
        wotsc::CommitLayerSignature(wots_sig, msg16, layer, leaf_index, pk_seed, metrics);

    if (auth_path.size() != params::HT_AUTH_SIZE) return node;

    uint32_t node_index = leaf_index;
    for (size_t depth = 0; depth < params::HT_HEIGHT; ++depth) {
        const auto sibling = auth_path.subspan(depth * params::N, params::N);
        const bool odd = (node_index & 1U) != 0;
        node = HashTreeNode(
            odd ? sibling : std::span<const uint8_t>{node},
            odd ? std::span<const uint8_t>{node} : sibling,
            pk_seed,
            layer,
            static_cast<uint32_t>(depth),
            node_index >> 1,
            metrics);
        node_index >>= 1;
    }

    return node;
}

inline std::array<uint8_t, params::N> BuildRootAndAuthPath(
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    const std::span<uint8_t> auth_path,
    PQSigMetrics* metrics)
{
    constexpr size_t LEAF_COUNT = 1U << params::HT_HEIGHT;
    std::vector<std::array<uint8_t, params::N>> level(LEAF_COUNT);
    for (size_t leaf = 0; leaf < LEAF_COUNT; ++leaf) {
        level[leaf] = wotsc::DeriveLeafPublicKey(sk_seed, pk_seed, layer, static_cast<uint16_t>(leaf), metrics);
    }

    uint32_t node_index = leaf_index;
    for (size_t depth = 0; depth < params::HT_HEIGHT; ++depth) {
        if (auth_path.size() == params::HT_AUTH_SIZE) {
            const auto& sibling = level[node_index ^ 1U];
            std::copy(sibling.begin(), sibling.end(), auth_path.begin() + static_cast<ptrdiff_t>(depth * params::N));
        }

        std::vector<std::array<uint8_t, params::N>> parent(level.size() / 2);
        for (size_t i = 0; i < parent.size(); ++i) {
            parent[i] = HashTreeNode(
                std::span<const uint8_t>{level[2 * i]},
                std::span<const uint8_t>{level[2 * i + 1]},
                pk_seed,
                layer,
                static_cast<uint32_t>(depth),
                static_cast<uint32_t>(i),
                metrics);
        }
        level = std::move(parent);
        node_index >>= 1;
    }

    return level[0];
}

inline void FillAuthPath(
    const std::span<uint8_t> auth_path,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const uint32_t layer,
    const uint16_t leaf_index,
    PQSigMetrics* metrics)
{
    if (auth_path.size() != params::HT_AUTH_SIZE) return;
    (void)BuildRootAndAuthPath(sk_seed, pk_seed, layer, leaf_index, auth_path, metrics);
}

inline std::array<uint8_t, params::N> DerivePublicRoot(
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::HT_AUTH_SIZE> unused_auth{};
    return BuildRootAndAuthPath(sk_seed, pk_seed, params::D - 1, 0, std::span<uint8_t>{unused_auth}.first(0), metrics);
}

} // namespace hypertree
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_HYPERTREE_H
