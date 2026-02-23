// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PORSFP_H
#define BITCOIN_CRYPTO_PQSIG_PORSFP_H

#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/octopus.h>
#include <crypto/pqsig/params.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span.h>

namespace pqsig {
namespace porsfp {

inline std::array<uint16_t, params::K> DeriveIndices(const std::span<const uint8_t> hmsg)
{
    std::array<uint16_t, params::K> out{};
    if (hmsg.size() < params::K * 2) return out;

    constexpr uint16_t mask = static_cast<uint16_t>((1U << params::A) - 1U);
    for (size_t i = 0; i < params::K; ++i) {
        const uint16_t raw = domains::U16FromLE(hmsg.data() + (i * 2));
        out[i] = static_cast<uint16_t>(raw & mask);
    }
    return out;
}

inline void FillReveals(
    const std::span<uint8_t> reveals,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> r,
    const std::span<const uint16_t> indices,
    PQSigMetrics* metrics)
{
    if (reveals.size() != params::PORS_REVEAL_SIZE || indices.size() != params::K) return;

    for (size_t i = 0; i < params::K; ++i) {
        const auto idx_le = domains::U16ToLE(indices[i]);
        const auto i_le = domains::U32ToLE(static_cast<uint32_t>(i));
        const std::array<std::span<const uint8_t>, 4> parts{
            sk_seed,
            r,
            std::span<const uint8_t>{idx_le},
            std::span<const uint8_t>{i_le},
        };
        const auto chunk = domains::HashN(metrics, "PQSIG-PORS-REVEAL", parts);
        std::copy(chunk.begin(), chunk.end(), reveals.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
}

inline std::array<uint8_t, params::N> ComputeRoot(
    const std::span<const uint8_t> reveals,
    const std::span<const uint8_t> auth_pad,
    const std::span<const uint16_t> indices,
    const std::span<const uint8_t> r,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::N> octo = octopus::FoldAuthPad(auth_pad, indices, metrics);

    std::array<uint8_t, params::K * 2> packed_idx{};
    for (size_t i = 0; i < params::K; ++i) {
        const auto idx = domains::U16ToLE(indices[i]);
        packed_idx[i * 2] = idx[0];
        packed_idx[i * 2 + 1] = idx[1];
    }

    const std::array<std::span<const uint8_t>, 6> parts{
        reveals,
        auth_pad,
        std::span<const uint8_t>{packed_idx},
        r,
        msg32,
        pk_seed,
    };
    const auto mix = domains::HashN(metrics, "PQSIG-PORS-MIX", parts);

    const std::array<std::span<const uint8_t>, 2> root_parts{
        std::span<const uint8_t>{mix},
        std::span<const uint8_t>{octo},
    };
    return domains::HashN(metrics, "PQSIG-PORS-ROOT", root_parts);
}

} // namespace porsfp
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_PORSFP_H
