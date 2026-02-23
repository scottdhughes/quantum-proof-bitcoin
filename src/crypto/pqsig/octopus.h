// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_OCTOPUS_H
#define BITCOIN_CRYPTO_PQSIG_OCTOPUS_H

#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/params.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span.h>

namespace pqsig {
namespace octopus {

inline void FillAuthPad(
    const std::span<uint8_t> auth_pad,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> r,
    const std::span<const uint8_t> hmsg,
    PQSigMetrics* metrics)
{
    if (auth_pad.size() != params::PORS_AUTH_PAD_SIZE) return;

    const size_t chunks = auth_pad.size() / params::N;
    for (size_t i = 0; i < chunks; ++i) {
        const auto i_le = domains::U32ToLE(static_cast<uint32_t>(i));
        const std::array<std::span<const uint8_t>, 4> parts{
            sk_seed,
            r,
            hmsg,
            std::span<const uint8_t>{i_le},
        };
        const auto chunk = domains::HashN(metrics, "PQSIG-OCTO-CHUNK", parts);
        std::copy(chunk.begin(), chunk.end(), auth_pad.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
}

inline std::array<uint8_t, params::N> FoldAuthPad(
    const std::span<const uint8_t> auth_pad,
    const std::span<const uint16_t> indices,
    PQSigMetrics* metrics)
{
    std::array<uint8_t, params::N> acc{};
    {
        const std::array<std::span<const uint8_t>, 1> parts{std::span<const uint8_t>{auth_pad}};
        acc = domains::HashN(metrics, "PQSIG-OCTO-INIT", parts);
    }

    if (auth_pad.size() != params::PORS_AUTH_PAD_SIZE || indices.size() != params::K) {
        return acc;
    }

    const size_t chunks = auth_pad.size() / params::N;
    for (size_t i = 0; i < chunks; ++i) {
        const auto idx_le = domains::U16ToLE(indices[i % params::K]);
        const auto i_le = domains::U32ToLE(static_cast<uint32_t>(i));
        const auto chunk = auth_pad.subspan(i * params::N, params::N);
        const std::array<std::span<const uint8_t>, 4> parts{
            std::span<const uint8_t>{acc},
            chunk,
            std::span<const uint8_t>{idx_le},
            std::span<const uint8_t>{i_le},
        };
        acc = domains::HashN(metrics, "PQSIG-OCTO-FOLD", parts);
    }

    return acc;
}

} // namespace octopus
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_OCTOPUS_H
