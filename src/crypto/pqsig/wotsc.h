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

inline void FillLayerSignature(
    const std::span<uint8_t> wots_sig,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_seed,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint32_t count,
    const std::span<const uint8_t> r,
    PQSigMetrics* metrics)
{
    if (wots_sig.size() != params::HT_WOTS_SIZE || msg16.size() != params::N) return;

    const auto layer_le = domains::U32ToLE(layer);
    const auto count_le = domains::U32ToLE(count);

    for (size_t i = 0; i < params::L; ++i) {
        const auto i_le = domains::U32ToLE(static_cast<uint32_t>(i));
        const uint8_t nibble = MessageNibble(msg16, i);
        const uint8_t tweak = static_cast<uint8_t>((nibble + (count % params::W) + i) & 0x0f);
        const std::array<uint8_t, 1> tweak_arr{tweak};

        const std::array<std::span<const uint8_t>, 8> parts{
            sk_seed,
            pk_seed,
            r,
            msg16,
            std::span<const uint8_t>{layer_le},
            std::span<const uint8_t>{count_le},
            std::span<const uint8_t>{i_le},
            std::span<const uint8_t>{tweak_arr},
        };
        const auto chunk = domains::HashN(metrics, "PQSIG-WOTS-SIG", parts);
        std::copy(chunk.begin(), chunk.end(), wots_sig.begin() + static_cast<ptrdiff_t>(i * params::N));
    }
}

inline std::array<uint8_t, params::N> CommitLayerSignature(
    const std::span<const uint8_t> wots_sig,
    const std::span<const uint8_t> msg16,
    const uint32_t layer,
    const uint32_t count,
    const std::span<const uint8_t> r,
    const std::span<const uint8_t> pk_seed,
    PQSigMetrics* metrics)
{
    const auto layer_le = domains::U32ToLE(layer);
    const auto count_le = domains::U32ToLE(count);
    const std::array<std::span<const uint8_t>, 6> parts{
        wots_sig,
        msg16,
        std::span<const uint8_t>{layer_le},
        std::span<const uint8_t>{count_le},
        r,
        pk_seed,
    };
    return domains::HashN(metrics, "PQSIG-WOTS-COMMIT", parts);
}

} // namespace wotsc
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_WOTSC_H
