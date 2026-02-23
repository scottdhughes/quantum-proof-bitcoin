// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PARAMS_H
#define BITCOIN_CRYPTO_PQSIG_PARAMS_H

#include <crypto/pqsig/pqsig.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace pqsig {
namespace params {

inline constexpr size_t N{16}; // 128-bit internal hash outputs
inline constexpr size_t PRFMSG_SIZE{32};

inline constexpr uint32_t QS_LOG2{40};
inline constexpr uint32_t H{44};
inline constexpr uint32_t D{4};
inline constexpr uint32_t HT_HEIGHT{H / D}; // 11

inline constexpr uint32_t A{16};
inline constexpr uint32_t K{8};
inline constexpr uint32_t W{16};
inline constexpr uint32_t L{32};
inline constexpr uint32_t SWN{240};

inline constexpr uint32_t PORS_TREE_HEIGHT{A + 3}; // log2(K * 2^A) = 19
inline constexpr uint32_t PORS_LEAF_COUNT{K * (1U << A)};
inline constexpr uint32_t PORS_MMAX{97};

inline constexpr size_t SIG_R_SIZE{32};
inline constexpr size_t PORS_REVEAL_SIZE{K * N};
inline constexpr size_t PORS_AUTH_PAD_SIZE{PORS_MMAX * N};
inline constexpr size_t HT_AUTH_SIZE{HT_HEIGHT * N};
inline constexpr size_t HT_WOTS_SIZE{L * N};
inline constexpr size_t HT_COUNTER_SIZE{4};
inline constexpr size_t HT_LAYER_SIZE{HT_AUTH_SIZE + HT_WOTS_SIZE + HT_COUNTER_SIZE};

inline constexpr size_t PORS_REVEAL_OFFSET{SIG_R_SIZE};
inline constexpr size_t PORS_AUTH_OFFSET{PORS_REVEAL_OFFSET + PORS_REVEAL_SIZE};
inline constexpr size_t HT_OFFSET{PORS_AUTH_OFFSET + PORS_AUTH_PAD_SIZE};

inline constexpr size_t EXPECTED_SIG_SIZE{
    SIG_R_SIZE + PORS_REVEAL_SIZE + PORS_AUTH_PAD_SIZE + D * HT_LAYER_SIZE};

static_assert(EXPECTED_SIG_SIZE == pqsig::SIG_SIZE);

inline constexpr uint32_t WOTS_COUNT_MAX{4096};

inline constexpr uint32_t BENCH_VERIFY_COMPRESSIONS{1292};
inline constexpr uint32_t BENCH_SIGN_HASHES{6027717};
inline constexpr uint32_t BENCH_SIGN_COMPRESSIONS{6869634};
inline constexpr uint32_t BENCH_SIGN_OUTER_SEARCH{244170};

} // namespace params
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_PARAMS_H
