// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.

#ifndef BITCOIN_CRYPTO_MLDSA44_RESOURCE_LIMITS_H
#define BITCOIN_CRYPTO_MLDSA44_RESOURCE_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace pqbtc::mldsa44 {
// Experimental native witness cost, in the existing sigop-cost units (not
// unscaled legacy sigops). Only SCRIPT_VERIFY_MLDSA44 activates this charge.
inline constexpr int64_t VERIFICATION_SIGOPS_COST{625};
inline constexpr size_t MAX_BLOCK_VERIFICATIONS{128};
inline constexpr size_t MAX_STANDARD_TX_VERIFICATIONS{25};
} // namespace pqbtc::mldsa44

#endif // BITCOIN_CRYPTO_MLDSA44_RESOURCE_LIMITS_H
