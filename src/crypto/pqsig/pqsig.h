// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PQSIG_H
#define BITCOIN_CRYPTO_PQSIG_PQSIG_H

#include <cstddef>
#include <cstdint>

#include <span.h>

namespace pqsig {

inline constexpr size_t PK_SCRIPT_SIZE{33};
inline constexpr size_t PK_CORE_SIZE{32};
inline constexpr size_t MSG32_SIZE{32};
inline constexpr size_t SIG_SIZE{4480};
inline constexpr uint8_t ALG_ID_V1{0x00};

bool IsValidPkScript(std::span<const uint8_t> pk_script33);

bool PQSigVerify(std::span<const uint8_t> sig4480,
                 std::span<const uint8_t> msg32,
                 std::span<const uint8_t> pk_script33);

bool PQSigSign(std::span<uint8_t> out_sig4480,
               std::span<const uint8_t> msg32,
               std::span<const uint8_t> sk_seed,
               std::span<const uint8_t> pk_script33,
               uint32_t max_counter = 1048576);

} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_PQSIG_H
