// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PQSIG_H
#define BITCOIN_CRYPTO_PQSIG_PQSIG_H

#include <crypto/pqsig/pqsig_registry.h>

#include <cstddef>
#include <cstdint>

#include <span.h>

namespace pqsig {

inline constexpr size_t PK_SCRIPT_SIZE{33};
inline constexpr size_t PK_CORE_SIZE{32};
inline constexpr size_t MSG32_SIZE{32};
inline constexpr size_t SIG_SIZE{4480};

static_assert(GetALGIDInfo(ALG_ID_RC2).state == ALGIDState::ACTIVE);
static_assert(GetALGIDInfo(ALG_ID_RC2).pk_script_size == PK_SCRIPT_SIZE);
static_assert(GetALGIDInfo(ALG_ID_RC2).sig_size == SIG_SIZE);

enum class PkScriptParseStatus : uint8_t {
    VALID_ACTIVE,
    INVALID_LENGTH,
    RESERVED_INVALID_ALG_ID,
    ALLOCATED_FUTURE_ALG_ID,
    RETIRED_ALG_ID,
    UNALLOCATED_ALG_ID,
};

PkScriptParseStatus ClassifyPkScript(std::span<const uint8_t> pk_script33);
bool IsValidPkScript(std::span<const uint8_t> pk_script33);
bool DerivePkScript(std::span<uint8_t> out_pk_script33, std::span<const uint8_t> sk_seed);
bool DeriveWalletSkSeed(std::span<uint8_t> out_sk_seed32, std::span<const uint8_t> root_seed, bool internal, uint32_t index);
bool DeriveWalletPkScript(std::span<uint8_t> out_pk_script33, std::span<const uint8_t> root_seed, bool internal, uint32_t index);

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
