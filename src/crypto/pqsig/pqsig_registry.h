// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PQSIG_REGISTRY_H
#define BITCOIN_CRYPTO_PQSIG_PQSIG_REGISTRY_H

#include <cstddef>
#include <cstdint>

namespace pqsig {

// This registry is frozen for the current release.
// Only ALG_ID=0x01 (rc2) is ACTIVE. All other ids are invalid.
inline constexpr uint8_t ALG_ID_RC2{0x01};

enum class ALGIDState : uint8_t {
    RESERVED_INVALID,
    ACTIVE,
    ALLOCATED_FUTURE,
    RETIRED,
    UNALLOCATED,
};

struct ALGIDInfo {
    uint8_t alg_id;
    ALGIDState state;
    size_t sig_size;
    size_t pk_script_size;
};

constexpr ALGIDInfo GetALGIDInfo(const uint8_t alg_id)
{
    switch (alg_id) {
    case 0x00:
        return {alg_id, ALGIDState::RESERVED_INVALID, 0, 0};
    case ALG_ID_RC2:
        return {alg_id, ALGIDState::ACTIVE, 4480, 33};
    case 0x02:
        return {alg_id, ALGIDState::ALLOCATED_FUTURE, 4480, 33};
    default:
        return {alg_id, ALGIDState::UNALLOCATED, 0, 0};
    }
}

constexpr bool IsValidALGID(const uint8_t alg_id)
{
    return GetALGIDInfo(alg_id).state == ALGIDState::ACTIVE;
}

} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_PQSIG_REGISTRY_H
