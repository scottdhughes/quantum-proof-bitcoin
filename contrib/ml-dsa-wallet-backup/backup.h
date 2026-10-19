// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_ML_DSA_WALLET_BACKUP_H
#define BITCOIN_ML_DSA_WALLET_BACKUP_H
#include "../ml-dsa-key-lifecycle/key_lifecycle.h"
#define PQBTC_BACKUP_BYTES 176U
#define PQBTC_PILOT_INTENT_BYTES 112U
enum pqbtc_backup_result {
    PQBTC_BACKUP_OK = 0,
    PQBTC_BACKUP_INVALID = -1,
    PQBTC_BACKUP_AUTH = -20,
    PQBTC_BACKUP_CRYPTO = -21,
    PQBTC_BACKUP_ENTROPY = -22,
    PQBTC_BACKUP_IO = -23,
    PQBTC_BACKUP_INDETERMINATE = -24
};
/* Experimental isolated pilot, NOT a production wallet format. All pointers
 * must designate accessible storage. Caller serializes key ownership and
 * destruction. No concurrent mutation, stale-pointer or hostile-host guarantee.
 * Password is counted bytes16..1024 (no normalization); caller owns its wipe.
 * Create stages privately; accepted failure clears nonalias package output.
 * Aliased/invalid output is rejected without writing. Restore requires an
 * initiallyNULL owner; failures never publish a provisional/unverified key. */
PQBTC_MLDSA44_KEY_API int pqbtc_backup_create(const struct pqbtc_mldsa44_key*,
    const uint8_t*, size_t, uint8_t*, size_t);
PQBTC_MLDSA44_KEY_API int pqbtc_backup_restore(struct pqbtc_mldsa44_key**,
    const uint8_t*, size_t, const uint8_t*, size_t);
PQBTC_MLDSA44_KEY_API int pqbtc_pilot_intent(uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t challenge[32]);
PQBTC_MLDSA44_KEY_API int pqbtc_pilot_sign(const struct pqbtc_mldsa44_key*,
    uint8_t*, size_t, const uint8_t*, size_t, const uint8_t challenge[32]);
PQBTC_MLDSA44_KEY_API int pqbtc_pilot_verify(const uint8_t*, size_t,
    const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t challenge[32]);
#endif // BITCOIN_ML_DSA_WALLET_BACKUP_H
