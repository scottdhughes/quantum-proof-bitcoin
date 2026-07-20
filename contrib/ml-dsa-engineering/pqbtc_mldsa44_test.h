// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_TEST_H
#define BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_TEST_H

#include <pqbtc_mldsa44.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pqbtc_mldsa44_test_entropy_mode {
    PQBTC_MLDSA44_TEST_ENTROPY_UNAVAILABLE = 0,
    PQBTC_MLDSA44_TEST_ENTROPY_FIXED = 1,
    PQBTC_MLDSA44_TEST_ENTROPY_FAILURE = 2
};

PQBTC_MLDSA44_API void pqbtc_mldsa44_test_reset(void);
PQBTC_MLDSA44_API int pqbtc_mldsa44_test_set_entropy(
    int mode, const uint8_t* bytes, size_t reported_size);
PQBTC_MLDSA44_API void pqbtc_mldsa44_test_force_backend_result(int result);
PQBTC_MLDSA44_API void pqbtc_mldsa44_test_force_signature_length(int enabled);
PQBTC_MLDSA44_API void pqbtc_mldsa44_test_force_verify_failure(int enabled);
PQBTC_MLDSA44_API size_t pqbtc_mldsa44_test_zeroized_bytes(void);

PQBTC_MLDSA44_API int pqbtc_mldsa44_test_keypair_from_seed(
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t seed[32]);

PQBTC_MLDSA44_API int pqbtc_mldsa44_test_sign_fixed_randomizer(
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES],
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_TEST_H
