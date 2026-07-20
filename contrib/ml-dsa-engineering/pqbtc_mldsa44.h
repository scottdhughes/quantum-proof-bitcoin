// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_H
#define BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define PQBTC_MLDSA44_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define PQBTC_MLDSA44_API __attribute__((visibility("default")))
#else
#define PQBTC_MLDSA44_API
#endif

#define PQBTC_MLDSA44_PUBLIC_KEY_BYTES 1312U
#define PQBTC_MLDSA44_SECRET_KEY_BYTES 2560U
#define PQBTC_MLDSA44_SIGNATURE_BYTES 2420U
#define PQBTC_MLDSA44_RANDOMIZER_BYTES 32U
#define PQBTC_MLDSA44_MAX_CONTEXT_BYTES 255U

enum pqbtc_mldsa44_result {
    PQBTC_MLDSA44_OK = 0,
    PQBTC_MLDSA44_ERR_INVALID_ARGUMENT = -1,
    PQBTC_MLDSA44_ERR_ENTROPY_SOURCE = -2,
    PQBTC_MLDSA44_ERR_ENTROPY_LENGTH = -3,
    PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO = -4,
    PQBTC_MLDSA44_ERR_ENTROPY_REPEAT = -5,
    PQBTC_MLDSA44_ERR_BACKEND = -6,
    PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED = -7,
    PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH = -8,
    PQBTC_MLDSA44_ERR_VERIFY = -9
};

/*
 * Produce a pure ML-DSA-44 signature using fresh module-owned randomness.
 * The output buffer is released only after strict self-verification. Once an
 * exact, non-overlapping output buffer is accepted, every later failure zeros
 * that complete buffer. Overlapping output is rejected without writing it.
 */
PQBTC_MLDSA44_API int pqbtc_mldsa44_sign_hedged(
    uint8_t* signature,
    size_t signature_size,
    const uint8_t* secret_key,
    size_t secret_key_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size);

/* Return PQBTC_MLDSA44_OK only for an exact, canonical valid signature. */
PQBTC_MLDSA44_API int pqbtc_mldsa44_verify_strict(
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_H
