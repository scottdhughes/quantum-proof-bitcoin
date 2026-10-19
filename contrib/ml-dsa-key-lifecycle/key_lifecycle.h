// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_H
#define BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define PQBTC_MLDSA44_KEY_API __attribute__((visibility("default")))
#else
#define PQBTC_MLDSA44_KEY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PQBTC_MLDSA44_KEY_SEED_BYTES 32U
#define PQBTC_MLDSA44_KEY_PUBLIC_BYTES 1312U
#define PQBTC_MLDSA44_KEY_SIGNATURE_BYTES 2420U

struct pqbtc_mldsa44_key;

enum pqbtc_mldsa44_key_result {
    PQBTC_MLDSA44_KEY_OK = 0,
    PQBTC_MLDSA44_KEY_ERR_INVALID_ARGUMENT = -1,
    PQBTC_MLDSA44_KEY_ERR_ALLOCATION = -11
};

/* Readiness prototype only. Other negative codes retain the held wrapper's
 * failure taxonomy. Constructors require a valid initially-NULL owner.
 * Do not copy ownership or race destruction with any borrowed use. */
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_generate(struct pqbtc_mldsa44_key** out);
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_import_seed(
    struct pqbtc_mldsa44_key** out, const uint8_t* seed, size_t seed_size);
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_public(
    const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t output_size);
/* Explicit sensitive copy: caller owns and must erase the returned seed. */
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_export_seed(
    const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t output_size);
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_sign_hedged(
    const struct pqbtc_mldsa44_key* key, uint8_t* signature, size_t signature_size,
    const uint8_t* message, size_t message_size, const uint8_t* context, size_t context_size);
PQBTC_MLDSA44_KEY_API int pqbtc_mldsa44_key_verify_strict(
    const uint8_t* signature, size_t signature_size, const uint8_t* public_key,
    size_t public_key_size, const uint8_t* message, size_t message_size,
    const uint8_t* context, size_t context_size);
PQBTC_MLDSA44_KEY_API void pqbtc_mldsa44_key_destroy(struct pqbtc_mldsa44_key** owner);

#ifdef __cplusplus
} // extern "C"
#endif
#endif // BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_H
