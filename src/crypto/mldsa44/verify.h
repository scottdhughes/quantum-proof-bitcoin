// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_VERIFY_H
#define BITCOIN_CRYPTO_MLDSA44_VERIFY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Public-only CONTRACT-1 verifier. Returns1 only for an exact canonical valid
 * signature over a32-byte message in the fixed transaction context; otherwise0.
 * No key generation, entropy, signing or process-policy side effects. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("default")))
#endif
int pqbtc_mldsa44_node_verify(const uint8_t* signature, size_t signature_size,
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* message, size_t message_size);
#ifdef __cplusplus
}
#endif
#endif // BITCOIN_CRYPTO_MLDSA44_VERIFY_H
