// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_SHRINCS_VERIFY_H
#define BITCOIN_CRYPTO_SHRINCS_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify one signature under the frozen PQBTC-SHRINCS-v0 profile.
 *
 * Returns 1 on success and 0 on every malformed, unsupported, or invalid input.
 * The accepted public-key size is exactly 48 bytes. Accepted signatures are
 * the canonical current-profile stateful lengths 538 + 16*d for 1 <= d <= 255
 * or the exact 5,776-byte stateless recovery encoding.
 */
int pqbtc_shrincs_verify(const uint8_t* public_key,
                         size_t public_key_len,
                         const uint8_t* signature,
                         size_t signature_len,
                         const uint8_t* message,
                         size_t message_len,
                         const uint8_t* context,
                         size_t context_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_CRYPTO_SHRINCS_VERIFY_H
