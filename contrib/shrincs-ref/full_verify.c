/* SPDX-License-Identifier: MIT
 *
 * Strict dual-mode research verifier for the pinned current SHRINCS draft.
 * Consensus-disabled. Not a production backend.
 */

#include <stddef.h>
#include <stdint.h>

#define PQBTC_SHRINCS_PUBLIC_KEY_BYTES 48U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_BYTES_MIN 548U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_BYTES_MAX 4619U
#define PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES 5777U
#define PQBTC_SHRINCS_NODE_BYTES 16U
#define PQBTC_SHRINCS_MAX_MESSAGE_BYTES 4096U
#define PQBTC_SHRINCS_MAX_CONTEXT_BYTES 255U

int pqbtc_shrincs_stateful_verify(const uint8_t *public_key,
                                  size_t public_key_len,
                                  const uint8_t *signature,
                                  size_t signature_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  const uint8_t *context,
                                  size_t context_len);

int pqbtc_shrincs_stateless_verify(const uint8_t *public_key,
                                   size_t public_key_len,
                                   const uint8_t *signature,
                                   size_t signature_len,
                                   const uint8_t *message,
                                   size_t message_len,
                                   const uint8_t *context,
                                   size_t context_len);

static int is_canonical_stateful_signature(const uint8_t *signature, size_t signature_len)
{
    size_t depth;
    size_t index_bytes;
    if (signature_len < PQBTC_SHRINCS_STATEFUL_SIGNATURE_BYTES_MIN ||
        signature_len > PQBTC_SHRINCS_STATEFUL_SIGNATURE_BYTES_MAX) {
        return 0;
    }
    if (signature[0] == 255U) {
        return 0;
    }
    depth = 255U - signature[0];
    index_bytes = ((depth < 64U ? depth : 64U) + 7U) / 8U;
    return signature_len == 17U + index_bytes + 514U + depth * PQBTC_SHRINCS_NODE_BYTES;
}

/*
 * Return values intentionally remain boolean for this research ABI:
 *   1: valid current-draft SHRINCS signature
 *   0: malformed, unsupported, or cryptographically invalid
 *
 * The indicator selects the mode and determines the exact canonical length.
 * Malformed headers fail closed before either cryptographic verifier is entered.
 */
int pqbtc_shrincs_verify(const uint8_t *public_key,
                         size_t public_key_len,
                         const uint8_t *signature,
                         size_t signature_len,
                         const uint8_t *message,
                         size_t message_len,
                         const uint8_t *context,
                         size_t context_len)
{
    if (public_key == NULL || signature == NULL) {
        return 0;
    }
    if (public_key_len != PQBTC_SHRINCS_PUBLIC_KEY_BYTES) {
        return 0;
    }
    if (message_len > PQBTC_SHRINCS_MAX_MESSAGE_BYTES ||
        context_len > PQBTC_SHRINCS_MAX_CONTEXT_BYTES) {
        return 0;
    }
    if ((message_len > 0U && message == NULL) ||
        (context_len > 0U && context == NULL)) {
        return 0;
    }

    if (signature_len == 0U) {
        return 0;
    }
    if (signature[0] == 255U && signature_len == PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES) {
        return pqbtc_shrincs_stateless_verify(public_key,
                                              public_key_len,
                                              signature,
                                              signature_len,
                                              message,
                                              message_len,
                                              context,
                                              context_len);
    }

    if (is_canonical_stateful_signature(signature, signature_len)) {
        return pqbtc_shrincs_stateful_verify(public_key,
                                             public_key_len,
                                             signature,
                                             signature_len,
                                             message,
                                             message_len,
                                             context,
                                             context_len);
    }

    return 0;
}
