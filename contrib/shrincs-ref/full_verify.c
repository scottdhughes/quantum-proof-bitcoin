/* SPDX-License-Identifier: MIT
 *
 * Strict research envelope for both verification modes of the pinned SHRINCS
 * draft. This file is consensus-disabled and not a production backend.
 */

#include <stddef.h>
#include <stdint.h>

#define PQBTC_SHRINCS_PUBLIC_KEY_BYTES 48U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_BASE_BYTES 538U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_MIN_BYTES 554U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_MAX_BYTES 4618U
#define PQBTC_SHRINCS_STATEFUL_SIGNATURE_STEP_BYTES 16U
#define PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES 5776U

#define PQBTC_SHRINCS_MODE_INVALID 0U
#define PQBTC_SHRINCS_MODE_STATEFUL 1U
#define PQBTC_SHRINCS_MODE_STATELESS 2U

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

uint32_t pqbtc_shrincs_signature_mode(size_t signature_len)
{
    if (signature_len == PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES) {
        return PQBTC_SHRINCS_MODE_STATELESS;
    }
    if (signature_len < PQBTC_SHRINCS_STATEFUL_SIGNATURE_MIN_BYTES ||
        signature_len > PQBTC_SHRINCS_STATEFUL_SIGNATURE_MAX_BYTES) {
        return PQBTC_SHRINCS_MODE_INVALID;
    }
    if ((signature_len - PQBTC_SHRINCS_STATEFUL_SIGNATURE_BASE_BYTES) %
            PQBTC_SHRINCS_STATEFUL_SIGNATURE_STEP_BYTES !=
        0U) {
        return PQBTC_SHRINCS_MODE_INVALID;
    }
    return PQBTC_SHRINCS_MODE_STATEFUL;
}

/* Returns 1 only for a valid signature in one of the two canonical modes of
 * the pinned SHRINCS profile. Unknown lengths fail before cryptographic work.
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
    uint32_t mode;

    if (public_key == NULL || signature == NULL ||
        public_key_len != PQBTC_SHRINCS_PUBLIC_KEY_BYTES) {
        return 0;
    }

    mode = pqbtc_shrincs_signature_mode(signature_len);
    if (mode == PQBTC_SHRINCS_MODE_STATEFUL) {
        return pqbtc_shrincs_stateful_verify(public_key,
                                             public_key_len,
                                             signature,
                                             signature_len,
                                             message,
                                             message_len,
                                             context,
                                             context_len);
    }
    if (mode == PQBTC_SHRINCS_MODE_STATELESS) {
        return pqbtc_shrincs_stateless_verify(public_key,
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
