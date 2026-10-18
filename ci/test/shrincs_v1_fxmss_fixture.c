/* SPDX-License-Identifier: MIT
 * Test-only FXMSS boundary fixture. The message digest is fixed to zero;
 * WOTS+C recovery and every Merkle hash use the real pinned native library.
 * These are synthetic component tests, NOT valid full-SHRINCS signing KATs.
 */
#include <sha256.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void pqbtc_fixture_message_sha256(uint8_t out[restrict 32],
                                const uint8_t *restrict input, size_t length)
{
    (void)input;
    (void)length;
    memset(out, 0, 32);
}

#define shrincs_sha256 pqbtc_fixture_message_sha256
#include "../../contrib/shrincs-ref/stateful_verify.c"
#undef shrincs_sha256
