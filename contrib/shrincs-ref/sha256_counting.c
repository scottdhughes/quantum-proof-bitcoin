/* SPDX-License-Identifier: MIT
 *
 * Research-only SHA-256 compression counter for the pinned SHRINCS verifier.
 * The upstream one-shot implementation is compiled with
 * shrincs_sha256 renamed to shrincs_sha256_real; this file exposes the normal
 * symbol and counts the exact number of 64-byte compression blocks requested.
 */

#include <sha256.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert(SHRINCS_SHA256_BLOCK_BYTES == 64, "resource model assumes 64-byte SHA-256 blocks");

static uint64_t g_sha256_calls;
static uint64_t g_sha256_compressions;

void shrincs_sha256_real(uint8_t out[SHRINCS_SHA256_DIGEST_BYTES],
                         const uint8_t *in,
                         size_t inlen);

void pqbtc_shrincs_resource_reset_sha256(void)
{
    g_sha256_calls = 0;
    g_sha256_compressions = 0;
}

uint64_t pqbtc_shrincs_resource_sha256_calls(void)
{
    return g_sha256_calls;
}

uint64_t pqbtc_shrincs_resource_sha256_compressions(void)
{
    return g_sha256_compressions;
}

void shrincs_sha256(uint8_t out[SHRINCS_SHA256_DIGEST_BYTES],
                    const uint8_t *in,
                    size_t inlen)
{
    size_t full = inlen / SHRINCS_SHA256_BLOCK_BYTES;
    size_t remainder = inlen % SHRINCS_SHA256_BLOCK_BYTES;
    uint64_t padding_blocks = remainder < 56U ? 1U : 2U;

    g_sha256_calls += 1U;
    g_sha256_compressions += (uint64_t)full + padding_blocks;
    shrincs_sha256_real(out, in, inlen);
}
