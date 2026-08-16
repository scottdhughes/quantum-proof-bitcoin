/* SPDX-License-Identifier: MIT
 *
 * Research-only SHA-256 accounting wrapper. The pinned libshrincs SHA-256
 * implementation is compiled with its public symbol renamed to
 * shrincs_sha256_impl, and this file exposes the counted entry point.
 * Counters are deliberately not thread-safe and are not a consensus API.
 */

#include <sha256.h>

#include <stddef.h>
#include <stdint.h>

static uint64_t g_sha256_calls;
static uint64_t g_sha256_compressions;

void shrincs_sha256_impl(uint8_t out[32], const uint8_t *input, size_t input_len);

static uint64_t compression_count(size_t input_len)
{
    uint64_t blocks = (uint64_t)(input_len / 64U);
    size_t remainder = input_len % 64U;

    /* SHA-256 appends one 0x80 byte and an eight-byte length field. */
    blocks += remainder <= 55U ? 1U : 2U;
    return blocks;
}

void shrincs_sha256(uint8_t out[32], const uint8_t *input, size_t input_len)
{
    ++g_sha256_calls;
    g_sha256_compressions += compression_count(input_len);
    shrincs_sha256_impl(out, input, input_len);
}

void pqbtc_sha256_metrics_reset(void)
{
    g_sha256_calls = 0U;
    g_sha256_compressions = 0U;
}

uint64_t pqbtc_sha256_metrics_calls(void)
{
    return g_sha256_calls;
}

uint64_t pqbtc_sha256_metrics_compressions(void)
{
    return g_sha256_compressions;
}
