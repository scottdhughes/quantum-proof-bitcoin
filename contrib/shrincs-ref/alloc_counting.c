/* SPDX-License-Identifier: MIT
 * Research-only allocation counter for the isolated SHRINCS verifier.
 * Link the shared object with --wrap=malloc,--wrap=free.
 */

#include <stddef.h>
#include <stdint.h>

static uint64_t g_malloc_calls;
static uint64_t g_free_calls;
static uint64_t g_malloc_bytes;
static size_t g_max_request;

void *__real_malloc(size_t size);
void __real_free(void *ptr);

void pqbtc_shrincs_resource_reset_allocations(void)
{
    g_malloc_calls = 0;
    g_free_calls = 0;
    g_malloc_bytes = 0;
    g_max_request = 0;
}

uint64_t pqbtc_shrincs_resource_malloc_calls(void)
{
    return g_malloc_calls;
}

uint64_t pqbtc_shrincs_resource_free_calls(void)
{
    return g_free_calls;
}

uint64_t pqbtc_shrincs_resource_malloc_bytes(void)
{
    return g_malloc_bytes;
}

size_t pqbtc_shrincs_resource_max_malloc_request(void)
{
    return g_max_request;
}

void *__wrap_malloc(size_t size)
{
    g_malloc_calls += 1U;
    g_malloc_bytes += (uint64_t)size;
    if (size > g_max_request) {
        g_max_request = size;
    }
    return __real_malloc(size);
}

void __wrap_free(void *ptr)
{
    g_free_calls += 1U;
    __real_free(ptr);
}
