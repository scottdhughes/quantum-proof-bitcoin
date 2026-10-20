// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "key_lifecycle.h"

#include <stdlib.h>
#if defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

/* Keep the reviewed wrapper and portable capsule byte-identical. The new
 * library's export allowlist hides the inherited raw-key interface. */
#include "../ml-dsa-engineering/pqbtc_mldsa44.c"

struct pqbtc_mldsa44_key {
    void* mapping;
    size_t mapping_size;
    size_t body_size;
    uint8_t seed[PQBTC_MLDSA44_KEY_SEED_BYTES];
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
};

#ifdef PQBTC_MLDSA44_TESTING
#include "key_lifecycle_test.h"
static atomic_int g_fail_key_allocation;
static atomic_int g_fail_keygen;
static atomic_size_t g_key_releases;
static atomic_int g_key_release_zero;
static atomic_int g_key_generation_scratch_zero;
#endif

#include "key_runtime.c"

int pqbtc_mldsa44_key_runtime_init(void)
{
    return KeyRuntimeInitialize();
}

int pqbtc_mldsa44_key_import_seed(
    struct pqbtc_mldsa44_key** out, const uint8_t* seed, size_t seed_size)
{
    struct pqbtc_mldsa44_key* key;
    int result;
    if (out == NULL || seed == NULL || seed_size != PQBTC_MLDSA44_KEY_SEED_BYTES ||
        RangesOverlap((const uint8_t*)out, sizeof(*out), seed, seed_size)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    result = KeyRuntimeCheck();
    if (result != 0) return result;
    if (*out != NULL) return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    if (!SigningForkLifecycleReady()) return PQBTC_MLDSA44_ERR_FORK_LIFECYCLE;
    result = AllocateKey(&key);
    if (result != 0) return result;
    memcpy(key->seed, seed, seed_size);
    LockSigningModule();
    result = pqbtc_mldsa44_upstream_keypair_internal(key->public_key, key->secret_key, key->seed);
#ifdef PQBTC_MLDSA44_TESTING
    if (atomic_load_explicit(&g_fail_keygen, memory_order_relaxed)) result = -1;
#endif
    UnlockSigningModule();
    if (result != 0) {
        DestroyAllocation(key);
        return PQBTC_MLDSA44_ERR_BACKEND;
    }
    *out = key;
    return PQBTC_MLDSA44_OK;
}

void pqbtc_mldsa44_key_destroy(struct pqbtc_mldsa44_key** owner)
{
    if (!KeyRuntimeOriginalProcess()) {
        if (owner != NULL) *owner = NULL;
        return;
    }
    if (owner != NULL && *owner != NULL) {
        DestroyAllocation(*owner);
        *owner = NULL;
    }
}

static int InvalidOwnedOutput(const struct pqbtc_mldsa44_key* key,
    const uint8_t* output, size_t size, size_t expected)
{
    return key == NULL || output == NULL || size != expected ||
        RangesOverlap(output, size, (const uint8_t*)key, key->body_size);
}

int pqbtc_mldsa44_key_public(const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t size)
{
    const int result = KeyRuntimeCheck();
    if (result != 0) return result;
    if (InvalidOwnedOutput(key, output, size, PQBTC_MLDSA44_PUBLIC_KEY_BYTES)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    memcpy(output, key->public_key, size);
    return PQBTC_MLDSA44_OK;
}
int pqbtc_mldsa44_key_export_seed(const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t size)
{
    const int result = KeyRuntimeCheck();
    if (result != 0) return result;
    if (InvalidOwnedOutput(key, output, size, PQBTC_MLDSA44_KEY_SEED_BYTES)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    memcpy(output, key->seed, size);
    return PQBTC_MLDSA44_OK;
}
int pqbtc_mldsa44_key_sign_hedged(const struct pqbtc_mldsa44_key* key,
    uint8_t* sig, size_t sig_size, const uint8_t* msg, size_t msg_size,
    const uint8_t* ctx, size_t ctx_size)
{
    const int result = KeyRuntimeCheck();
    if (result != 0) return result;
    if (key != NULL && sig != NULL &&
        RangesOverlap(sig, sig_size, (const uint8_t*)key, key->body_size)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    return pqbtc_mldsa44_sign_hedged(sig, sig_size,
        key == NULL ? NULL : key->secret_key, PQBTC_MLDSA44_SECRET_KEY_BYTES,
        key == NULL ? NULL : key->public_key, PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
        msg, msg_size, ctx, ctx_size);
}
int pqbtc_mldsa44_key_verify_strict(const uint8_t* sig, size_t sig_size,
    const uint8_t* pk, size_t pk_size, const uint8_t* msg, size_t msg_size,
    const uint8_t* ctx, size_t ctx_size)
{
    return pqbtc_mldsa44_verify_strict(sig, sig_size, pk, pk_size, msg, msg_size, ctx, ctx_size);
}

int pqbtc_mldsa44_key_generate(struct pqbtc_mldsa44_key** out)
{
    struct pqbtc_mldsa44_key* key;
    uint8_t digest[32] = {0};
    size_t received = 0;
    int result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
    if (out == NULL) return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    result = KeyRuntimeCheck();
    if (result != 0) return result;
    if (*out != NULL) return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    if (!SigningForkLifecycleReady()) return PQBTC_MLDSA44_ERR_FORK_LIFECYCLE;
    result = AllocateKey(&key);
    if (result != 0) return result;
    LockSigningModule();
    result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
    if (FillEntropy(key->seed, sizeof(key->seed), &received) != 0) goto unlock;
    if (received != sizeof(key->seed)) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_LENGTH;
        goto unlock;
    }
    if (ConstantTimeAllZero(key->seed, sizeof(key->seed))) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO;
        goto unlock;
    }
    pqbtc_mldsa44_upstream_shake256(digest, sizeof(digest), key->seed, sizeof(key->seed));
    if (g_has_last_randomizer_digest &&
        ConstantTimeEqual(digest, g_last_randomizer_digest, sizeof(digest))) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_REPEAT;
        goto unlock;
    }
    memcpy(g_last_randomizer_digest, digest, sizeof(digest));
    g_has_last_randomizer_digest = 1;
    result = pqbtc_mldsa44_upstream_keypair_internal(key->public_key, key->secret_key, key->seed);
#ifdef PQBTC_MLDSA44_TESTING
    if (atomic_load_explicit(&g_fail_keygen, memory_order_relaxed)) result = -1;
#endif
    result = result == 0 ? PQBTC_MLDSA44_OK : PQBTC_MLDSA44_ERR_BACKEND;
unlock:
    UnlockSigningModule();
    if (result == PQBTC_MLDSA44_OK) *out = key;
    else DestroyAllocation(key);
    pqbtc_mldsa44_zeroize(digest, sizeof(digest));
#ifdef PQBTC_MLDSA44_TESTING
    atomic_store_explicit(&g_key_generation_scratch_zero,
        ConstantTimeAllZero(digest, sizeof(digest)), memory_order_relaxed);
#endif
    return result;
}
#ifdef PQBTC_MLDSA44_TESTING
void pqbtc_mldsa44_key_test_reset(void)
{
    pqbtc_mldsa44_test_reset();
    LockSigningModule();
    atomic_store_explicit(&g_fail_key_allocation, 0, memory_order_relaxed);
    atomic_store_explicit(&g_fail_keygen, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_releases, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_release_zero, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_generation_scratch_zero, 0, memory_order_relaxed);
    UnlockSigningModule();
}
void pqbtc_mldsa44_key_test_fail_allocation(int enabled)
{
    atomic_store_explicit(&g_fail_key_allocation, enabled != 0, memory_order_relaxed);
}
void pqbtc_mldsa44_key_test_fail_keygen(int enabled)
{
    atomic_store_explicit(&g_fail_keygen, enabled != 0, memory_order_relaxed);
}
size_t pqbtc_mldsa44_key_test_releases(void)
{
    return atomic_load_explicit(&g_key_releases, memory_order_relaxed);
}
size_t pqbtc_mldsa44_key_test_allocation_size(void)
{
#if defined(__linux__)
    size_t body = 0, total = 0;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || KeyPageLayout(sizeof(struct pqbtc_mldsa44_key), (size_t)page, &body, &total) != 0) return 0;
    return body;
#else
    return 0;
#endif
}
int pqbtc_mldsa44_key_test_release_zero(void)
{
    return atomic_load_explicit(&g_key_release_zero, memory_order_relaxed);
}
int pqbtc_mldsa44_key_test_generation_scratch_zero(void)
{
    return atomic_load_explicit(&g_key_generation_scratch_zero, memory_order_relaxed);
}
#endif
