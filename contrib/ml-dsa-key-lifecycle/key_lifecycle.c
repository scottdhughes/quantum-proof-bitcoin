// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "key_lifecycle.h"

#include <stdlib.h>

/* Keep the reviewed wrapper and portable capsule byte-identical. The new
 * library's export allowlist hides the inherited raw-key interface. */
#include "../ml-dsa-engineering/pqbtc_mldsa44.c"

struct pqbtc_mldsa44_key {
    uint8_t seed[PQBTC_MLDSA44_KEY_SEED_BYTES];
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
};

static uint8_t g_last_key_seed_digest[32];
static int g_has_key_seed_digest;

#ifdef PQBTC_MLDSA44_TESTING
#include "key_lifecycle_test.h"
static atomic_int g_fail_key_allocation;
static atomic_int g_fail_keygen;
static atomic_size_t g_key_releases;
static atomic_int g_key_release_zero;
static atomic_int g_key_seed_zero;
#endif

static void DestroyAllocation(struct pqbtc_mldsa44_key* key)
{
    pqbtc_mldsa44_zeroize(key, sizeof(*key));
#ifdef PQBTC_MLDSA44_TESTING
    atomic_store_explicit(&g_key_release_zero,
        ConstantTimeAllZero((const uint8_t*)key, sizeof(*key)), memory_order_relaxed);
    atomic_fetch_add_explicit(&g_key_releases, 1, memory_order_relaxed);
#endif
    free(key);
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
    if (*out != NULL) return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    if (!SigningForkLifecycleReady()) return PQBTC_MLDSA44_ERR_FORK_LIFECYCLE;
#ifdef PQBTC_MLDSA44_TESTING
    if (atomic_load_explicit(&g_fail_key_allocation, memory_order_relaxed)) {
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
#endif
    key = (struct pqbtc_mldsa44_key*)calloc(1, sizeof(*key));
    if (key == NULL) return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
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
    if (owner != NULL && *owner != NULL) {
        DestroyAllocation(*owner);
        *owner = NULL;
    }
}

static int InvalidOwnedOutput(const struct pqbtc_mldsa44_key* key,
    const uint8_t* output, size_t size, size_t expected)
{
    return key == NULL || output == NULL || size != expected ||
        RangesOverlap(output, size, (const uint8_t*)key, sizeof(*key));
}

int pqbtc_mldsa44_key_public(const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t size)
{
    if (InvalidOwnedOutput(key, output, size, PQBTC_MLDSA44_PUBLIC_KEY_BYTES)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    memcpy(output, key->public_key, size);
    return PQBTC_MLDSA44_OK;
}
int pqbtc_mldsa44_key_export_seed(const struct pqbtc_mldsa44_key* key, uint8_t* output, size_t size)
{
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
    if (key != NULL && sig != NULL &&
        RangesOverlap(sig, sig_size, (const uint8_t*)key, sizeof(*key))) {
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
    uint8_t seed[PQBTC_MLDSA44_KEY_SEED_BYTES] = {0};
    uint8_t digest[32] = {0};
    size_t received = 0;
    int result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
    if (out == NULL || *out != NULL) return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    if (!SigningForkLifecycleReady()) return PQBTC_MLDSA44_ERR_FORK_LIFECYCLE;
    LockSigningModule();
    if (FillEntropy(seed, sizeof(seed), &received) != 0) goto unlock;
    if (received != sizeof(seed)) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_LENGTH;
        goto unlock;
    }
    if (ConstantTimeAllZero(seed, sizeof(seed))) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO;
        goto unlock;
    }
    pqbtc_mldsa44_upstream_shake256(digest, sizeof(digest), seed, sizeof(seed));
    if (g_has_key_seed_digest &&
        ConstantTimeEqual(digest, g_last_key_seed_digest, sizeof(digest))) {
        result = PQBTC_MLDSA44_ERR_ENTROPY_REPEAT;
        goto unlock;
    }
    memcpy(g_last_key_seed_digest, digest, sizeof(digest));
    g_has_key_seed_digest = 1;
    result = PQBTC_MLDSA44_OK;
unlock:
    UnlockSigningModule();
    if (result == PQBTC_MLDSA44_OK) {
        result = pqbtc_mldsa44_key_import_seed(out, seed, sizeof(seed));
    }
    pqbtc_mldsa44_zeroize(seed, sizeof(seed));
    pqbtc_mldsa44_zeroize(digest, sizeof(digest));
#ifdef PQBTC_MLDSA44_TESTING
    atomic_store_explicit(&g_key_seed_zero,
        ConstantTimeAllZero(seed, sizeof(seed)), memory_order_relaxed);
#endif
    return result;
}
#ifdef PQBTC_MLDSA44_TESTING
void pqbtc_mldsa44_key_test_reset(void)
{
    pqbtc_mldsa44_test_reset();
    LockSigningModule();
    pqbtc_mldsa44_zeroize(g_last_key_seed_digest, sizeof(g_last_key_seed_digest));
    g_has_key_seed_digest = 0;
    atomic_store_explicit(&g_fail_key_allocation, 0, memory_order_relaxed);
    atomic_store_explicit(&g_fail_keygen, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_releases, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_release_zero, 0, memory_order_relaxed);
    atomic_store_explicit(&g_key_seed_zero, 0, memory_order_relaxed);
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
int pqbtc_mldsa44_key_test_release_zero(void)
{
    return atomic_load_explicit(&g_key_release_zero, memory_order_relaxed);
}
int pqbtc_mldsa44_key_test_seed_zero(void)
{
    return atomic_load_explicit(&g_key_seed_zero, memory_order_relaxed);
}
#endif
