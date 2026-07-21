// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "pqbtc_mldsa44.h"

#ifdef PQBTC_MLDSA44_TESTING
#include "pqbtc_mldsa44_test.h"
#endif

#include <stdatomic.h>
#include <string.h>

#ifdef PQBTC_MLDSA44_CT_TESTING
#include <valgrind/memcheck.h>
#define PQBTC_MLDSA44_CT_SECRET(ptr, len) \
    VALGRIND_MAKE_MEM_UNDEFINED((ptr), (len))
#define PQBTC_MLDSA44_CT_DECLASSIFY(ptr, len) \
    VALGRIND_MAKE_MEM_DEFINED((ptr), (len))
#else
#define PQBTC_MLDSA44_CT_SECRET(ptr, len) \
    do {                                    \
    } while (0)
#define PQBTC_MLDSA44_CT_DECLASSIFY(ptr, len) \
    do {                                        \
    } while (0)
#endif

#if defined(_WIN32) && !defined(PQBTC_MLDSA44_TESTING)
#include <bcrypt.h>
#elif !defined(PQBTC_MLDSA44_TESTING)
#include <sys/random.h>
#endif

static void pqbtc_mldsa44_zeroize(void* ptr, size_t len);
static int pqbtc_mldsa44_randombytes(uint8_t* ptr, size_t len);

#define MLD_CONFIG_FILE "pqbtc_mldsa44_config.h"
#include "vendor/mldsa-native/mldsa/mldsa_native.h"

enum {
    PQBTC_MLDSA44_UPSTREAM_ERR_RNG_FAIL = MLD_ERR_RNG_FAIL,
    PQBTC_MLDSA44_UPSTREAM_ERR_SIGN_ATTEMPTS_EXHAUSTED =
        MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED
};

#include "vendor/mldsa-native/mldsa/mldsa_native.c"

static atomic_flag g_sign_lock = ATOMIC_FLAG_INIT;
static uint8_t g_last_randomizer_digest[32];
static int g_has_last_randomizer_digest;
static int g_entropy_active;
static int g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;

#ifdef PQBTC_MLDSA44_TESTING
static int g_test_entropy_mode = PQBTC_MLDSA44_TEST_ENTROPY_UNAVAILABLE;
static uint8_t g_test_entropy[PQBTC_MLDSA44_RANDOMIZER_BYTES];
static size_t g_test_entropy_size;
static int g_test_backend_result;
static int g_test_force_signature_length;
static int g_test_force_verify_failure;
static atomic_size_t g_test_zeroized_bytes;
#endif

static void LockSigningModule(void)
{
    while (atomic_flag_test_and_set_explicit(&g_sign_lock, memory_order_acquire)) {
    }
}

static void UnlockSigningModule(void)
{
    atomic_flag_clear_explicit(&g_sign_lock, memory_order_release);
}

static void pqbtc_mldsa44_zeroize(void* ptr, size_t len)
{
#ifdef PQBTC_MLDSA44_TESTING
    const size_t original_len = len;
#endif
    volatile uint8_t* cursor = (volatile uint8_t*)ptr;
    while (len-- > 0) {
        *cursor++ = 0;
    }
#ifdef PQBTC_MLDSA44_TESTING
    atomic_fetch_add_explicit(&g_test_zeroized_bytes, original_len, memory_order_relaxed);
#endif
}

static int ConstantTimeAllZero(const uint8_t* bytes, size_t len)
{
    uint8_t aggregate = 0;
    size_t i;
    for (i = 0; i < len; ++i)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static int ConstantTimeEqual(const uint8_t* left, const uint8_t* right, size_t len)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < len; ++i)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static int FillEntropy(uint8_t* output, size_t requested, size_t* received)
{
#ifdef PQBTC_MLDSA44_TESTING
    if (g_test_entropy_mode == PQBTC_MLDSA44_TEST_ENTROPY_FAILURE) {
        *received = 0;
        return -1;
    }
    if (g_test_entropy_mode != PQBTC_MLDSA44_TEST_ENTROPY_FIXED) {
        *received = 0;
        return -1;
    }
    *received = g_test_entropy_size;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    if (*received <= requested) memcpy(output, g_test_entropy, *received);
    return 0;
#elif defined(_WIN32)
    if (requested > 0xffffffffU ||
        BCryptGenRandom(NULL, output, (ULONG)requested, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        *received = 0;
        return -1;
    }
    *received = requested;
    return 0;
#elif defined(__APPLE__) || defined(__linux__)
    if (getentropy(output, requested) != 0) {
        *received = 0;
        return -1;
    }
    *received = requested;
    return 0;
#else
#error Unsupported prototype entropy platform
#endif
}

static int pqbtc_mldsa44_randombytes(uint8_t* ptr, size_t len)
{
    uint8_t digest[32] = {0};
    size_t received = 0;
    int all_zero;

    if (!g_entropy_active || ptr == NULL || len != PQBTC_MLDSA44_RANDOMIZER_BYTES) {
        g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_LENGTH;
        if (ptr != NULL) pqbtc_mldsa44_zeroize(ptr, len);
        return -1;
    }

    pqbtc_mldsa44_zeroize(ptr, len);
    if (FillEntropy(ptr, len, &received) != 0) {
        g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
        return -1;
    }

    // PQBTC_CT_SECRET: generated_randomizer
    PQBTC_MLDSA44_CT_SECRET(ptr, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    if (received != len) {
        pqbtc_mldsa44_zeroize(ptr, len);
        g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_LENGTH;
        return -1;
    }

    all_zero = ConstantTimeAllZero(ptr, len);
    // PQBTC_CT_DECLASSIFICATION: randomizer_all_zero_predicate
    PQBTC_MLDSA44_CT_DECLASSIFY(&all_zero, sizeof(all_zero));
    if (all_zero) {
        pqbtc_mldsa44_zeroize(ptr, len);
        g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO;
        return -1;
    }

    pqbtc_mldsa44_upstream_shake256(digest, sizeof(digest), ptr, len);
    if (g_has_last_randomizer_digest) {
        int repeated =
            ConstantTimeEqual(digest, g_last_randomizer_digest, sizeof(digest));
        // PQBTC_CT_DECLASSIFICATION: immediate_repeat_predicate
        PQBTC_MLDSA44_CT_DECLASSIFY(&repeated, sizeof(repeated));
        if (repeated) {
            pqbtc_mldsa44_zeroize(digest, sizeof(digest));
            pqbtc_mldsa44_zeroize(ptr, len);
            g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_REPEAT;
            return -1;
        }
    }

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(g_last_randomizer_digest, digest, sizeof(digest));
    g_has_last_randomizer_digest = 1;
    pqbtc_mldsa44_zeroize(digest, sizeof(digest));
    g_entropy_result = PQBTC_MLDSA44_OK;
    return 0;
}

static int InvalidByteString(const uint8_t* value, size_t size)
{
    return size != 0 && value == NULL;
}

static int RangesOverlap(
    const uint8_t* left, size_t left_size, const uint8_t* right, size_t right_size)
{
    const uintptr_t left_start = (uintptr_t)left;
    const uintptr_t right_start = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_size == 0 || right_size == 0) return 0;
    if (left_start > UINTPTR_MAX - left_size || right_start > UINTPTR_MAX - right_size) {
        return 1;
    }
    left_end = left_start + left_size;
    right_end = right_start + right_size;
    return left_start < right_end && right_start < left_end;
}

int pqbtc_mldsa44_sign_hedged(
    uint8_t* signature,
    size_t signature_size,
    const uint8_t* secret_key,
    size_t secret_key_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size)
{
    uint8_t candidate[PQBTC_MLDSA44_SIGNATURE_BYTES] = {0};
    size_t candidate_size = 0;
    int backend_result;
    int result = PQBTC_MLDSA44_ERR_BACKEND;

    if (signature == NULL || signature_size != PQBTC_MLDSA44_SIGNATURE_BYTES) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    if ((secret_key != NULL &&
         RangesOverlap(
             signature,
             signature_size,
             secret_key,
             PQBTC_MLDSA44_SECRET_KEY_BYTES)) ||
        (public_key != NULL &&
         RangesOverlap(
             signature,
             signature_size,
             public_key,
             PQBTC_MLDSA44_PUBLIC_KEY_BYTES)) ||
        (message != NULL &&
         RangesOverlap(signature, signature_size, message, message_size)) ||
        (context != NULL &&
         RangesOverlap(signature, signature_size, context, context_size))) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    if (secret_key == NULL || secret_key_size != PQBTC_MLDSA44_SECRET_KEY_BYTES ||
        public_key == NULL || public_key_size != PQBTC_MLDSA44_PUBLIC_KEY_BYTES ||
        InvalidByteString(message, message_size) ||
        InvalidByteString(context, context_size) ||
        context_size > PQBTC_MLDSA44_MAX_CONTEXT_BYTES) {
        pqbtc_mldsa44_zeroize(signature, signature_size);
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    pqbtc_mldsa44_zeroize(signature, signature_size);

    LockSigningModule();
    g_entropy_active = 1;
    g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
    backend_result = pqbtc_mldsa44_upstream_signature(
        candidate, &candidate_size, message, message_size, context, context_size, secret_key);
    g_entropy_active = 0;

#ifdef PQBTC_MLDSA44_TESTING
    if (backend_result == 0 && g_test_backend_result != 0) {
        backend_result = g_test_backend_result;
    }
#endif

    if (backend_result != 0) {
        if (backend_result == PQBTC_MLDSA44_UPSTREAM_ERR_RNG_FAIL) {
            result = g_entropy_result == PQBTC_MLDSA44_OK ? PQBTC_MLDSA44_ERR_ENTROPY_SOURCE : g_entropy_result;
        } else if (backend_result == PQBTC_MLDSA44_UPSTREAM_ERR_SIGN_ATTEMPTS_EXHAUSTED) {
            result = PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED;
        }
        goto cleanup;
    }

#ifdef PQBTC_MLDSA44_TESTING
    if (g_test_force_signature_length) --candidate_size;
#endif
    if (candidate_size != PQBTC_MLDSA44_SIGNATURE_BYTES) {
        result = PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH;
        goto cleanup;
    }

    backend_result = pqbtc_mldsa44_upstream_verify(
        candidate, candidate_size, message, message_size, context, context_size, public_key);
#ifdef PQBTC_MLDSA44_TESTING
    if (g_test_force_verify_failure) backend_result = -1;
#endif
    if (backend_result != 0) {
        result = PQBTC_MLDSA44_ERR_VERIFY;
        goto cleanup;
    }

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(signature, candidate, sizeof(candidate));
    result = PQBTC_MLDSA44_OK;

cleanup:
    g_entropy_active = 0;
    pqbtc_mldsa44_zeroize(candidate, sizeof(candidate));
    UnlockSigningModule();
    return result;
}

int pqbtc_mldsa44_verify_strict(
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size)
{
    if (signature == NULL || signature_size != PQBTC_MLDSA44_SIGNATURE_BYTES ||
        public_key == NULL || public_key_size != PQBTC_MLDSA44_PUBLIC_KEY_BYTES ||
        InvalidByteString(message, message_size) ||
        InvalidByteString(context, context_size) ||
        context_size > PQBTC_MLDSA44_MAX_CONTEXT_BYTES) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    if (pqbtc_mldsa44_upstream_verify(
            signature,
            signature_size,
            message,
            message_size,
            context,
            context_size,
            public_key) != 0) {
        return PQBTC_MLDSA44_ERR_VERIFY;
    }
    return PQBTC_MLDSA44_OK;
}

#ifdef PQBTC_MLDSA44_TESTING
void pqbtc_mldsa44_test_reset(void)
{
    LockSigningModule();
    pqbtc_mldsa44_zeroize(g_last_randomizer_digest, sizeof(g_last_randomizer_digest));
    g_has_last_randomizer_digest = 0;
    g_entropy_active = 0;
    g_entropy_result = PQBTC_MLDSA44_ERR_ENTROPY_SOURCE;
    g_test_entropy_mode = PQBTC_MLDSA44_TEST_ENTROPY_UNAVAILABLE;
    pqbtc_mldsa44_zeroize(g_test_entropy, sizeof(g_test_entropy));
    g_test_entropy_size = 0;
    g_test_backend_result = 0;
    g_test_force_signature_length = 0;
    g_test_force_verify_failure = 0;
    atomic_store_explicit(&g_test_zeroized_bytes, 0, memory_order_relaxed);
    UnlockSigningModule();
}

int pqbtc_mldsa44_test_set_entropy(int mode, const uint8_t* bytes, size_t reported_size)
{
    if (mode < PQBTC_MLDSA44_TEST_ENTROPY_UNAVAILABLE ||
        mode > PQBTC_MLDSA44_TEST_ENTROPY_FAILURE ||
        reported_size > PQBTC_MLDSA44_RANDOMIZER_BYTES ||
        InvalidByteString(bytes, reported_size)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    LockSigningModule();
    pqbtc_mldsa44_zeroize(g_test_entropy, sizeof(g_test_entropy));
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    if (reported_size != 0) memcpy(g_test_entropy, bytes, reported_size);
    g_test_entropy_size = reported_size;
    g_test_entropy_mode = mode;
    UnlockSigningModule();
    return PQBTC_MLDSA44_OK;
}

void pqbtc_mldsa44_test_force_backend_result(int result)
{
    LockSigningModule();
    g_test_backend_result = result;
    UnlockSigningModule();
}

void pqbtc_mldsa44_test_force_signature_length(int enabled)
{
    LockSigningModule();
    g_test_force_signature_length = enabled != 0;
    UnlockSigningModule();
}

void pqbtc_mldsa44_test_force_verify_failure(int enabled)
{
    LockSigningModule();
    g_test_force_verify_failure = enabled != 0;
    UnlockSigningModule();
}

size_t pqbtc_mldsa44_test_zeroized_bytes(void)
{
    return atomic_load_explicit(&g_test_zeroized_bytes, memory_order_relaxed);
}

int pqbtc_mldsa44_test_keypair_from_seed(
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t seed[32])
{
    int result;
    if (public_key == NULL || secret_key == NULL || seed == NULL) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    LockSigningModule();
    result = pqbtc_mldsa44_upstream_keypair_internal(public_key, secret_key, seed);
    if (result != 0) {
        pqbtc_mldsa44_zeroize(public_key, PQBTC_MLDSA44_PUBLIC_KEY_BYTES);
        pqbtc_mldsa44_zeroize(secret_key, PQBTC_MLDSA44_SECRET_KEY_BYTES);
    }
    UnlockSigningModule();
    return result == 0 ? PQBTC_MLDSA44_OK : PQBTC_MLDSA44_ERR_BACKEND;
}

int pqbtc_mldsa44_test_sign_fixed_randomizer(
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES],
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    uint8_t candidate[PQBTC_MLDSA44_SIGNATURE_BYTES] = {0};
    uint8_t prefix[2 + PQBTC_MLDSA44_MAX_CONTEXT_BYTES] = {0};
    size_t candidate_size = 0;
    int backend_result;
    int result = PQBTC_MLDSA44_ERR_BACKEND;

    if (signature == NULL || secret_key == NULL || randomizer == NULL ||
        InvalidByteString(message, message_size) ||
        InvalidByteString(context, context_size) ||
        context_size > PQBTC_MLDSA44_MAX_CONTEXT_BYTES) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    if (RangesOverlap(
            signature,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES) ||
        RangesOverlap(signature, PQBTC_MLDSA44_SIGNATURE_BYTES, message, message_size) ||
        RangesOverlap(signature, PQBTC_MLDSA44_SIGNATURE_BYTES, context, context_size) ||
        RangesOverlap(
            signature,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            randomizer,
            PQBTC_MLDSA44_RANDOMIZER_BYTES)) {
        return PQBTC_MLDSA44_ERR_INVALID_ARGUMENT;
    }
    pqbtc_mldsa44_zeroize(signature, PQBTC_MLDSA44_SIGNATURE_BYTES);
    prefix[0] = 0;
    prefix[1] = (uint8_t)context_size;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    if (context_size != 0) memcpy(prefix + 2, context, context_size);

    LockSigningModule();
    backend_result = pqbtc_mldsa44_upstream_signature_internal(
        candidate,
        &candidate_size,
        message,
        message_size,
        prefix,
        context_size + 2,
        randomizer,
        secret_key,
        0);
    if (backend_result == 0 && candidate_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        memcpy(signature, candidate, sizeof(candidate));
        result = PQBTC_MLDSA44_OK;
    } else if (backend_result == PQBTC_MLDSA44_UPSTREAM_ERR_SIGN_ATTEMPTS_EXHAUSTED) {
        result = PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED;
    } else if (backend_result == 0) {
        result = PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH;
    }
    pqbtc_mldsa44_zeroize(prefix, sizeof(prefix));
    pqbtc_mldsa44_zeroize(candidate, sizeof(candidate));
    UnlockSigningModule();
    return result;
}
#endif // PQBTC_MLDSA44_TESTING
