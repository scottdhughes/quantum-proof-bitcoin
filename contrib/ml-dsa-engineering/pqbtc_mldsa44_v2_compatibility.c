// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PQBTC_MLDSA44_TESTING
#error The compatibility probe requires the isolated testing build
#endif

void __cyg_profile_func_enter(void*, void*) __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void*, void*) __attribute__((no_instrument_function));

#include "pqbtc_mldsa44.c"

static size_t g_verify_entries;
static int g_forbid_verify_entry;
static unsigned g_checks;

void __cyg_profile_func_enter(void* function, void* caller)
{
    (void)caller;
    if ((uintptr_t)function == (uintptr_t)&pqbtc_mldsa44_upstream_verify) {
        ++g_verify_entries;
        if (g_forbid_verify_entry) {
            fputs("v2 compatibility failure: invalid input reached upstream verifier\n", stderr);
            _Exit(41);
        }
    }
}

void __cyg_profile_func_exit(void* function, void* caller)
{
    (void)function;
    (void)caller;
}

#define CHECK(condition)                                                        \
    do {                                                                        \
        ++g_checks;                                                             \
        if (!(condition)) {                                                     \
            fprintf(stderr, "v2 compatibility failure: line %d: %s\n", __LINE__, \
                #condition);                                                    \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static int AllZero(const uint8_t* bytes, size_t size)
{
    size_t i;
    uint8_t aggregate = 0;
    for (i = 0; i < size; ++i) aggregate |= bytes[i];
    return aggregate == 0;
}

int main(void)
{
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES] = {0};
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES] = {0};
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES] = {0};
    const uint8_t seed[32] = {0}; // Public synthetic fixture, not fresh entropy.
    uint8_t entropy[32] = {1};
    const size_t bad_lengths[] = {0, 1, 2419, 2421, SIZE_MAX};
    const struct {
        int backend;
        int expected;
    } errors[] = {
        {-1, PQBTC_MLDSA44_ERR_BACKEND},
        {-2, PQBTC_MLDSA44_ERR_BACKEND},
        {-3, PQBTC_MLDSA44_ERR_ENTROPY_SOURCE},
        {-4, PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED},
        {-5, PQBTC_MLDSA44_ERR_BACKEND},
        {-6, PQBTC_MLDSA44_ERR_BACKEND},
        {-7, PQBTC_MLDSA44_ERR_BACKEND},
        {-8, PQBTC_MLDSA44_ERR_BACKEND},
        {-9, PQBTC_MLDSA44_ERR_BACKEND},
        {123, PQBTC_MLDSA44_ERR_BACKEND},
    };
    size_t i;

    // Positive instrumentation control: an exact-sized invalid tuple enters
    // the real upstream verifier once and is rejected cryptographically.
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              sizeof(public_key), NULL, 0, NULL, 0) == PQBTC_MLDSA44_ERR_VERIFY);
    CHECK(g_verify_entries == 1);
    g_forbid_verify_entry = 1;
    for (i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i) {
        CHECK(pqbtc_mldsa44_verify_strict(signature, bad_lengths[i], public_key,
                  sizeof(public_key), NULL, 0, NULL, 0) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    }
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              1311, NULL, 0, NULL, 0) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              1313, NULL, 0, NULL, 0) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              sizeof(public_key), NULL, 1, NULL, 0) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              sizeof(public_key), NULL, 0, NULL, 1) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(pqbtc_mldsa44_verify_strict(signature, sizeof(signature), public_key,
              sizeof(public_key), NULL, 0, signature, 256) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(pqbtc_mldsa44_verify_strict(NULL, sizeof(signature), public_key,
              sizeof(public_key), NULL, 0, NULL, 0) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(g_verify_entries == 1);
    g_forbid_verify_entry = 0;

    CHECK(pqbtc_mldsa44_test_keypair_from_seed(public_key, secret_key, seed) == 0);
    // Fault injection follows a real successful signing call. These checks
    // pin the project mapping and accepted-output erasure for every v2 code,
    // including disabled-hook and unknown errors; no signature may escape.
    for (i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        pqbtc_mldsa44_test_reset();
        entropy[0] = (uint8_t)(i + 1);
        CHECK(pqbtc_mldsa44_test_set_entropy(PQBTC_MLDSA44_TEST_ENTROPY_FIXED,
                  entropy, sizeof(entropy)) == 0);
        pqbtc_mldsa44_test_force_backend_result(errors[i].backend);
        memset(signature, 0xa5, sizeof(signature));
        CHECK(pqbtc_mldsa44_sign_hedged(signature, sizeof(signature), secret_key,
                  sizeof(secret_key), public_key, sizeof(public_key), NULL, 0,
                  NULL, 0) == errors[i].expected);
        CHECK(AllZero(signature, sizeof(signature)));
        CHECK(pqbtc_mldsa44_test_last_candidate_zeroized());
    }
    pqbtc_mldsa44_zeroize(secret_key, sizeof(secret_key));
    printf("v2 API compatibility PASS: checks=%u, malformed verifier entries=0\n", g_checks);
    return 0;
}
