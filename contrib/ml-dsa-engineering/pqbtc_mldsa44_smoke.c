// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44_test.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                              \
    do {                                                              \
        if (!(condition)) {                                           \
            fprintf(stderr, "wrapper smoke failure at line %d: %s\n", \
                    __LINE__, #condition);                            \
            return 1;                                                 \
        }                                                             \
    } while (0)

static const uint8_t TEST_SEED[32] = {
    0xd7,
    0x13,
    0x61,
    0xc0,
    0x00,
    0xf9,
    0xa7,
    0xbc,
    0x99,
    0xdf,
    0xb4,
    0x25,
    0xbc,
    0xb6,
    0xbb,
    0x27,
    0xc3,
    0x2c,
    0x36,
    0xab,
    0x44,
    0x4f,
    0xf3,
    0x70,
    0x8b,
    0x2d,
    0x93,
    0xb4,
    0xe6,
    0x6d,
    0x5b,
    0x5b,
};

static int IsZero(const uint8_t* bytes, size_t size)
{
    uint8_t aggregate = 0;
    size_t i;
    for (i = 0; i < size; ++i)
        aggregate |= bytes[i];
    return aggregate == 0;
}

struct thread_case {
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    const uint8_t* secret_key;
    const uint8_t* public_key;
    const uint8_t* message;
    size_t message_size;
    const uint8_t* context;
    size_t context_size;
    int result;
};

static void* SignThread(void* opaque)
{
    struct thread_case* test = (struct thread_case*)opaque;
    test->result = pqbtc_mldsa44_sign_hedged(
        test->signature,
        sizeof(test->signature),
        test->secret_key,
        PQBTC_MLDSA44_SECRET_KEY_BYTES,
        test->public_key,
        PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
        test->message,
        test->message_size,
        test->context,
        test->context_size);
    return NULL;
}

static int SetFixedEntropy(const uint8_t bytes[32], size_t reported_size)
{
    return pqbtc_mldsa44_test_set_entropy(
        PQBTC_MLDSA44_TEST_ENTROPY_FIXED, bytes, reported_size);
}

int main(void)
{
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t secret_key_copy[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t message[32];
    const uint8_t context[] = "PQBTC/tx-signature/v1";
    uint8_t randomizer[32];
    uint8_t zero_randomizer[32] = {0};
    uint8_t long_context[256] = {0};
    size_t i;

    for (i = 0; i < sizeof(message); ++i)
        message[i] = (uint8_t)i;
    for (i = 0; i < sizeof(randomizer); ++i)
        randomizer[i] = (uint8_t)(i + 1);

    pqbtc_mldsa44_test_reset();
    CHECK(pqbtc_mldsa44_test_keypair_from_seed(public_key, secret_key, TEST_SEED) ==
          PQBTC_MLDSA44_OK);
    memcpy(secret_key_copy, secret_key, sizeof(secret_key_copy));
    CHECK(pqbtc_mldsa44_sign_hedged(
              secret_key,
              PQBTC_MLDSA44_SIGNATURE_BYTES,
              secret_key,
              sizeof(secret_key),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(memcmp(secret_key, secret_key_copy, sizeof(secret_key)) == 0);
    CHECK(pqbtc_mldsa44_sign_hedged(
              secret_key,
              PQBTC_MLDSA44_SIGNATURE_BYTES,
              secret_key,
              sizeof(secret_key),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              long_context,
              sizeof(long_context)) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(memcmp(secret_key, secret_key_copy, sizeof(secret_key)) == 0);
    CHECK(pqbtc_mldsa44_test_sign_fixed_randomizer(
              signature,
              secret_key,
              message,
              sizeof(message),
              context,
              sizeof(context) - 1,
              zero_randomizer) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_verify_strict(
              signature,
              sizeof(signature),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_OK);
    signature[0] ^= 1;
    CHECK(pqbtc_mldsa44_verify_strict(
              signature,
              sizeof(signature),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_ERR_VERIFY);
    signature[0] ^= 1;

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature,
              sizeof(signature),
              secret_key,
              sizeof(secret_key),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_verify_strict(
              signature,
              sizeof(signature),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature,
              sizeof(signature),
              secret_key,
              sizeof(secret_key),
              public_key,
              sizeof(public_key),
              message,
              sizeof(message),
              context,
              sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_REPEAT);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(pqbtc_mldsa44_test_set_entropy(
              PQBTC_MLDSA44_TEST_ENTROPY_FAILURE, NULL, 0) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_SOURCE);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer) - 1) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_LENGTH);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(zero_randomizer, sizeof(zero_randomizer)) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    pqbtc_mldsa44_test_force_backend_result(-1);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_BACKEND);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    pqbtc_mldsa44_test_force_backend_result(-4);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) ==
          PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    pqbtc_mldsa44_test_force_signature_length(1);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    public_key[0] ^= 1;
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_VERIFY);
    CHECK(IsZero(signature, sizeof(signature)));
    public_key[0] ^= 1;

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    pqbtc_mldsa44_test_force_verify_failure(1);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_ERR_VERIFY);
    CHECK(IsZero(signature, sizeof(signature)));

    pqbtc_mldsa44_test_reset();
    CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              long_context, sizeof(long_context)) == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    CHECK(IsZero(signature, sizeof(signature)));
    CHECK(pqbtc_mldsa44_sign_hedged(
              signature, sizeof(signature), secret_key, sizeof(secret_key),
              public_key, sizeof(public_key), message, sizeof(message),
              context, sizeof(context) - 1) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_test_zeroized_bytes() > 0);

    {
        pthread_t threads[2];
        struct thread_case cases[2];
        int successes = 0;
        int repeats = 0;

        pqbtc_mldsa44_test_reset();
        CHECK(SetFixedEntropy(randomizer, sizeof(randomizer)) == PQBTC_MLDSA44_OK);
        memset(cases, 0, sizeof(cases));
        for (i = 0; i < 2; ++i) {
            cases[i].secret_key = secret_key;
            cases[i].public_key = public_key;
            cases[i].message = message;
            cases[i].message_size = sizeof(message);
            cases[i].context = context;
            cases[i].context_size = sizeof(context) - 1;
            CHECK(pthread_create(&threads[i], NULL, SignThread, &cases[i]) == 0);
        }
        for (i = 0; i < 2; ++i) {
            CHECK(pthread_join(threads[i], NULL) == 0);
            successes += cases[i].result == PQBTC_MLDSA44_OK;
            repeats += cases[i].result == PQBTC_MLDSA44_ERR_ENTROPY_REPEAT;
        }
        CHECK(successes == 1);
        CHECK(repeats == 1);
    }

    return 0;
}
