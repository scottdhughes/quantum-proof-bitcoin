// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44.h"
#include "pqbtc_mldsa44_test.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CONCURRENT_VERIFY_THREADS 4U
#define CONCURRENT_VERIFY_ITERATIONS 32U
#define TEST_CONTEXT "PQBTC/concurrent-verify/v1"
#define TEST_CONTEXT_BYTES (sizeof(TEST_CONTEXT) - 1U)
#define TEST_MESSAGE_BYTES 32U

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

static int ReportFailure(int line, const char* condition)
{
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    fprintf(stderr, "concurrent verifier failure at line %d: %s\n", line,
            condition);
    return 1;
}

#define CHECK(condition)                                \
    do {                                                \
        if (!(condition)) {                             \
            return ReportFailure(__LINE__, #condition); \
        }                                               \
    } while (0)

struct shared_inputs {
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t rejected_signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t message[TEST_MESSAGE_BYTES];
    uint8_t rejected_message[TEST_MESSAGE_BYTES];
    uint8_t context[TEST_CONTEXT_BYTES];
    uint8_t rejected_context[TEST_CONTEXT_BYTES];
};

struct start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t ready;
    pthread_cond_t start;
    size_t ready_threads;
    int released;
};

struct verify_case {
    struct start_gate* gate;
    const uint8_t* signature;
    const uint8_t* public_key;
    const uint8_t* message;
    const uint8_t* context;
    int expected_result;
    int observed_result;
    size_t completed_iterations;
    int synchronization_result;
};

static int AwaitSynchronizedStart(struct start_gate* gate)
{
    int result = pthread_mutex_lock(&gate->mutex);
    if (result != 0)
        return result;

    ++gate->ready_threads;
    result = pthread_cond_signal(&gate->ready);
    while (result == 0 && !gate->released) {
        result = pthread_cond_wait(&gate->start, &gate->mutex);
    }
    if (pthread_mutex_unlock(&gate->mutex) != 0 && result == 0)
        return -1;
    return result;
}

static void* VerifyThread(void* opaque)
{
    struct verify_case* test = (struct verify_case*)opaque;
    size_t iteration;

    test->synchronization_result = AwaitSynchronizedStart(test->gate);
    if (test->synchronization_result != 0)
        return NULL;

    for (iteration = 0; iteration < CONCURRENT_VERIFY_ITERATIONS; ++iteration) {
        test->observed_result = pqbtc_mldsa44_verify_strict(
            test->signature, PQBTC_MLDSA44_SIGNATURE_BYTES, test->public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES, test->message, TEST_MESSAGE_BYTES,
            test->context, TEST_CONTEXT_BYTES);
        if (test->observed_result != test->expected_result)
            return NULL;
        ++test->completed_iterations;
    }
    return NULL;
}

int main(void)
{
    struct shared_inputs inputs = {0};
    struct shared_inputs original_inputs;
    struct start_gate gate;
    struct verify_case cases[CONCURRENT_VERIFY_THREADS];
    pthread_t threads[CONCURRENT_VERIFY_THREADS];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES];
    size_t i;

    for (i = 0; i < sizeof(inputs.message); ++i) {
        inputs.message[i] = (uint8_t)i;
    }
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(inputs.context, TEST_CONTEXT, sizeof(inputs.context));
    for (i = 0; i < sizeof(randomizer); ++i) {
        randomizer[i] = (uint8_t)(i + 1U);
    }

    CHECK(pqbtc_mldsa44_test_keypair_from_seed(inputs.public_key, secret_key,
                                               TEST_SEED) == PQBTC_MLDSA44_OK);
    CHECK(pqbtc_mldsa44_test_sign_fixed_randomizer(
              inputs.signature, secret_key, inputs.message,
              sizeof(inputs.message), inputs.context, sizeof(inputs.context),
              randomizer) == PQBTC_MLDSA44_OK);

    // All rejection cases retain exact valid lengths and reach cryptographic
    // verification.
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(inputs.rejected_signature, inputs.signature,
           sizeof(inputs.rejected_signature));
    inputs.rejected_signature[0] ^= 1U;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(inputs.rejected_message, inputs.message,
           sizeof(inputs.rejected_message));
    inputs.rejected_message[sizeof(inputs.rejected_message) - 1U] ^= 1U;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(inputs.rejected_context, inputs.context,
           sizeof(inputs.rejected_context));
    inputs.rejected_context[sizeof(inputs.rejected_context) - 1U] ^= 1U;

    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memcpy(&original_inputs, &inputs, sizeof(original_inputs));

    alarm(20);
    CHECK(pthread_mutex_init(&gate.mutex, NULL) == 0);
    CHECK(pthread_cond_init(&gate.ready, NULL) == 0);
    CHECK(pthread_cond_init(&gate.start, NULL) == 0);
    gate.ready_threads = 0;
    gate.released = 0;

    cases[0] = (struct verify_case){
        &gate,
        inputs.signature,
        inputs.public_key,
        inputs.message,
        inputs.context,
        PQBTC_MLDSA44_OK,
        PQBTC_MLDSA44_ERR_INVALID_ARGUMENT,
        0,
        0,
    };
    cases[1] = (struct verify_case){
        &gate,
        inputs.rejected_signature,
        inputs.public_key,
        inputs.message,
        inputs.context,
        PQBTC_MLDSA44_ERR_VERIFY,
        PQBTC_MLDSA44_OK,
        0,
        0,
    };
    cases[2] = (struct verify_case){
        &gate,
        inputs.signature,
        inputs.public_key,
        inputs.rejected_message,
        inputs.context,
        PQBTC_MLDSA44_ERR_VERIFY,
        PQBTC_MLDSA44_OK,
        0,
        0,
    };
    cases[3] = (struct verify_case){
        &gate,
        inputs.signature,
        inputs.public_key,
        inputs.message,
        inputs.rejected_context,
        PQBTC_MLDSA44_ERR_VERIFY,
        PQBTC_MLDSA44_OK,
        0,
        0,
    };

    for (i = 0; i < CONCURRENT_VERIFY_THREADS; ++i) {
        CHECK(pthread_create(&threads[i], NULL, VerifyThread, &cases[i]) == 0);
    }

    CHECK(pthread_mutex_lock(&gate.mutex) == 0);
    while (gate.ready_threads != CONCURRENT_VERIFY_THREADS) {
        CHECK(pthread_cond_wait(&gate.ready, &gate.mutex) == 0);
    }
    gate.released = 1;
    CHECK(pthread_cond_broadcast(&gate.start) == 0);
    CHECK(pthread_mutex_unlock(&gate.mutex) == 0);

    for (i = 0; i < CONCURRENT_VERIFY_THREADS; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(cases[i].synchronization_result == 0);
        CHECK(cases[i].observed_result == cases[i].expected_result);
        CHECK(cases[i].completed_iterations == CONCURRENT_VERIFY_ITERATIONS);
    }
    alarm(0);

    CHECK(memcmp(inputs.public_key, original_inputs.public_key,
                 sizeof(inputs.public_key)) == 0);
    CHECK(memcmp(inputs.signature, original_inputs.signature,
                 sizeof(inputs.signature)) == 0);
    CHECK(memcmp(inputs.rejected_signature, original_inputs.rejected_signature,
                 sizeof(inputs.rejected_signature)) == 0);
    CHECK(memcmp(inputs.message, original_inputs.message,
                 sizeof(inputs.message)) == 0);
    CHECK(memcmp(inputs.rejected_message, original_inputs.rejected_message,
                 sizeof(inputs.rejected_message)) == 0);
    CHECK(memcmp(inputs.context, original_inputs.context,
                 sizeof(inputs.context)) == 0);
    CHECK(memcmp(inputs.rejected_context, original_inputs.rejected_context,
                 sizeof(inputs.rejected_context)) == 0);

    CHECK(pthread_cond_destroy(&gate.start) == 0);
    CHECK(pthread_cond_destroy(&gate.ready) == 0);
    CHECK(pthread_mutex_destroy(&gate.mutex) == 0);

    puts("ML-DSA-44 concurrent strict verifier passed: 4 threads, "
         "32 iterations each, 1 valid case, 3 deep-reject cases");
    return 0;
}
