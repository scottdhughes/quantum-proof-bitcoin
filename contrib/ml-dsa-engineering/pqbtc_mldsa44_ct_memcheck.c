// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44.h"
#include "pqbtc_mldsa44_test.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

#define CHECK_OR_RETURN(condition, code) \
    do {                                 \
        if (!(condition)) return (code); \
    } while (0)

static const uint8_t TEST_SEED[32] = {
    0xd7, 0x13, 0x61, 0xc0, 0x00, 0xf9, 0xa7, 0xbc,
    0x99, 0xdf, 0xb4, 0x25, 0xbc, 0xb6, 0xbb, 0x27,
    0xc3, 0x2c, 0x36, 0xab, 0x44, 0x4f, 0xf3, 0x70,
    0x8b, 0x2d, 0x93, 0xb4, 0xe6, 0x6d, 0x5b, 0x5b,
};

static volatile uint8_t g_taint_sink;

static __attribute__((noinline)) void ProbeSecretKeyTaint(
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES])
{
    volatile uint8_t secret = secret_key[0];
    if ((secret & 1U) != 0) g_taint_sink = secret;
}

static int IsAllZero(const uint8_t* bytes, size_t size)
{
    uint8_t aggregate = 0;
    size_t i;
    for (i = 0; i < size; ++i)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static void FillRandomizer(uint8_t randomizer[32], uint8_t scenario)
{
    size_t i;
    for (i = 0; i < 32; ++i)
        randomizer[i] = (uint8_t)(1U + i + (size_t)scenario * 37U);
}

static int SetEntropy(const uint8_t randomizer[32])
{
    return pqbtc_mldsa44_test_set_entropy(
        PQBTC_MLDSA44_TEST_ENTROPY_FIXED, randomizer, 32);
}

int main(int argc, char** argv)
{
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t message[32];
    const uint8_t context[] = "PQBTC/valgrind-ct/v1";
    uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES];
    size_t i;
    uint8_t scenario;
    int taint_control;

    CHECK_OR_RETURN(RUNNING_ON_VALGRIND != 0, 90);
    taint_control = argc == 2 && strcmp(argv[1], "secret-key-taint") == 0;
    CHECK_OR_RETURN(argc == 1 || taint_control, 64);
    for (i = 0; i < sizeof(message); ++i)
        message[i] = (uint8_t)(0xa0U + i);

    pqbtc_mldsa44_test_reset();
    CHECK_OR_RETURN(
        pqbtc_mldsa44_test_keypair_from_seed(public_key, secret_key, TEST_SEED) ==
            PQBTC_MLDSA44_OK,
        10);

    VALGRIND_MAKE_MEM_UNDEFINED(secret_key, sizeof(secret_key));
    if (taint_control) {
        ProbeSecretKeyTaint(secret_key);
        return 0;
    }
    for (scenario = 0; scenario < 5; ++scenario) {
        FillRandomizer(randomizer, scenario);
        CHECK_OR_RETURN(SetEntropy(randomizer) == PQBTC_MLDSA44_OK, 20 + scenario);
        CHECK_OR_RETURN(
            pqbtc_mldsa44_sign_hedged(
                signature,
                sizeof(signature),
                secret_key,
                sizeof(secret_key),
                public_key,
                sizeof(public_key),
                message,
                sizeof(message),
                context,
                sizeof(context) - 1) == PQBTC_MLDSA44_OK,
            30 + scenario);
        CHECK_OR_RETURN(!IsAllZero(signature, sizeof(signature)), 40 + scenario);
        CHECK_OR_RETURN(
            pqbtc_mldsa44_verify_strict(
                signature,
                sizeof(signature),
                public_key,
                sizeof(public_key),
                message,
                sizeof(message),
                context,
                sizeof(context) - 1) == PQBTC_MLDSA44_OK,
            50 + scenario);
    }

    CHECK_OR_RETURN(SetEntropy(randomizer) == PQBTC_MLDSA44_OK, 60);
    CHECK_OR_RETURN(
        pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            sizeof(secret_key),
            public_key,
            sizeof(public_key),
            message,
            sizeof(message),
            context,
            sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
        61);
    CHECK_OR_RETURN(IsAllZero(signature, sizeof(signature)), 62);

    pqbtc_mldsa44_test_reset();
    for (i = 0; i < sizeof(randomizer); ++i)
        randomizer[i] = 0;
    CHECK_OR_RETURN(SetEntropy(randomizer) == PQBTC_MLDSA44_OK, 70);
    CHECK_OR_RETURN(
        pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            sizeof(secret_key),
            public_key,
            sizeof(public_key),
            message,
            sizeof(message),
            context,
            sizeof(context) - 1) == PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO,
        71);
    CHECK_OR_RETURN(IsAllZero(signature, sizeof(signature)), 72);
    return 0;
}
