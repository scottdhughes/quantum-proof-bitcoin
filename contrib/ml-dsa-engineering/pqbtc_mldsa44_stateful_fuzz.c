// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44.h"
#include "pqbtc_mldsa44_test.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define PQBTC_MLDSA44_STATEFUL_FRAME_VERSION 1U
#define PQBTC_MLDSA44_STATEFUL_HEADER_BYTES 8U
#define PQBTC_MLDSA44_STATEFUL_SEED_BYTES 32U
#define PQBTC_MLDSA44_STATEFUL_FIXED_BYTES 96U
#define PQBTC_MLDSA44_STATEFUL_MAX_MESSAGE_BYTES 4096U
#define PQBTC_MLDSA44_STATEFUL_MAX_CONTEXT_BYTES 256U
#define PQBTC_MLDSA44_STATEFUL_MAX_FRAME_BYTES \
    (PQBTC_MLDSA44_STATEFUL_HEADER_BYTES + PQBTC_MLDSA44_STATEFUL_FIXED_BYTES + \
     PQBTC_MLDSA44_STATEFUL_MAX_MESSAGE_BYTES + \
     PQBTC_MLDSA44_STATEFUL_MAX_CONTEXT_BYTES)

#define PQBTC_MLDSA44_STATEFUL_SCENARIOS 11U
#define PQBTC_MLDSA44_STATEFUL_ARGUMENT_VARIANTS 13U

enum stateful_scenario {
    SCENARIO_FRESH_THEN_FRESH = 0,
    SCENARIO_FRESH_THEN_REPEAT = 1,
    SCENARIO_SHORT_THEN_FRESH = 2,
    SCENARIO_FAILURE_THEN_FRESH = 3,
    SCENARIO_ZERO_THEN_FRESH = 4,
    SCENARIO_INVALID_THEN_FRESH = 5,
    SCENARIO_BACKEND_THEN_REPEAT = 6,
    SCENARIO_ATTEMPTS_THEN_REPEAT = 7,
    SCENARIO_LENGTH_THEN_REPEAT = 8,
    SCENARIO_VERIFY_THEN_REPEAT = 9,
    SCENARIO_RESET_THEN_REUSE = 10
};

enum invalid_argument_variant {
    ARGUMENT_NULL_OUTPUT = 0,
    ARGUMENT_SHORT_OUTPUT = 1,
    ARGUMENT_LONG_OUTPUT = 2,
    ARGUMENT_ALIAS_SECRET_KEY = 3,
    ARGUMENT_ALIAS_PUBLIC_KEY = 4,
    ARGUMENT_ALIAS_MESSAGE = 5,
    ARGUMENT_ALIAS_CONTEXT = 6,
    ARGUMENT_NULL_SECRET_KEY = 7,
    ARGUMENT_SHORT_SECRET_KEY = 8,
    ARGUMENT_NULL_PUBLIC_KEY = 9,
    ARGUMENT_SHORT_PUBLIC_KEY = 10,
    ARGUMENT_NULL_MESSAGE = 11,
    ARGUMENT_NULL_CONTEXT = 12
};

struct stateful_frame {
    uint8_t scenario;
    uint8_t argument_variant;
    uint8_t short_length;
    uint16_t message_size;
    uint16_t context_size;
    const uint8_t* seed;
    const uint8_t* randomizer_a;
    const uint8_t* randomizer_b;
    const uint8_t* message;
    const uint8_t* context;
};

_Static_assert(PQBTC_MLDSA44_PUBLIC_KEY_BYTES == 1312U, "unexpected public key size");
_Static_assert(PQBTC_MLDSA44_SECRET_KEY_BYTES == 2560U, "unexpected secret key size");
_Static_assert(PQBTC_MLDSA44_SIGNATURE_BYTES == 2420U, "unexpected signature size");
_Static_assert(PQBTC_MLDSA44_RANDOMIZER_BYTES == 32U, "unexpected randomizer size");
_Static_assert(PQBTC_MLDSA44_MAX_CONTEXT_BYTES == 255U, "unexpected context limit");
_Static_assert(PQBTC_MLDSA44_STATEFUL_MAX_FRAME_BYTES == 4456U, "unexpected frame size");

static void Require(int condition)
{
    if (!condition) abort();
}

static uint16_t ReadU16(const uint8_t* bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static void WriteU16(uint8_t* bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void CopyBytes(uint8_t* destination, const uint8_t* source, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i)
        destination[i] = source[i];
}

static void MoveBytes(uint8_t* destination, const uint8_t* source, size_t size)
{
    size_t i;
    if (destination < source) {
        for (i = 0; i < size; ++i)
            destination[i] = source[i];
    } else if (destination > source) {
        for (i = size; i > 0; --i)
            destination[i - 1] = source[i - 1];
    }
}

static void FillBytes(uint8_t* destination, size_t size, uint8_t value)
{
    size_t i;
    for (i = 0; i < size; ++i)
        destination[i] = value;
}

static int BytesEqual(const uint8_t* left, const uint8_t* right, size_t size)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < size; ++i)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static int IsZero(const uint8_t* bytes, size_t size)
{
    uint8_t aggregate = 0;
    size_t i;
    for (i = 0; i < size; ++i)
        aggregate |= bytes[i];
    return aggregate == 0;
}

static int IsFilled(const uint8_t* bytes, size_t size, uint8_t value)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        if (bytes[i] != value) return 0;
    }
    return 1;
}

static int ParseFrame(const uint8_t* data, size_t size, struct stateful_frame* frame)
{
    size_t expected_size;
    size_t cursor;

    if (size < PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
                   PQBTC_MLDSA44_STATEFUL_FIXED_BYTES ||
        data[0] != PQBTC_MLDSA44_STATEFUL_FRAME_VERSION) {
        return 0;
    }

    frame->scenario = data[1] % PQBTC_MLDSA44_STATEFUL_SCENARIOS;
    frame->argument_variant =
        data[2] % PQBTC_MLDSA44_STATEFUL_ARGUMENT_VARIANTS;
    frame->short_length = data[3] % PQBTC_MLDSA44_RANDOMIZER_BYTES;
    frame->message_size = ReadU16(data + 4);
    frame->context_size = ReadU16(data + 6);
    if (frame->message_size > PQBTC_MLDSA44_STATEFUL_MAX_MESSAGE_BYTES ||
        frame->context_size > PQBTC_MLDSA44_STATEFUL_MAX_CONTEXT_BYTES) {
        return 0;
    }

    expected_size = PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
        PQBTC_MLDSA44_STATEFUL_FIXED_BYTES + frame->message_size +
        frame->context_size;
    if (expected_size != size) return 0;

    cursor = PQBTC_MLDSA44_STATEFUL_HEADER_BYTES;
    frame->seed = data + cursor;
    cursor += PQBTC_MLDSA44_STATEFUL_SEED_BYTES;
    frame->randomizer_a = data + cursor;
    cursor += PQBTC_MLDSA44_RANDOMIZER_BYTES;
    frame->randomizer_b = data + cursor;
    cursor += PQBTC_MLDSA44_RANDOMIZER_BYTES;
    frame->message = data + cursor;
    cursor += frame->message_size;
    frame->context = data + cursor;
    return 1;
}

static const uint8_t* OptionalBytes(const uint8_t* bytes, size_t size)
{
    return size == 0 ? NULL : bytes;
}

static void NormalizeRandomizers(
    const struct stateful_frame* frame,
    uint8_t randomizer_a[PQBTC_MLDSA44_RANDOMIZER_BYTES],
    uint8_t randomizer_b[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    CopyBytes(randomizer_a, frame->randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    CopyBytes(randomizer_b, frame->randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    if (IsZero(randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES)) randomizer_a[0] = 1U;
    if (IsZero(randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES)) randomizer_b[0] = 2U;
    if (BytesEqual(
            randomizer_a, randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES)) {
        randomizer_b[0] ^= 0x80U;
        if (IsZero(randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES)) {
            randomizer_b[0] = 2U;
        }
    }
}

static void RequireEntropyCount(size_t requests)
{
    Require(pqbtc_mldsa44_test_entropy_requests() == requests);
    Require(
        pqbtc_mldsa44_test_entropy_requested_bytes() ==
        requests * PQBTC_MLDSA44_RANDOMIZER_BYTES);
}

static void ClearFaults(void)
{
    pqbtc_mldsa44_test_force_backend_result(0);
    pqbtc_mldsa44_test_force_signature_length(0);
    pqbtc_mldsa44_test_force_verify_failure(0);
}

static void SetFixedEntropy(const uint8_t randomizer[32], size_t reported_size)
{
    Require(
        pqbtc_mldsa44_test_set_entropy(
            PQBTC_MLDSA44_TEST_ENTROPY_FIXED, randomizer, reported_size) ==
        PQBTC_MLDSA44_OK);
}

static int Sign(
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES],
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size)
{
    FillBytes(signature, PQBTC_MLDSA44_SIGNATURE_BYTES, 0xa5U);
    return pqbtc_mldsa44_sign_hedged(
        signature,
        PQBTC_MLDSA44_SIGNATURE_BYTES,
        secret_key,
        PQBTC_MLDSA44_SECRET_KEY_BYTES,
        public_key,
        PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
        OptionalBytes(message, message_size),
        message_size,
        OptionalBytes(context, context_size),
        context_size);
}

static void RequireSuccessfulSignature(
    const uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES],
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    uint8_t expected[PQBTC_MLDSA44_SIGNATURE_BYTES];

    Require(!IsZero(signature, PQBTC_MLDSA44_SIGNATURE_BYTES));
    Require(
        pqbtc_mldsa44_verify_strict(
            signature,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size) == PQBTC_MLDSA44_OK);
    Require(
        pqbtc_mldsa44_test_sign_fixed_randomizer(
            expected,
            secret_key,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size,
            randomizer) == PQBTC_MLDSA44_OK);
    Require(BytesEqual(signature, expected, PQBTC_MLDSA44_SIGNATURE_BYTES));
    FillBytes(expected, sizeof(expected), 0);
}

static void RequireValidCall(
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES],
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES],
    int expected,
    size_t expected_entropy_requests)
{
    int result;

    SetFixedEntropy(randomizer, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    result = Sign(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size);
    Require(result == expected);
    RequireEntropyCount(expected_entropy_requests);
    if (expected == PQBTC_MLDSA44_OK) {
        RequireSuccessfulSignature(
            signature,
            secret_key,
            public_key,
            message,
            message_size,
            context,
            context_size,
            randomizer);
    } else {
        Require(IsZero(signature, PQBTC_MLDSA44_SIGNATURE_BYTES));
    }
}

static void RequireInvalidContextPreservesRepeatState(
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const struct stateful_frame* frame,
    const uint8_t randomizer_a[PQBTC_MLDSA44_RANDOMIZER_BYTES],
    const uint8_t randomizer_b[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    int result;

    RequireValidCall(
        signature,
        secret_key,
        public_key,
        frame->message,
        frame->message_size,
        frame->context,
        PQBTC_MLDSA44_MAX_CONTEXT_BYTES,
        randomizer_a,
        PQBTC_MLDSA44_OK,
        1);
    SetFixedEntropy(randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    result = Sign(
        signature,
        secret_key,
        public_key,
        frame->message,
        frame->message_size,
        frame->context,
        frame->context_size);
    Require(result == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    Require(IsZero(signature, sizeof(signature)));
    RequireEntropyCount(1);
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        frame->message,
        frame->message_size,
        frame->context,
        PQBTC_MLDSA44_MAX_CONTEXT_BYTES,
        randomizer_a,
        PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
        2);
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        frame->message,
        frame->message_size,
        frame->context,
        PQBTC_MLDSA44_MAX_CONTEXT_BYTES,
        randomizer_b,
        PQBTC_MLDSA44_OK,
        3);
}

static void RequireInvalidArgumentDoesNotConsumeState(
    uint8_t variant,
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    size_t expected_entropy_requests)
{
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t secret_alias[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t public_alias[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t message_alias[PQBTC_MLDSA44_STATEFUL_MAX_MESSAGE_BYTES];
    uint8_t context_alias[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t before[PQBTC_MLDSA44_STATEFUL_MAX_MESSAGE_BYTES];
    size_t alias_message_size = message_size == 0 ? 1U : message_size;
    size_t alias_context_size = context_size == 0 ? 1U : context_size;
    int result;

    FillBytes(signature, sizeof(signature), 0xa5U);
    CopyBytes(before, signature, sizeof(signature));
    switch (variant) {
    case ARGUMENT_NULL_OUTPUT:
        result = pqbtc_mldsa44_sign_hedged(
            NULL,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(BytesEqual(signature, before, sizeof(signature)));
        break;
    case ARGUMENT_SHORT_OUTPUT:
    case ARGUMENT_LONG_OUTPUT:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            variant == ARGUMENT_SHORT_OUTPUT ?
                PQBTC_MLDSA44_SIGNATURE_BYTES - 1U :
                PQBTC_MLDSA44_SIGNATURE_BYTES + 1U,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(BytesEqual(signature, before, sizeof(signature)));
        break;
    case ARGUMENT_ALIAS_SECRET_KEY:
        CopyBytes(secret_alias, secret_key, sizeof(secret_alias));
        CopyBytes(before, secret_alias, sizeof(secret_alias));
        result = pqbtc_mldsa44_sign_hedged(
            secret_alias,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_alias,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(BytesEqual(secret_alias, before, sizeof(secret_alias)));
        break;
    case ARGUMENT_ALIAS_PUBLIC_KEY:
        FillBytes(public_alias, sizeof(public_alias), 0x3cU);
        CopyBytes(public_alias, public_key, PQBTC_MLDSA44_PUBLIC_KEY_BYTES);
        CopyBytes(before, public_alias, sizeof(public_alias));
        result = pqbtc_mldsa44_sign_hedged(
            public_alias,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_alias,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(BytesEqual(public_alias, before, sizeof(public_alias)));
        break;
    case ARGUMENT_ALIAS_MESSAGE:
        FillBytes(message_alias, sizeof(message_alias), 0x5aU);
        if (message_size != 0) {
            CopyBytes(message_alias, message, message_size);
        }
        CopyBytes(before, message_alias, sizeof(before));
        result = pqbtc_mldsa44_sign_hedged(
            message_alias,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            message_alias,
            alias_message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(BytesEqual(message_alias, before, sizeof(message_alias)));
        break;
    case ARGUMENT_ALIAS_CONTEXT:
        FillBytes(context_alias, sizeof(context_alias), 0x69U);
        if (context_size != 0) {
            CopyBytes(context_alias, context, context_size);
        }
        CopyBytes(before, context_alias, sizeof(context_alias));
        result = pqbtc_mldsa44_sign_hedged(
            context_alias,
            PQBTC_MLDSA44_SIGNATURE_BYTES,
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            context_alias,
            alias_context_size);
        Require(BytesEqual(context_alias, before, sizeof(context_alias)));
        break;
    case ARGUMENT_NULL_SECRET_KEY:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            NULL,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    case ARGUMENT_SHORT_SECRET_KEY:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES - 1U,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    case ARGUMENT_NULL_PUBLIC_KEY:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            NULL,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    case ARGUMENT_SHORT_PUBLIC_KEY:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES - 1U,
            OptionalBytes(message, message_size),
            message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    case ARGUMENT_NULL_MESSAGE:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            NULL,
            message_size == 0 ? 1U : message_size,
            OptionalBytes(context, context_size),
            context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    default:
        result = pqbtc_mldsa44_sign_hedged(
            signature,
            sizeof(signature),
            secret_key,
            PQBTC_MLDSA44_SECRET_KEY_BYTES,
            public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES,
            OptionalBytes(message, message_size),
            message_size,
            NULL,
            context_size == 0 ? 1U : context_size);
        Require(IsZero(signature, sizeof(signature)));
        break;
    }
    Require(result == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    RequireEntropyCount(expected_entropy_requests);
}

static void RequireFreshThenEntropyFailurePreservesRepeat(
    int entropy_mode,
    size_t reported_size,
    int expected,
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer_a[PQBTC_MLDSA44_RANDOMIZER_BYTES],
    const uint8_t randomizer_b[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    uint8_t zero_randomizer[PQBTC_MLDSA44_RANDOMIZER_BYTES] = {0};
    const uint8_t* configured =
        expected == PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO ?
        zero_randomizer :
        randomizer_b;
    int result;

    RequireValidCall(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size,
        randomizer_a,
        PQBTC_MLDSA44_OK,
        1);
    Require(
        pqbtc_mldsa44_test_set_entropy(
            entropy_mode,
            entropy_mode == PQBTC_MLDSA44_TEST_ENTROPY_FAILURE ? NULL : configured,
            reported_size) == PQBTC_MLDSA44_OK);
    result = Sign(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size);
    Require(result == expected);
    Require(IsZero(signature, sizeof(signature)));
    RequireEntropyCount(2);
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size,
        randomizer_a,
        PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
        3);
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size,
        randomizer_b,
        PQBTC_MLDSA44_OK,
        4);
}

static void RequireFaultThenRepeat(
    uint8_t scenario,
    const uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES],
    const uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES],
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size,
    const uint8_t randomizer_a[PQBTC_MLDSA44_RANDOMIZER_BYTES],
    const uint8_t randomizer_b[PQBTC_MLDSA44_RANDOMIZER_BYTES])
{
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    int expected;
    int result;

    if (scenario == SCENARIO_BACKEND_THEN_REPEAT) {
        pqbtc_mldsa44_test_force_backend_result(-1);
        expected = PQBTC_MLDSA44_ERR_BACKEND;
    } else if (scenario == SCENARIO_ATTEMPTS_THEN_REPEAT) {
        pqbtc_mldsa44_test_force_backend_result(-4);
        expected = PQBTC_MLDSA44_ERR_SIGN_ATTEMPTS_EXHAUSTED;
    } else if (scenario == SCENARIO_LENGTH_THEN_REPEAT) {
        pqbtc_mldsa44_test_force_signature_length(1);
        expected = PQBTC_MLDSA44_ERR_SIGNATURE_LENGTH;
    } else {
        pqbtc_mldsa44_test_force_verify_failure(1);
        expected = PQBTC_MLDSA44_ERR_VERIFY;
    }

    SetFixedEntropy(randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES);
    result = Sign(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size);
    Require(result == expected);
    Require(IsZero(signature, sizeof(signature)));
    RequireEntropyCount(1);

    ClearFaults();
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size,
        randomizer_a,
        PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
        2);
    RequireValidCall(
        signature,
        secret_key,
        public_key,
        message,
        message_size,
        context,
        context_size,
        randomizer_b,
        PQBTC_MLDSA44_OK,
        3);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    struct stateful_frame frame;
    uint8_t public_key[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t public_key_repeat[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t public_key_before[PQBTC_MLDSA44_PUBLIC_KEY_BYTES];
    uint8_t secret_key[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t secret_key_repeat[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t secret_key_before[PQBTC_MLDSA44_SECRET_KEY_BYTES];
    uint8_t frame_before[PQBTC_MLDSA44_STATEFUL_MAX_FRAME_BYTES];
    uint8_t randomizer_a[PQBTC_MLDSA44_RANDOMIZER_BYTES];
    uint8_t randomizer_b[PQBTC_MLDSA44_RANDOMIZER_BYTES];
    uint8_t signature[PQBTC_MLDSA44_SIGNATURE_BYTES];
    size_t context_size;

    pqbtc_mldsa44_test_reset();
    RequireEntropyCount(0);
    if (!ParseFrame(data, size, &frame)) {
        pqbtc_mldsa44_test_reset();
        RequireEntropyCount(0);
        return 0;
    }
    CopyBytes(frame_before, data, size);
    NormalizeRandomizers(&frame, randomizer_a, randomizer_b);

    Require(
        pqbtc_mldsa44_test_keypair_from_seed(
            public_key, secret_key, frame.seed) == PQBTC_MLDSA44_OK);
    Require(
        pqbtc_mldsa44_test_keypair_from_seed(
            public_key_repeat, secret_key_repeat, frame.seed) ==
        PQBTC_MLDSA44_OK);
    Require(BytesEqual(public_key, public_key_repeat, sizeof(public_key)));
    Require(BytesEqual(secret_key, secret_key_repeat, sizeof(secret_key)));
    RequireEntropyCount(0);
    CopyBytes(public_key_before, public_key, sizeof(public_key));
    CopyBytes(secret_key_before, secret_key, sizeof(secret_key));

    FillBytes(public_key_repeat, sizeof(public_key_repeat), 0x5aU);
    FillBytes(secret_key_repeat, sizeof(secret_key_repeat), 0x5aU);
    Require(
        pqbtc_mldsa44_test_keypair_from_seed(
            NULL, secret_key_repeat, frame.seed) ==
        PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    Require(IsFilled(secret_key_repeat, sizeof(secret_key_repeat), 0x5aU));
    FillBytes(secret_key_repeat, sizeof(secret_key_repeat), 0x69U);
    Require(
        pqbtc_mldsa44_test_keypair_from_seed(
            public_key_repeat, NULL, frame.seed) ==
        PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    Require(IsFilled(public_key_repeat, sizeof(public_key_repeat), 0x5aU));
    FillBytes(public_key_repeat, sizeof(public_key_repeat), 0x3cU);
    FillBytes(secret_key_repeat, sizeof(secret_key_repeat), 0x3cU);
    Require(
        pqbtc_mldsa44_test_keypair_from_seed(
            public_key_repeat, secret_key_repeat, NULL) ==
        PQBTC_MLDSA44_ERR_INVALID_ARGUMENT);
    Require(IsFilled(public_key_repeat, sizeof(public_key_repeat), 0x3cU));
    Require(IsFilled(secret_key_repeat, sizeof(secret_key_repeat), 0x3cU));
    RequireEntropyCount(0);

    if (frame.context_size == PQBTC_MLDSA44_STATEFUL_MAX_CONTEXT_BYTES) {
        RequireInvalidContextPreservesRepeatState(
            secret_key, public_key, &frame, randomizer_a, randomizer_b);
        Require(BytesEqual(public_key, public_key_before, sizeof(public_key)));
        Require(BytesEqual(secret_key, secret_key_before, sizeof(secret_key)));
        Require(BytesEqual(data, frame_before, size));
        pqbtc_mldsa44_test_reset();
        RequireEntropyCount(0);
        return 0;
    }
    context_size = frame.context_size;

    switch (frame.scenario) {
    case SCENARIO_FRESH_THEN_FRESH:
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_OK,
            1);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_b,
            PQBTC_MLDSA44_OK,
            2);
        break;
    case SCENARIO_FRESH_THEN_REPEAT:
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_OK,
            1);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
            2);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_b,
            PQBTC_MLDSA44_OK,
            3);
        break;
    case SCENARIO_SHORT_THEN_FRESH:
        RequireFreshThenEntropyFailurePreservesRepeat(
            PQBTC_MLDSA44_TEST_ENTROPY_FIXED,
            frame.short_length,
            PQBTC_MLDSA44_ERR_ENTROPY_LENGTH,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            randomizer_b);
        break;
    case SCENARIO_FAILURE_THEN_FRESH:
        RequireFreshThenEntropyFailurePreservesRepeat(
            PQBTC_MLDSA44_TEST_ENTROPY_FAILURE,
            0,
            PQBTC_MLDSA44_ERR_ENTROPY_SOURCE,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            randomizer_b);
        break;
    case SCENARIO_ZERO_THEN_FRESH:
        RequireFreshThenEntropyFailurePreservesRepeat(
            PQBTC_MLDSA44_TEST_ENTROPY_FIXED,
            PQBTC_MLDSA44_RANDOMIZER_BYTES,
            PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            randomizer_b);
        break;
    case SCENARIO_INVALID_THEN_FRESH:
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_OK,
            1);
        RequireInvalidArgumentDoesNotConsumeState(
            frame.argument_variant,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            1);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_ERR_ENTROPY_REPEAT,
            2);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_b,
            PQBTC_MLDSA44_OK,
            3);
        break;
    case SCENARIO_RESET_THEN_REUSE:
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_OK,
            1);
        pqbtc_mldsa44_test_reset();
        RequireEntropyCount(0);
        RequireValidCall(
            signature,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            PQBTC_MLDSA44_OK,
            1);
        break;
    default:
        RequireFaultThenRepeat(
            frame.scenario,
            secret_key,
            public_key,
            frame.message,
            frame.message_size,
            frame.context,
            context_size,
            randomizer_a,
            randomizer_b);
        break;
    }

    Require(BytesEqual(public_key, public_key_before, sizeof(public_key)));
    Require(BytesEqual(secret_key, secret_key_before, sizeof(secret_key)));
    Require(BytesEqual(data, frame_before, size));
    pqbtc_mldsa44_test_reset();
    RequireEntropyCount(0);
    return 0;
}

extern size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

static uint32_t NextRandom(uint32_t* state)
{
    *state = *state * 1664525U + 1013904223U;
    return *state;
}

static void FlipRandomByte(uint8_t* bytes, size_t size, uint32_t* state)
{
    size_t offset;
    if (size == 0) return;
    offset = NextRandom(state) % size;
    bytes[offset] ^= (uint8_t)(1U << (NextRandom(state) % 8U));
}

static size_t ResizeMessage(
    uint8_t* data,
    size_t size,
    size_t max_size,
    const struct stateful_frame* frame,
    uint16_t new_length,
    uint32_t* state)
{
    size_t message_offset =
        PQBTC_MLDSA44_STATEFUL_HEADER_BYTES + PQBTC_MLDSA44_STATEFUL_FIXED_BYTES;
    size_t context_offset = message_offset + frame->message_size;
    size_t new_context_offset = message_offset + new_length;
    size_t new_size = size - frame->message_size + new_length;
    size_t i;

    if (new_size > max_size ||
        new_size > PQBTC_MLDSA44_STATEFUL_MAX_FRAME_BYTES) {
        return size;
    }
    MoveBytes(
        data + new_context_offset, data + context_offset, frame->context_size);
    for (i = frame->message_size; i < new_length; ++i)
        data[message_offset + i] = (uint8_t)NextRandom(state);
    WriteU16(data + 4, new_length);
    return new_size;
}

static size_t ResizeContext(
    uint8_t* data,
    size_t size,
    size_t max_size,
    const struct stateful_frame* frame,
    uint16_t new_length,
    uint32_t* state)
{
    size_t context_offset = PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
        PQBTC_MLDSA44_STATEFUL_FIXED_BYTES + frame->message_size;
    size_t new_size = size - frame->context_size + new_length;
    size_t i;

    if (new_size > max_size ||
        new_size > PQBTC_MLDSA44_STATEFUL_MAX_FRAME_BYTES) {
        return size;
    }
    for (i = frame->context_size; i < new_length; ++i)
        data[context_offset + i] = (uint8_t)NextRandom(state);
    WriteU16(data + 6, new_length);
    return new_size;
}

size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    struct stateful_frame frame;
    static const uint16_t message_lengths[] = {0U, 1U, 32U, 255U, 4096U};
    static const uint16_t context_lengths[] = {0U, 1U, 254U, 255U, 256U};
    static const uint8_t short_lengths[] = {0U, 1U, 16U, 31U};
    uint32_t state = seed == 0 ? 1U : seed;
    uint8_t* randomizer_a;
    uint8_t* randomizer_b;

    if (!ParseFrame(data, size, &frame)) {
        return LLVMFuzzerMutate(data, size, max_size);
    }
    randomizer_a = data + PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
        PQBTC_MLDSA44_STATEFUL_SEED_BYTES;
    randomizer_b = randomizer_a + PQBTC_MLDSA44_RANDOMIZER_BYTES;

    switch (NextRandom(&state) % 11U) {
    case 0:
        data[1] = (uint8_t)(NextRandom(&state) % PQBTC_MLDSA44_STATEFUL_SCENARIOS);
        break;
    case 1:
        data[2] =
            (uint8_t)(NextRandom(&state) % PQBTC_MLDSA44_STATEFUL_ARGUMENT_VARIANTS);
        break;
    case 2:
        data[3] = short_lengths[NextRandom(&state) % 4U];
        break;
    case 3:
        size = ResizeMessage(
            data,
            size,
            max_size,
            &frame,
            message_lengths[NextRandom(&state) % 5U],
            &state);
        break;
    case 4:
        size = ResizeContext(
            data,
            size,
            max_size,
            &frame,
            context_lengths[NextRandom(&state) % 5U],
            &state);
        break;
    case 5:
        FlipRandomByte(
            data + PQBTC_MLDSA44_STATEFUL_HEADER_BYTES,
            PQBTC_MLDSA44_STATEFUL_SEED_BYTES,
            &state);
        break;
    case 6:
        FlipRandomByte(randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES, &state);
        break;
    case 7:
        FlipRandomByte(randomizer_b, PQBTC_MLDSA44_RANDOMIZER_BYTES, &state);
        break;
    case 8:
        CopyBytes(
            randomizer_b, randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES);
        break;
    case 9:
        FillBytes(randomizer_a, PQBTC_MLDSA44_RANDOMIZER_BYTES, 0);
        break;
    default:
        if ((NextRandom(&state) & 1U) == 0) {
            FlipRandomByte(
                data + PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
                    PQBTC_MLDSA44_STATEFUL_FIXED_BYTES,
                frame.message_size,
                &state);
        } else {
            FlipRandomByte(
                data + PQBTC_MLDSA44_STATEFUL_HEADER_BYTES +
                    PQBTC_MLDSA44_STATEFUL_FIXED_BYTES + frame.message_size,
                frame.context_size,
                &state);
        }
        break;
    }
    return size;
}
