// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PQBTC_MLDSA44_FUZZ_FRAME_VERSION 1U
#define PQBTC_MLDSA44_FUZZ_HEADER_BYTES 10U
#define PQBTC_MLDSA44_FUZZ_MAX_SIGNATURE_BYTES 2421U
#define PQBTC_MLDSA44_FUZZ_MAX_PUBLIC_KEY_BYTES 1313U
#define PQBTC_MLDSA44_FUZZ_MAX_CONTEXT_BYTES 256U
#define PQBTC_MLDSA44_FUZZ_MAX_MESSAGE_BYTES 4096U

#define PQBTC_MLDSA44_FUZZ_NULL_SIGNATURE 0x01U
#define PQBTC_MLDSA44_FUZZ_NULL_PUBLIC_KEY 0x02U
#define PQBTC_MLDSA44_FUZZ_NULL_CONTEXT 0x04U
#define PQBTC_MLDSA44_FUZZ_NULL_MESSAGE 0x08U
#define PQBTC_MLDSA44_FUZZ_NULL_MASK 0x0fU

#define PQBTC_MLDSA44_CTILDE_BYTES 32U
#define PQBTC_MLDSA44_Z_BYTES 2304U
#define PQBTC_MLDSA44_HINT_INDICES 80U
#define PQBTC_MLDSA44_HINT_COUNTERS 4U
#define PQBTC_MLDSA44_HINT_OFFSET \
    (PQBTC_MLDSA44_CTILDE_BYTES + PQBTC_MLDSA44_Z_BYTES)

_Static_assert(PQBTC_MLDSA44_PUBLIC_KEY_BYTES == 1312U, "unexpected ML-DSA-44 public key size");
_Static_assert(PQBTC_MLDSA44_SIGNATURE_BYTES == 2420U, "unexpected ML-DSA-44 signature size");
_Static_assert(
    PQBTC_MLDSA44_HINT_OFFSET + PQBTC_MLDSA44_HINT_INDICES +
            PQBTC_MLDSA44_HINT_COUNTERS ==
        PQBTC_MLDSA44_SIGNATURE_BYTES,
    "unexpected ML-DSA-44 signature layout");

struct fuzz_frame {
    uint8_t null_flags;
    uint16_t signature_size;
    uint16_t public_key_size;
    uint16_t context_size;
    uint16_t message_size;
    size_t signature_offset;
    size_t public_key_offset;
    size_t context_offset;
    size_t message_offset;
};

static uint16_t ReadU16(const uint8_t* bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static void WriteU16(uint8_t* bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static int ParseFrame(const uint8_t* data, size_t size, struct fuzz_frame* frame)
{
    size_t expected_size;

    if (size < PQBTC_MLDSA44_FUZZ_HEADER_BYTES ||
        data[0] != PQBTC_MLDSA44_FUZZ_FRAME_VERSION ||
        (data[1] & ~PQBTC_MLDSA44_FUZZ_NULL_MASK) != 0) {
        return 0;
    }

    frame->null_flags = data[1];
    frame->signature_size = ReadU16(data + 2);
    frame->public_key_size = ReadU16(data + 4);
    frame->context_size = ReadU16(data + 6);
    frame->message_size = ReadU16(data + 8);
    if (frame->signature_size > PQBTC_MLDSA44_FUZZ_MAX_SIGNATURE_BYTES ||
        frame->public_key_size > PQBTC_MLDSA44_FUZZ_MAX_PUBLIC_KEY_BYTES ||
        frame->context_size > PQBTC_MLDSA44_FUZZ_MAX_CONTEXT_BYTES ||
        frame->message_size > PQBTC_MLDSA44_FUZZ_MAX_MESSAGE_BYTES) {
        return 0;
    }

    frame->signature_offset = PQBTC_MLDSA44_FUZZ_HEADER_BYTES;
    frame->public_key_offset = frame->signature_offset + frame->signature_size;
    frame->context_offset = frame->public_key_offset + frame->public_key_size;
    frame->message_offset = frame->context_offset + frame->context_size;
    expected_size = frame->message_offset + frame->message_size;
    return expected_size == size;
}

static const uint8_t* MaybeNull(
    const uint8_t* data, size_t offset, uint8_t null_flags, uint8_t null_flag)
{
    return (null_flags & null_flag) != 0 ? NULL : data + offset;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    struct fuzz_frame frame;
    int expected_invalid_argument;
    int result;

    if (!ParseFrame(data, size, &frame)) return 0;

    expected_invalid_argument =
        (frame.null_flags & PQBTC_MLDSA44_FUZZ_NULL_SIGNATURE) != 0 ||
        frame.signature_size != PQBTC_MLDSA44_SIGNATURE_BYTES ||
        (frame.null_flags & PQBTC_MLDSA44_FUZZ_NULL_PUBLIC_KEY) != 0 ||
        frame.public_key_size != PQBTC_MLDSA44_PUBLIC_KEY_BYTES ||
        ((frame.null_flags & PQBTC_MLDSA44_FUZZ_NULL_CONTEXT) != 0 &&
         frame.context_size != 0) ||
        frame.context_size > PQBTC_MLDSA44_MAX_CONTEXT_BYTES ||
        ((frame.null_flags & PQBTC_MLDSA44_FUZZ_NULL_MESSAGE) != 0 &&
         frame.message_size != 0);

    result = pqbtc_mldsa44_verify_strict(
        MaybeNull(
            data,
            frame.signature_offset,
            frame.null_flags,
            PQBTC_MLDSA44_FUZZ_NULL_SIGNATURE),
        frame.signature_size,
        MaybeNull(
            data,
            frame.public_key_offset,
            frame.null_flags,
            PQBTC_MLDSA44_FUZZ_NULL_PUBLIC_KEY),
        frame.public_key_size,
        MaybeNull(
            data,
            frame.message_offset,
            frame.null_flags,
            PQBTC_MLDSA44_FUZZ_NULL_MESSAGE),
        frame.message_size,
        MaybeNull(
            data,
            frame.context_offset,
            frame.null_flags,
            PQBTC_MLDSA44_FUZZ_NULL_CONTEXT),
        frame.context_size);

    if (expected_invalid_argument) {
        if (result != PQBTC_MLDSA44_ERR_INVALID_ARGUMENT) abort();
    } else if (result != PQBTC_MLDSA44_OK && result != PQBTC_MLDSA44_ERR_VERIFY) {
        abort();
    }
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

static size_t ResizeField(
    uint8_t* data,
    size_t size,
    size_t max_size,
    size_t offset,
    uint16_t old_length,
    uint16_t new_length,
    size_t length_header_offset,
    uint32_t* state)
{
    size_t tail_offset = offset + old_length;
    size_t tail_size = size - tail_offset;
    size_t new_size = size - old_length + new_length;
    size_t i;

    if (new_size > max_size) return size;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memmove(data + offset + new_length, data + tail_offset, tail_size);
    for (i = old_length; i < new_length; ++i) {
        data[offset + i] = (uint8_t)NextRandom(state);
    }
    WriteU16(data + length_header_offset, new_length);
    return new_size;
}

static void SetFirstZCode(uint8_t* signature, uint32_t* state)
{
    uint8_t* packed = signature + PQBTC_MLDSA44_CTILDE_BYTES +
        (NextRandom(state) % 4U) * 576U;
    if ((NextRandom(state) & 1U) == 0) {
        packed[0] = 0;
        packed[1] = 0;
        packed[2] &= 0xfcU;
    } else {
        packed[0] = 0xffU;
        packed[1] = 0xffU;
        packed[2] |= 0x03U;
    }
}

size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    struct fuzz_frame frame;
    uint32_t state = seed == 0 ? 1U : seed;
    uint8_t* signature;
    uint8_t* public_key;
    uint8_t* hints;

    if (!ParseFrame(data, size, &frame)) {
        return LLVMFuzzerMutate(data, size, max_size);
    }

    signature = data + frame.signature_offset;
    public_key = data + frame.public_key_offset;
    switch (NextRandom(&state) % 14U) {
    case 0:
        if (frame.signature_size >= PQBTC_MLDSA44_CTILDE_BYTES) {
            FlipRandomByte(signature, PQBTC_MLDSA44_CTILDE_BYTES, &state);
        }
        break;
    case 1:
        if (frame.signature_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
            SetFirstZCode(signature, &state);
        }
        break;
    case 2:
        if (frame.signature_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
            hints = signature + PQBTC_MLDSA44_HINT_OFFSET;
            hints[PQBTC_MLDSA44_HINT_INDICES + (NextRandom(&state) % 4U)] = 81U;
        }
        break;
    case 3:
        if (frame.signature_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
            hints = signature + PQBTC_MLDSA44_HINT_OFFSET;
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memset(hints, 0, PQBTC_MLDSA44_HINT_INDICES + PQBTC_MLDSA44_HINT_COUNTERS);
            hints[0] = 2U;
            hints[1] = 1U;
            hints[PQBTC_MLDSA44_HINT_INDICES] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 1U] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 2U] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 3U] = 2U;
        }
        break;
    case 4:
        if (frame.signature_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
            hints = signature + PQBTC_MLDSA44_HINT_OFFSET;
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memset(hints, 0, PQBTC_MLDSA44_HINT_INDICES + PQBTC_MLDSA44_HINT_COUNTERS);
            hints[0] = 1U;
            hints[1] = 1U;
            hints[PQBTC_MLDSA44_HINT_INDICES] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 1U] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 2U] = 2U;
            hints[PQBTC_MLDSA44_HINT_INDICES + 3U] = 2U;
        }
        break;
    case 5:
        if (frame.signature_size == PQBTC_MLDSA44_SIGNATURE_BYTES) {
            hints = signature + PQBTC_MLDSA44_HINT_OFFSET;
            // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
            memset(hints, 0, PQBTC_MLDSA44_HINT_INDICES + PQBTC_MLDSA44_HINT_COUNTERS);
            hints[0] = 1U;
        }
        break;
    case 6:
        if (frame.public_key_size >= 32U) FlipRandomByte(public_key, 32U, &state);
        break;
    case 7:
        if (frame.public_key_size > 32U) {
            FlipRandomByte(public_key + 32U, frame.public_key_size - 32U, &state);
        }
        break;
    case 8: {
        static const uint16_t lengths[] = {0U, 2419U, 2420U, 2421U};
        size = ResizeField(
            data,
            size,
            max_size,
            frame.signature_offset,
            frame.signature_size,
            lengths[NextRandom(&state) % 4U],
            2U,
            &state);
        break;
    }
    case 9: {
        static const uint16_t lengths[] = {0U, 1311U, 1312U, 1313U};
        size = ResizeField(
            data,
            size,
            max_size,
            frame.public_key_offset,
            frame.public_key_size,
            lengths[NextRandom(&state) % 4U],
            4U,
            &state);
        break;
    }
    case 10: {
        static const uint16_t lengths[] = {0U, 1U, 255U, 256U};
        size = ResizeField(
            data,
            size,
            max_size,
            frame.context_offset,
            frame.context_size,
            lengths[NextRandom(&state) % 4U],
            6U,
            &state);
        break;
    }
    case 11:
        FlipRandomByte(data + frame.context_offset, frame.context_size, &state);
        break;
    case 12:
        FlipRandomByte(data + frame.message_offset, frame.message_size, &state);
        break;
    default:
        data[1] = (uint8_t)(1U << (NextRandom(&state) % 4U));
        break;
    }
    return size;
}
