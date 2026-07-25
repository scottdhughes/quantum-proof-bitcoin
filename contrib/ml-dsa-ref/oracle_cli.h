// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PQBTC_ML_DSA_REF_ORACLE_CLI_H
#define PQBTC_ML_DSA_REF_ORACLE_CLI_H

#include <stddef.h>
#include <stdint.h>

#define ORACLE_KEYGEN_SEED_SIZE 32U
#define ORACLE_PRIVATE_KEY_SIZE 2560U
#define ORACLE_PUBLIC_KEY_SIZE 1312U
#define ORACLE_RANDOMIZER_SIZE 32U
#define ORACLE_SIGNATURE_SIZE 2420U
#define ORACLE_MAX_VERIFY_SIGNATURE_SIZE (ORACLE_SIGNATURE_SIZE + 1U)
#define ORACLE_MAX_MESSAGE_SIZE 8192U
#define ORACLE_MAX_CONTEXT_SIZE 255U

static inline int OracleHexDigit(const char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

/*
 * Decode an argv value without an unbounded strlen or attacker-sized
 * allocation. Upper- and lower-case ASCII hex are accepted. Embedded NUL
 * cannot cross the execve argv boundary and is therefore outside this helper's
 * process-level contract.
 */
static inline int OracleDecodeHexBounded(
    const char* hex,
    uint8_t* output,
    const size_t output_capacity,
    size_t* output_size)
{
    size_t maximum_hex_size;
    size_t hex_size = 0;

    if (hex == NULL || output == NULL || output_size == NULL ||
        output_capacity > SIZE_MAX / 2U) {
        return 0;
    }
    maximum_hex_size = output_capacity * 2U;
    while (hex_size <= maximum_hex_size && hex[hex_size] != '\0') ++hex_size;
    if (hex_size > maximum_hex_size || (hex_size & 1U) != 0) return 0;

    *output_size = hex_size / 2U;
    for (size_t i = 0; i < *output_size; ++i) {
        const int high = OracleHexDigit(hex[2U * i]);
        const int low = OracleHexDigit(hex[2U * i + 1U]);
        if (high < 0 || low < 0) return 0;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static inline int OracleDecodeHexExact(
    const char* hex, uint8_t* output, const size_t expected_size)
{
    size_t output_size = 0;
    return OracleDecodeHexBounded(hex, output, expected_size, &output_size) &&
        output_size == expected_size;
}

static inline int OracleCommandEquals(const char* actual, const char* expected)
{
    size_t index = 0;
    if (actual == NULL || expected == NULL) return 0;
    while (expected[index] != '\0' && actual[index] == expected[index]) ++index;
    return expected[index] == '\0' && actual[index] == '\0';
}

#endif // PQBTC_ML_DSA_REF_ORACLE_CLI_H
