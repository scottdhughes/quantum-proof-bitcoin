// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define _POSIX_C_SOURCE 200809L

#include "oracle_cli.h"

#include <mldsa_native.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define KEYGEN_SEED_SIZE ORACLE_KEYGEN_SEED_SIZE
#define PRIVATE_KEY_SIZE ORACLE_PRIVATE_KEY_SIZE
#define PUBLIC_KEY_SIZE ORACLE_PUBLIC_KEY_SIZE
#define RANDOMIZER_SIZE ORACLE_RANDOMIZER_SIZE
#define SIGNATURE_SIZE ORACLE_SIGNATURE_SIZE

static uint64_t MonotonicNs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

int randombytes(uint8_t* output, size_t output_size)
{
    FILE* source = fopen("/dev/urandom", "rb");
    if (source == NULL) return -1;

    while (output_size > 0) {
        const size_t read_size = fread(output, 1, output_size, source);
        if (read_size == 0) {
            fclose(source);
            return -1;
        }
        output += read_size;
        output_size -= read_size;
    }
    return fclose(source) == 0 ? 0 : -1;
}

static void PrintHex(const char* name, const uint8_t* data, const size_t size)
{
    printf("%s=", name);
    for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
    putchar('\n');
}

static int RunKeygen(const char* seed_hex)
{
    uint8_t seed[KEYGEN_SEED_SIZE];
    uint8_t private_key[PRIVATE_KEY_SIZE];
    uint8_t public_key[PUBLIC_KEY_SIZE];
    int result = 1;

    if (!OracleDecodeHexExact(seed_hex, seed, sizeof(seed))) {
        fprintf(
            stderr,
            "mldsa_native_oracle: keygen seed must be %u bytes\n",
            (unsigned int)KEYGEN_SEED_SIZE);
        return result;
    }
    const uint64_t started = MonotonicNs();
    const int generated = mldsa_keypair_internal(public_key, private_key, seed);
    const uint64_t keygen_ns = MonotonicNs() - started;
    if (generated != 0) {
        fprintf(stderr, "mldsa_native_oracle: key generation failed\n");
        return result;
    }

    PrintHex("pk", public_key, sizeof(public_key));
    PrintHex("sk", private_key, sizeof(private_key));
    printf("keygen_ns=%llu\n", (unsigned long long)keygen_ns);
    result = 0;
    return result;
}

static int RunPublicKey(const char* key_hex)
{
    uint8_t private_key[PRIVATE_KEY_SIZE];
    uint8_t public_key[PUBLIC_KEY_SIZE];
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, private_key, sizeof(private_key))) {
        fprintf(
            stderr,
            "mldsa_native_oracle: private key must be %u bytes\n",
            (unsigned int)PRIVATE_KEY_SIZE);
        return result;
    }
    if (mldsa_pk_from_sk(public_key, private_key) != 0) {
        fprintf(stderr, "mldsa_native_oracle: public-key derivation failed\n");
        return result;
    }

    PrintHex("pk", public_key, sizeof(public_key));
    result = 0;
    return result;
}

static int RunSign(
    const char* key_hex,
    const char* message_hex,
    const char* context_hex,
    const char* randomizer_hex,
    const int randomized)
{
    size_t message_size = 0;
    size_t context_size = 0;
    uint8_t private_key[PRIVATE_KEY_SIZE];
    uint8_t message[ORACLE_MAX_MESSAGE_SIZE];
    uint8_t context_string[ORACLE_MAX_CONTEXT_SIZE];
    uint8_t randomizer[RANDOMIZER_SIZE];
    const uint8_t* randomizer_pointer = NULL;
    uint8_t deterministic_randomizer[RANDOMIZER_SIZE] = {0};
    uint8_t prefix[257];
    uint8_t public_key[PUBLIC_KEY_SIZE];
    uint8_t signature[SIGNATURE_SIZE];
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, private_key, sizeof(private_key)) ||
        !OracleDecodeHexBounded(
            message_hex, message, sizeof(message), &message_size) ||
        !OracleDecodeHexBounded(
            context_hex, context_string, sizeof(context_string), &context_size) ||
        (randomized && randomizer_hex != NULL) ||
        (randomizer_hex != NULL &&
         !OracleDecodeHexExact(randomizer_hex, randomizer, sizeof(randomizer)))) {
        fprintf(stderr, "mldsa_native_oracle: invalid sign input\n");
        return result;
    }
    if (randomizer_hex != NULL) randomizer_pointer = randomizer;
    if (mldsa_pk_from_sk(public_key, private_key) != 0) {
        fprintf(stderr, "mldsa_native_oracle: invalid private key\n");
        return result;
    }

    size_t signature_size = 0;
    const uint64_t sign_started = MonotonicNs();
    int signed_result = 0;
    if (randomized) {
        signed_result = mldsa_signature(
            signature,
            &signature_size,
            message,
            message_size,
            context_string,
            context_size,
            private_key);
    } else {
        prefix[0] = 0;
        prefix[1] = (uint8_t)context_size;
        memcpy(prefix + 2, context_string, context_size);
        const uint8_t* signing_randomizer =
            randomizer_pointer == NULL ? deterministic_randomizer : randomizer_pointer;
        signed_result = mldsa_signature_internal(
            signature,
            &signature_size,
            message,
            message_size,
            prefix,
            context_size + 2,
            signing_randomizer,
            private_key,
            0);
    }
    const uint64_t sign_ns = MonotonicNs() - sign_started;
    if (signed_result != 0 || signature_size != SIGNATURE_SIZE) {
        fprintf(stderr, "mldsa_native_oracle: signing failed\n");
        return result;
    }

    const uint64_t verify_started = MonotonicNs();
    const int verified = mldsa_verify(
        signature,
        signature_size,
        message,
        message_size,
        context_string,
        context_size,
        public_key);
    const uint64_t verify_ns = MonotonicNs() - verify_started;
    if (verified != 0) {
        fprintf(stderr, "mldsa_native_oracle: verification failed\n");
        return result;
    }

    PrintHex("signature", signature, signature_size);
    printf("verified=1\n");
    printf("sign_ns=%llu\n", (unsigned long long)sign_ns);
    printf("verify_ns=%llu\n", (unsigned long long)verify_ns);
    result = 0;
    return result;
}

static int RunVerify(
    const char* key_hex,
    const char* message_hex,
    const char* context_hex,
    const char* signature_hex)
{
    size_t message_size = 0;
    size_t context_size = 0;
    size_t signature_size = 0;
    uint8_t public_key[PUBLIC_KEY_SIZE];
    uint8_t message[ORACLE_MAX_MESSAGE_SIZE];
    uint8_t context_string[ORACLE_MAX_CONTEXT_SIZE];
    uint8_t signature[ORACLE_MAX_VERIFY_SIGNATURE_SIZE];
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, public_key, sizeof(public_key)) ||
        !OracleDecodeHexBounded(
            message_hex, message, sizeof(message), &message_size) ||
        !OracleDecodeHexBounded(
            context_hex, context_string, sizeof(context_string), &context_size) ||
        !OracleDecodeHexBounded(
            signature_hex, signature, sizeof(signature), &signature_size)) {
        fprintf(stderr, "mldsa_native_oracle: invalid verify input\n");
        return result;
    }
    if (signature_size != SIGNATURE_SIZE) {
        printf("verified=0\n");
        printf("verify_ns=0\n");
        return 0;
    }
    const uint64_t verify_started = MonotonicNs();
    const int verified = mldsa_verify(
        signature,
        signature_size,
        message,
        message_size,
        context_string,
        context_size,
        public_key);
    const uint64_t verify_ns = MonotonicNs() - verify_started;

    printf("verified=%d\n", verified == 0);
    printf("verify_ns=%llu\n", (unsigned long long)verify_ns);
    result = 0;
    return result;
}

int main(const int argc, char** argv)
{
    if (argc == 3 && OracleCommandEquals(argv[1], "keygen")) return RunKeygen(argv[2]);
    if (argc == 3 && OracleCommandEquals(argv[1], "public-key")) {
        return RunPublicKey(argv[2]);
    }
    if (argc == 5 && OracleCommandEquals(argv[1], "sign")) {
        return RunSign(argv[2], argv[3], argv[4], NULL, 0);
    }
    if (argc == 5 && OracleCommandEquals(argv[1], "sign-randomized")) {
        return RunSign(argv[2], argv[3], argv[4], NULL, 1);
    }
    if (argc == 6 && OracleCommandEquals(argv[1], "sign-with-randomizer")) {
        return RunSign(argv[2], argv[3], argv[4], argv[5], 0);
    }
    if (argc == 6 && OracleCommandEquals(argv[1], "verify")) {
        return RunVerify(argv[2], argv[3], argv[4], argv[5]);
    }

    fprintf(stderr, "usage: mldsa_native_oracle keygen <seed-hex>\n");
    fprintf(stderr, "       mldsa_native_oracle public-key <sk-hex>\n");
    fprintf(stderr, "       mldsa_native_oracle sign <sk-hex> <message-hex> <context-hex>\n");
    fprintf(
        stderr,
        "       mldsa_native_oracle sign-randomized <sk-hex> <message-hex> "
        "<context-hex>\n");
    fprintf(stderr,
            "       mldsa_native_oracle sign-with-randomizer <sk-hex> <message-hex> "
            "<context-hex> <randomizer-hex>\n");
    fprintf(stderr,
            "       mldsa_native_oracle verify <pk-hex> <message-hex> <context-hex> "
            "<signature-hex>\n");
    return 2;
}
