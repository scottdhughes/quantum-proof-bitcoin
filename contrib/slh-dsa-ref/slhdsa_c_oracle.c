// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define _POSIX_C_SOURCE 200809L

#include <slh_dsa.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEYGEN_SEED_SIZE 48
#define PRIVATE_KEY_SIZE 64
#define PUBLIC_KEY_SIZE 32
#define RANDOMIZER_SIZE 16
#define SIGNATURE_SIZE 7856

static uint64_t MonotonicNs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int HexDigit(const char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static uint8_t* DecodeHex(const char* hex, size_t* output_size)
{
    const size_t hex_size = strlen(hex);
    if ((hex_size & 1U) != 0) return NULL;

    *output_size = hex_size / 2;
    uint8_t* output = malloc(*output_size == 0 ? 1 : *output_size);
    if (output == NULL) return NULL;

    for (size_t i = 0; i < *output_size; ++i) {
        const int high = HexDigit(hex[2 * i]);
        const int low = HexDigit(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(output);
            return NULL;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return output;
}

static void PrintHex(const char* name, const uint8_t* data, const size_t size)
{
    printf("%s=", name);
    for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
    putchar('\n');
}

static int RunKeygen(const char* seed_hex)
{
    size_t seed_size = 0;
    uint8_t* seed = DecodeHex(seed_hex, &seed_size);
    uint8_t private_key[PRIVATE_KEY_SIZE];
    uint8_t public_key[PUBLIC_KEY_SIZE];
    int result = 1;

    if (seed == NULL || seed_size != KEYGEN_SEED_SIZE) {
        fprintf(stderr, "slhdsa_c_oracle: keygen seed must be %d bytes\n", KEYGEN_SEED_SIZE);
        goto cleanup;
    }
    const uint64_t started = MonotonicNs();
    const int generated = slh_keygen_internal(
        private_key,
        public_key,
        seed,
        seed + 16,
        seed + 32,
        &slh_dsa_sha2_128s);
    const uint64_t keygen_ns = MonotonicNs() - started;
    if (generated != 0) {
        fprintf(stderr, "slhdsa_c_oracle: key generation failed\n");
        goto cleanup;
    }

    PrintHex("pk", public_key, sizeof(public_key));
    PrintHex("sk", private_key, sizeof(private_key));
    printf("keygen_ns=%llu\n", (unsigned long long)keygen_ns);
    result = 0;

cleanup:
    free(seed);
    return result;
}

static int RunSign(
    const char* key_hex,
    const char* message_hex,
    const char* context_hex,
    const char* randomizer_hex)
{
    size_t key_size = 0;
    size_t message_size = 0;
    size_t context_size = 0;
    size_t randomizer_size = 0;
    uint8_t* private_key = DecodeHex(key_hex, &key_size);
    uint8_t* message = DecodeHex(message_hex, &message_size);
    uint8_t* context_string = DecodeHex(context_hex, &context_size);
    uint8_t* randomizer =
        randomizer_hex == NULL ? NULL : DecodeHex(randomizer_hex, &randomizer_size);
    uint8_t public_key[PUBLIC_KEY_SIZE];
    uint8_t* signature = NULL;
    int result = 1;

    if (private_key == NULL || key_size != PRIVATE_KEY_SIZE || message == NULL ||
        context_string == NULL || context_size > 255 ||
        (randomizer_hex != NULL &&
         (randomizer == NULL || randomizer_size != RANDOMIZER_SIZE))) {
        fprintf(stderr, "slhdsa_c_oracle: invalid sign input\n");
        goto cleanup;
    }
    memcpy(public_key, private_key + PRIVATE_KEY_SIZE - PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
    signature = malloc(SIGNATURE_SIZE);
    if (signature == NULL) goto cleanup;

    const uint64_t sign_started = MonotonicNs();
    const size_t signature_size = slh_sign(
        signature,
        message,
        message_size,
        context_string,
        context_size,
        private_key,
        randomizer,
        &slh_dsa_sha2_128s);
    const uint64_t sign_ns = MonotonicNs() - sign_started;
    if (signature_size != SIGNATURE_SIZE) {
        fprintf(stderr, "slhdsa_c_oracle: signing failed\n");
        goto cleanup;
    }

    const uint64_t verify_started = MonotonicNs();
    const int verified = slh_verify(
        message,
        message_size,
        signature,
        signature_size,
        context_string,
        context_size,
        public_key,
        &slh_dsa_sha2_128s);
    const uint64_t verify_ns = MonotonicNs() - verify_started;
    if (verified != 1) {
        fprintf(stderr, "slhdsa_c_oracle: verification failed\n");
        goto cleanup;
    }

    PrintHex("signature", signature, signature_size);
    printf("verified=1\n");
    printf("sign_ns=%llu\n", (unsigned long long)sign_ns);
    printf("verify_ns=%llu\n", (unsigned long long)verify_ns);
    result = 0;

cleanup:
    free(signature);
    free(randomizer);
    free(context_string);
    free(message);
    free(private_key);
    return result;
}

static int RunVerify(
    const char* key_hex,
    const char* message_hex,
    const char* context_hex,
    const char* signature_hex)
{
    size_t key_size = 0;
    size_t message_size = 0;
    size_t context_size = 0;
    size_t signature_size = 0;
    uint8_t* public_key = DecodeHex(key_hex, &key_size);
    uint8_t* message = DecodeHex(message_hex, &message_size);
    uint8_t* context_string = DecodeHex(context_hex, &context_size);
    uint8_t* signature = DecodeHex(signature_hex, &signature_size);
    int result = 1;

    if (public_key == NULL || key_size != PUBLIC_KEY_SIZE || message == NULL ||
        context_string == NULL || context_size > 255 || signature == NULL) {
        fprintf(stderr, "slhdsa_c_oracle: invalid verify input\n");
        goto cleanup;
    }
    if (signature_size != SIGNATURE_SIZE) {
        printf("verified=0\n");
        printf("verify_ns=0\n");
        result = 0;
        goto cleanup;
    }
    const uint64_t verify_started = MonotonicNs();
    const int verified = slh_verify(
        message,
        message_size,
        signature,
        signature_size,
        context_string,
        context_size,
        public_key,
        &slh_dsa_sha2_128s);
    const uint64_t verify_ns = MonotonicNs() - verify_started;

    printf("verified=%d\n", verified == 1);
    printf("verify_ns=%llu\n", (unsigned long long)verify_ns);
    result = 0;

cleanup:
    free(signature);
    free(context_string);
    free(message);
    free(public_key);
    return result;
}

int main(const int argc, char** argv)
{
    if (argc == 3 && strcmp(argv[1], "keygen") == 0) return RunKeygen(argv[2]);
    if (argc == 5 && strcmp(argv[1], "sign") == 0) {
        return RunSign(argv[2], argv[3], argv[4], NULL);
    }
    if (argc == 6 && strcmp(argv[1], "sign-with-randomizer") == 0) {
        return RunSign(argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc == 6 && strcmp(argv[1], "verify") == 0) {
        return RunVerify(argv[2], argv[3], argv[4], argv[5]);
    }

    fprintf(stderr, "usage: %s keygen <seed-hex>\n", argv[0]);
    fprintf(stderr, "       %s sign <sk-hex> <message-hex> <context-hex>\n", argv[0]);
    fprintf(stderr,
            "       %s sign-with-randomizer <sk-hex> <message-hex> "
            "<context-hex> <randomizer-hex>\n",
            argv[0]);
    fprintf(stderr,
            "       %s verify <pk-hex> <message-hex> <context-hex> "
            "<signature-hex>\n",
            argv[0]);
    return 2;
}
