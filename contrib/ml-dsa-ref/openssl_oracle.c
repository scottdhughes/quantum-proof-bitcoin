// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define _POSIX_C_SOURCE 200809L

#include "oracle_cli.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define ALGORITHM "ML-DSA-44"
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

static void PrintHex(const char* name, const unsigned char* data, const size_t size)
{
    printf("%s=", name);
    for (size_t i = 0; i < size; ++i) printf("%02x", data[i]);
    putchar('\n');
}

static void PrintOpenSSLError(const char* operation)
{
    fprintf(stderr, "openssl_oracle: %s failed\n", operation);
    ERR_print_errors_fp(stderr);
}

static int ExportKeys(EVP_PKEY* key, unsigned char* private_key, unsigned char* public_key)
{
    size_t private_key_size = 0;
    size_t public_key_size = 0;
    if (EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PRIV_KEY, private_key, PRIVATE_KEY_SIZE, &private_key_size) <= 0 ||
        private_key_size != PRIVATE_KEY_SIZE) {
        PrintOpenSSLError("private-key export");
        return 0;
    }
    if (EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY, public_key, PUBLIC_KEY_SIZE, &public_key_size) <= 0 ||
        public_key_size != PUBLIC_KEY_SIZE) {
        PrintOpenSSLError("public-key export");
        return 0;
    }
    return 1;
}

static EVP_PKEY* GenerateKey(const unsigned char* seed, uint64_t* elapsed_ns)
{
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, ALGORITHM, NULL);
    EVP_PKEY* key = NULL;
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0) {
        PrintOpenSSLError("keygen initialization");
        EVP_PKEY_CTX_free(context);
        return NULL;
    }

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ML_DSA_SEED, (void*)seed, KEYGEN_SEED_SIZE),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_CTX_set_params(context, parameters) <= 0) {
        PrintOpenSSLError("keygen seed setup");
        EVP_PKEY_CTX_free(context);
        return NULL;
    }

    const uint64_t started = MonotonicNs();
    const int generated = EVP_PKEY_keygen(context, &key);
    *elapsed_ns = MonotonicNs() - started;
    EVP_PKEY_CTX_free(context);
    if (generated <= 0) {
        PrintOpenSSLError("key generation");
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

static EVP_PKEY* ImportPrivateKey(const unsigned char* private_key)
{
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, ALGORITHM, NULL);
    EVP_PKEY* key = NULL;

    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0) {
        PrintOpenSSLError("key import initialization");
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void*)private_key, PRIVATE_KEY_SIZE),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_fromdata(context, &key, EVP_PKEY_KEYPAIR, parameters) <= 0) {
        PrintOpenSSLError("private-key import");
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(key);
        return NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static EVP_PKEY* ImportPublicKey(const unsigned char* public_key)
{
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, ALGORITHM, NULL);
    EVP_PKEY* key = NULL;

    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0) {
        PrintOpenSSLError("public-key import initialization");
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, (void*)public_key, PUBLIC_KEY_SIZE),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) <= 0) {
        PrintOpenSSLError("public-key import");
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(key);
        return NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int VerifySignature(
    EVP_PKEY* key,
    const unsigned char* message,
    const size_t message_size,
    unsigned char* context_string,
    const size_t context_size,
    const unsigned char* signature,
    const size_t signature_size,
    uint64_t* verify_ns)
{
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context_string, context_size),
        OSSL_PARAM_construct_end(),
    };
    EVP_SIGNATURE* algorithm = EVP_SIGNATURE_fetch(NULL, ALGORITHM, NULL);
    EVP_PKEY_CTX* verify_context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int result = -1;

    if (algorithm == NULL || verify_context == NULL ||
        EVP_PKEY_verify_message_init(verify_context, algorithm, parameters) <= 0) {
        PrintOpenSSLError("verify initialization");
        goto cleanup;
    }
    const uint64_t verify_started = MonotonicNs();
    result = EVP_PKEY_verify(
        verify_context, signature, signature_size, message, message_size);
    *verify_ns = MonotonicNs() - verify_started;
    if (result < 0) PrintOpenSSLError("verification");

cleanup:
    EVP_PKEY_CTX_free(verify_context);
    EVP_SIGNATURE_free(algorithm);
    return result;
}

static int SignAndVerify(
    EVP_PKEY* key,
    const unsigned char* message,
    const size_t message_size,
    unsigned char* context_string,
    const size_t context_size,
    unsigned char* test_entropy,
    const size_t test_entropy_size,
    const int randomized,
    unsigned char* signature,
    uint64_t* sign_ns,
    uint64_t* verify_ns)
{
    int deterministic = randomized ? 0 : 1;
    OSSL_PARAM parameters[4];
    size_t parameter_index = 0;
    parameters[parameter_index++] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context_string, context_size);
    if (test_entropy != NULL) {
        parameters[parameter_index++] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY, test_entropy, test_entropy_size);
    } else {
        parameters[parameter_index++] = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    }
    parameters[parameter_index] = OSSL_PARAM_construct_end();
    EVP_SIGNATURE* algorithm = EVP_SIGNATURE_fetch(NULL, ALGORITHM, NULL);
    EVP_PKEY_CTX* sign_context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    size_t signature_size = SIGNATURE_SIZE;
    int result = 0;

    if (algorithm == NULL || sign_context == NULL ||
        EVP_PKEY_sign_message_init(sign_context, algorithm, parameters) <= 0) {
        PrintOpenSSLError("sign initialization");
        goto cleanup;
    }

    const uint64_t sign_started = MonotonicNs();
    if (EVP_PKEY_sign(sign_context, signature, &signature_size, message, message_size) <= 0 ||
        signature_size != SIGNATURE_SIZE) {
        PrintOpenSSLError("signing");
        goto cleanup;
    }
    *sign_ns = MonotonicNs() - sign_started;

    result = VerifySignature(
        key,
        message,
        message_size,
        context_string,
        context_size,
        signature,
        signature_size,
        verify_ns);
    if (result == 0) fprintf(stderr, "openssl_oracle: generated signature did not verify\n");

cleanup:
    EVP_PKEY_CTX_free(sign_context);
    EVP_SIGNATURE_free(algorithm);
    return result > 0;
}

static int RunKeygen(const char* seed_hex)
{
    unsigned char seed[KEYGEN_SEED_SIZE];
    unsigned char private_key[PRIVATE_KEY_SIZE];
    unsigned char public_key[PUBLIC_KEY_SIZE];
    uint64_t keygen_ns = 0;
    int result = 1;

    if (!OracleDecodeHexExact(seed_hex, seed, sizeof(seed))) {
        fprintf(
            stderr,
            "openssl_oracle: keygen seed must be %u bytes\n",
            (unsigned int)KEYGEN_SEED_SIZE);
        return result;
    }
    EVP_PKEY* key = GenerateKey(seed, &keygen_ns);
    if (key == NULL) return result;
    if (!ExportKeys(key, private_key, public_key)) {
        EVP_PKEY_free(key);
        return result;
    }
    EVP_PKEY_free(key);

    PrintHex("pk", public_key, sizeof(public_key));
    PrintHex("sk", private_key, sizeof(private_key));
    printf("keygen_ns=%llu\n", (unsigned long long)keygen_ns);
    result = 0;
    return result;
}

static int RunPublicKey(const char* key_hex)
{
    unsigned char private_key[PRIVATE_KEY_SIZE];
    unsigned char public_key[PUBLIC_KEY_SIZE];
    size_t public_key_size = 0;
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, private_key, sizeof(private_key))) {
        fprintf(
            stderr,
            "openssl_oracle: private key must be %u bytes\n",
            (unsigned int)PRIVATE_KEY_SIZE);
        return result;
    }
    EVP_PKEY* key = ImportPrivateKey(private_key);
    if (key == NULL) return result;
    if (EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY, public_key, sizeof(public_key), &public_key_size) <= 0 ||
        public_key_size != PUBLIC_KEY_SIZE) {
        PrintOpenSSLError("public-key derivation");
        EVP_PKEY_free(key);
        return result;
    }
    EVP_PKEY_free(key);

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
    size_t randomizer_size = 0;
    unsigned char private_key[PRIVATE_KEY_SIZE];
    unsigned char message[ORACLE_MAX_MESSAGE_SIZE];
    unsigned char context_string[ORACLE_MAX_CONTEXT_SIZE];
    unsigned char randomizer[RANDOMIZER_SIZE];
    unsigned char signature[SIGNATURE_SIZE];
    unsigned char* randomizer_pointer = NULL;
    uint64_t sign_ns = 0;
    uint64_t verify_ns = 0;
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, private_key, sizeof(private_key)) ||
        !OracleDecodeHexBounded(
            message_hex, message, sizeof(message), &message_size) ||
        !OracleDecodeHexBounded(
            context_hex, context_string, sizeof(context_string), &context_size) ||
        (randomizer_hex != NULL &&
         !OracleDecodeHexExact(randomizer_hex, randomizer, sizeof(randomizer)))) {
        fprintf(stderr, "openssl_oracle: invalid sign input\n");
        return result;
    }
    if (randomizer_hex != NULL) {
        randomizer_pointer = randomizer;
        randomizer_size = sizeof(randomizer);
    }
    EVP_PKEY* key = ImportPrivateKey(private_key);
    if (key == NULL) return result;
    if (!SignAndVerify(
            key,
            message,
            message_size,
            context_string,
            context_size,
            randomizer_pointer,
            randomizer_size,
            randomized,
            signature,
            &sign_ns,
            &verify_ns)) {
        EVP_PKEY_free(key);
        return result;
    }
    EVP_PKEY_free(key);

    PrintHex("signature", signature, SIGNATURE_SIZE);
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
    unsigned char public_key[PUBLIC_KEY_SIZE];
    unsigned char message[ORACLE_MAX_MESSAGE_SIZE];
    unsigned char context_string[ORACLE_MAX_CONTEXT_SIZE];
    unsigned char signature[ORACLE_MAX_VERIFY_SIGNATURE_SIZE];
    uint64_t verify_ns = 0;
    int result = 1;

    if (!OracleDecodeHexExact(key_hex, public_key, sizeof(public_key)) ||
        !OracleDecodeHexBounded(
            message_hex, message, sizeof(message), &message_size) ||
        !OracleDecodeHexBounded(
            context_hex, context_string, sizeof(context_string), &context_size) ||
        !OracleDecodeHexBounded(
            signature_hex, signature, sizeof(signature), &signature_size)) {
        fprintf(stderr, "openssl_oracle: invalid verify input\n");
        return result;
    }
    if (signature_size != SIGNATURE_SIZE) {
        printf("verified=0\n");
        printf("verify_ns=0\n");
        return 0;
    }
    EVP_PKEY* key = ImportPublicKey(public_key);
    if (key == NULL) return result;
    const int verified = VerifySignature(
        key,
        message,
        message_size,
        context_string,
        context_size,
        signature,
        signature_size,
        &verify_ns);
    EVP_PKEY_free(key);
    if (verified < 0) return result;

    printf("verified=%d\n", verified == 1);
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

    fprintf(stderr, "usage: openssl_oracle keygen <seed-hex>\n");
    fprintf(stderr, "       openssl_oracle public-key <sk-hex>\n");
    fprintf(stderr, "       openssl_oracle sign <sk-hex> <message-hex> <context-hex>\n");
    fprintf(
        stderr,
        "       openssl_oracle sign-randomized <sk-hex> <message-hex> <context-hex>\n");
    fprintf(stderr,
            "       openssl_oracle sign-with-randomizer <sk-hex> <message-hex> "
            "<context-hex> <randomizer-hex>\n");
    fprintf(stderr,
            "       openssl_oracle verify <pk-hex> <message-hex> <context-hex> "
            "<signature-hex>\n");
    return 2;
}
