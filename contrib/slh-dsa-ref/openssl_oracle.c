// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define _POSIX_C_SOURCE 200809L

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALGORITHM "SLH-DSA-SHA2-128s"
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

static unsigned char* DecodeHex(const char* hex, size_t* output_size)
{
    const size_t hex_size = strlen(hex);
    if ((hex_size & 1U) != 0) return NULL;

    *output_size = hex_size / 2;
    unsigned char* output = malloc(*output_size == 0 ? 1 : *output_size);
    if (output == NULL) return NULL;

    for (size_t i = 0; i < *output_size; ++i) {
        const int high = HexDigit(hex[2 * i]);
        const int low = HexDigit(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(output);
            return NULL;
        }
        output[i] = (unsigned char)((high << 4) | low);
    }
    return output;
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
            OSSL_PKEY_PARAM_SLH_DSA_SEED, (void*)seed, KEYGEN_SEED_SIZE),
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
    unsigned char public_key[PUBLIC_KEY_SIZE];
    memcpy(public_key, private_key + PRIVATE_KEY_SIZE - PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0) {
        PrintOpenSSLError("key import initialization");
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void*)private_key, PRIVATE_KEY_SIZE),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public_key, PUBLIC_KEY_SIZE),
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
    size_t seed_size = 0;
    unsigned char* seed = DecodeHex(seed_hex, &seed_size);
    unsigned char private_key[PRIVATE_KEY_SIZE];
    unsigned char public_key[PUBLIC_KEY_SIZE];
    uint64_t keygen_ns = 0;
    int result = 1;

    if (seed == NULL || seed_size != KEYGEN_SEED_SIZE) {
        fprintf(stderr, "openssl_oracle: keygen seed must be %d bytes\n", KEYGEN_SEED_SIZE);
        goto cleanup;
    }
    EVP_PKEY* key = GenerateKey(seed, &keygen_ns);
    if (key == NULL) goto cleanup;
    if (!ExportKeys(key, private_key, public_key)) {
        EVP_PKEY_free(key);
        goto cleanup;
    }
    EVP_PKEY_free(key);

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
    const char* randomizer_hex,
    const int randomized)
{
    size_t key_size = 0;
    size_t message_size = 0;
    size_t context_size = 0;
    size_t randomizer_size = 0;
    unsigned char* private_key = DecodeHex(key_hex, &key_size);
    unsigned char* message = DecodeHex(message_hex, &message_size);
    unsigned char* context_string = DecodeHex(context_hex, &context_size);
    unsigned char* randomizer =
        randomizer_hex == NULL ? NULL : DecodeHex(randomizer_hex, &randomizer_size);
    unsigned char* signature = NULL;
    uint64_t sign_ns = 0;
    uint64_t verify_ns = 0;
    int result = 1;

    if (private_key == NULL || key_size != PRIVATE_KEY_SIZE || message == NULL ||
        context_string == NULL || context_size > 255 ||
        (randomizer_hex != NULL &&
         (randomizer == NULL || randomizer_size != RANDOMIZER_SIZE))) {
        fprintf(stderr, "openssl_oracle: invalid sign input\n");
        goto cleanup;
    }
    EVP_PKEY* key = ImportPrivateKey(private_key);
    if (key == NULL) goto cleanup;
    signature = malloc(SIGNATURE_SIZE);
    if (signature == NULL || !SignAndVerify(
                                 key,
                                 message,
                                 message_size,
                                 context_string,
                                 context_size,
                                 randomizer,
                                 randomizer_size,
                                 randomized,
                                 signature,
                                 &sign_ns,
                                 &verify_ns)) {
        EVP_PKEY_free(key);
        goto cleanup;
    }
    EVP_PKEY_free(key);

    PrintHex("signature", signature, SIGNATURE_SIZE);
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
    unsigned char* public_key = DecodeHex(key_hex, &key_size);
    unsigned char* message = DecodeHex(message_hex, &message_size);
    unsigned char* context_string = DecodeHex(context_hex, &context_size);
    unsigned char* signature = DecodeHex(signature_hex, &signature_size);
    uint64_t verify_ns = 0;
    int result = 1;

    if (public_key == NULL || key_size != PUBLIC_KEY_SIZE || message == NULL ||
        context_string == NULL || context_size > 255 || signature == NULL) {
        fprintf(stderr, "openssl_oracle: invalid verify input\n");
        goto cleanup;
    }
    if (signature_size != SIGNATURE_SIZE) {
        printf("verified=0\n");
        printf("verify_ns=0\n");
        result = 0;
        goto cleanup;
    }
    EVP_PKEY* key = ImportPublicKey(public_key);
    if (key == NULL) goto cleanup;
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
    if (verified < 0) goto cleanup;

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
        return RunSign(argv[2], argv[3], argv[4], NULL, 0);
    }
    if (argc == 5 && strcmp(argv[1], "sign-randomized") == 0) {
        return RunSign(argv[2], argv[3], argv[4], NULL, 1);
    }
    if (argc == 6 && strcmp(argv[1], "sign-with-randomizer") == 0) {
        return RunSign(argv[2], argv[3], argv[4], argv[5], 0);
    }
    if (argc == 6 && strcmp(argv[1], "verify") == 0) {
        return RunVerify(argv[2], argv[3], argv[4], argv[5]);
    }

    fprintf(stderr, "usage: %s keygen <seed-hex>\n", argv[0]);
    fprintf(stderr, "       %s sign <sk-hex> <message-hex> <context-hex>\n", argv[0]);
    fprintf(stderr, "       %s sign-randomized <sk-hex> <message-hex> <context-hex>\n", argv[0]);
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
