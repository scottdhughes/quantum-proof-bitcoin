// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "pqbtc_mldsa44.h"
#include "pqbtc_mldsa44_differential.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PQBTC_MLDSA44_OPENSSL_ALGORITHM "ML-DSA-44"
#define PQBTC_MLDSA44_OPENSSL_PROPERTIES "provider=default"

static int InvalidByteString(const uint8_t* value, size_t size)
{
    return size != 0 && value == NULL;
}

static int OracleError(const char* stage)
{
    unsigned long error_code = ERR_peek_last_error();

    fprintf(
        stderr,
        "PQBTC_MLDSA44_OPENSSL_ORACLE_ERROR stage=%s code=%lu\n",
        stage,
        error_code);
    fflush(stderr);
    ERR_clear_error();
    return PQBTC_MLDSA44_ORACLE_ERROR;
}

static EVP_PKEY* ImportPublicKey(
    OSSL_LIB_CTX* library_context,
    const uint8_t* public_key,
    int* result)
{
    EVP_PKEY_CTX* context =
        EVP_PKEY_CTX_new_from_name(
            library_context,
            PQBTC_MLDSA44_OPENSSL_ALGORITHM,
            PQBTC_MLDSA44_OPENSSL_PROPERTIES);
    EVP_PKEY* key = NULL;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            (void*)public_key,
            PQBTC_MLDSA44_PUBLIC_KEY_BYTES),
        OSSL_PARAM_construct_end(),
    };

    if (context == NULL) {
        *result = OracleError("public_key_context");
    } else if (EVP_PKEY_fromdata_init(context) <= 0) {
        *result = OracleError("public_key_import_init");
    } else if (
        EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) <= 0) {
        *result = OracleError("public_key_import");
    } else {
        *result = PQBTC_MLDSA44_ORACLE_ACCEPT;
    }
    EVP_PKEY_CTX_free(context);
    if (*result != PQBTC_MLDSA44_ORACLE_ACCEPT) EVP_PKEY_free(key);
    return *result == PQBTC_MLDSA44_ORACLE_ACCEPT ? key : NULL;
}

int pqbtc_mldsa44_openssl_verify(
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size)
{
    static const uint8_t empty[1] = {0};
    OSSL_LIB_CTX* library_context = NULL;
    OSSL_PROVIDER* default_provider = NULL;
    EVP_PKEY* key = NULL;
    EVP_SIGNATURE* algorithm = NULL;
    EVP_PKEY_CTX* verify_context = NULL;
    OSSL_PARAM parameters[2];
    int imported;
    int result;
    int verified;

    if (signature == NULL || signature_size != PQBTC_MLDSA44_SIGNATURE_BYTES ||
        public_key == NULL || public_key_size != PQBTC_MLDSA44_PUBLIC_KEY_BYTES ||
        InvalidByteString(message, message_size) ||
        InvalidByteString(context, context_size) ||
        context_size > PQBTC_MLDSA44_MAX_CONTEXT_BYTES) {
        return PQBTC_MLDSA44_ORACLE_REJECT;
    }
    if (message == NULL) message = empty;
    if (context == NULL) context = empty;

    ERR_clear_error();
    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) return OracleError("library_context");
    default_provider = OSSL_PROVIDER_load(library_context, "default");
    if (default_provider == NULL) {
        result = OracleError("default_provider_load");
        goto cleanup;
    }

    key = ImportPublicKey(library_context, public_key, &imported);
    if (key == NULL) {
        result = imported;
        goto cleanup;
    }

    algorithm = EVP_SIGNATURE_fetch(
        library_context,
        PQBTC_MLDSA44_OPENSSL_ALGORITHM,
        PQBTC_MLDSA44_OPENSSL_PROPERTIES);
    if (algorithm == NULL) {
        result = OracleError("signature_fetch");
        goto cleanup;
    }
    verify_context = EVP_PKEY_CTX_new_from_pkey(
        library_context, key, PQBTC_MLDSA44_OPENSSL_PROPERTIES);
    if (verify_context == NULL) {
        result = OracleError("verify_context");
        goto cleanup;
    }
    parameters[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)context, context_size);
    parameters[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_verify_message_init(verify_context, algorithm, parameters) <= 0) {
        result = OracleError("verify_init");
        goto cleanup;
    }

    verified = EVP_PKEY_verify(
        verify_context, signature, signature_size, message, message_size);
    if (verified < 0) {
        result = OracleError("verify");
        goto cleanup;
    }
    ERR_clear_error();
    result = verified == 1 ? PQBTC_MLDSA44_ORACLE_ACCEPT :
                             PQBTC_MLDSA44_ORACLE_REJECT;

cleanup:
    EVP_PKEY_CTX_free(verify_context);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_free(key);
    if (default_provider != NULL) OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(library_context);
    return result;
}
