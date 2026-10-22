// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include "verify.h"

static void pqbtc_mldsa44_node_zeroize(void* ptr, size_t size);

#define MLD_CONFIG_FILE "verify_config.h"
#include "../../../contrib/ml-dsa-engineering/vendor/mldsa-native/mldsa/mldsa_native.h"
#include "../../../contrib/ml-dsa-engineering/vendor/mldsa-native/mldsa/mldsa_native.c"

static void pqbtc_mldsa44_node_zeroize(void* ptr, size_t size)
{
    volatile uint8_t* cursor = (volatile uint8_t*)ptr;
    while (size-- != 0) *cursor++ = 0;
}

int pqbtc_mldsa44_node_verify(const uint8_t* signature, size_t signature_size,
    const uint8_t* public_key, size_t public_key_size,
    const uint8_t* message, size_t message_size)
{
    static const uint8_t context[] = "PQBTC/MLDSA44/tx/v1";
    if (signature == NULL || signature_size != 2420 || public_key == NULL ||
        public_key_size != 1312 || message == NULL || message_size != 32) return 0;
    return pqbtc_mldsa44_node_upstream_verify(signature, message, message_size,
        context, sizeof(context) - 1, public_key) == 0;
}
