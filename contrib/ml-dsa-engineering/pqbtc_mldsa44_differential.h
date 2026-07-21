// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_DIFFERENTIAL_H
#define BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_DIFFERENTIAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pqbtc_mldsa44_oracle_result {
    PQBTC_MLDSA44_ORACLE_ERROR = -1,
    PQBTC_MLDSA44_ORACLE_REJECT = 0,
    PQBTC_MLDSA44_ORACLE_ACCEPT = 1
};

int pqbtc_mldsa44_openssl_verify(
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size);

int pqbtc_mldsa44_libcrux_verify(
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* message,
    size_t message_size,
    const uint8_t* context,
    size_t context_size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_DIFFERENTIAL_H
