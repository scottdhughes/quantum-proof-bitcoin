// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_VERIFY_CONFIG_H
#define BITCOIN_CRYPTO_MLDSA44_VERIFY_CONFIG_H
#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX pqbtc_mldsa44_node_upstream
#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_NO_ASM
#define MLD_CONFIG_NO_KEYPAIR_API
#define MLD_CONFIG_NO_SIGN_API
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize pqbtc_mldsa44_node_zeroize
#endif // BITCOIN_CRYPTO_MLDSA44_VERIFY_CONFIG_H
