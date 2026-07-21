// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_CONFIG_H
#define BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_CONFIG_H

#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX pqbtc_mldsa44_upstream
#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_NO_SUPERCOP
#define MLD_CONFIG_NO_ASM
#define MLD_CONFIG_MAX_SIGNING_ATTEMPTS 814

#if defined(PQBTC_MLDSA44_CT_TESTING)
#if !defined(PQBTC_MLDSA44_TESTING)
#error PQBTC_MLDSA44_CT_TESTING requires PQBTC_MLDSA44_TESTING
#endif
#define MLD_CONFIG_CT_TESTING_ENABLED
#endif

#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#define mld_randombytes pqbtc_mldsa44_randombytes

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize pqbtc_mldsa44_zeroize

#endif // BITCOIN_ML_DSA_ENGINEERING_PQBTC_MLDSA44_CONFIG_H
