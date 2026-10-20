// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_TEST_H
#define BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_TEST_H
#ifndef PQBTC_MLDSA44_TESTING
#error Key lifecycle test controls require PQBTC_MLDSA44_TESTING
#endif

#include <stddef.h>

void pqbtc_mldsa44_key_test_reset(void);
void pqbtc_mldsa44_key_test_fail_allocation(int enabled);
void pqbtc_mldsa44_key_test_fail_keygen(int enabled);
size_t pqbtc_mldsa44_key_test_releases(void);
size_t pqbtc_mldsa44_key_test_allocation_size(void);
int pqbtc_mldsa44_key_test_release_zero(void);
/* Only generation's digest scratch; durable seed erasure is a release check. */
int pqbtc_mldsa44_key_test_generation_scratch_zero(void);

#endif // BITCOIN_ML_DSA_KEY_LIFECYCLE_KEY_LIFECYCLE_TEST_H
