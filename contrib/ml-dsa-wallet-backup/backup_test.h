// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_ML_DSA_WALLET_BACKUP_TEST_H
#define BITCOIN_ML_DSA_WALLET_BACKUP_TEST_H
#ifndef PQBTC_MLDSA44_TESTING
#error Backup test controls are not a normal API
#endif
#include <stddef.h>
enum { TEST_RANDOM_FIXED=1, TEST_RANDOM_FAIL, TEST_RANDOM_ZERO,
       TEST_KDF_FAIL, TEST_CONTEXT_FAIL, TEST_ENCRYPT_FAIL, TEST_DECRYPT_FAIL,
       TEST_IMPORT_FAIL, TEST_BAD_COMMITMENT, TEST_AFTER_IMPORT_FAIL };
void pqbtc_backup_test_reset(void);
void pqbtc_backup_test_stage(int);
int pqbtc_backup_test_clean(void);
size_t pqbtc_backup_test_derivations(void);
#endif // BITCOIN_ML_DSA_WALLET_BACKUP_TEST_H
