// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_ML_DSA_WALLET_BACKUP_FILE_H
#define BITCOIN_ML_DSA_WALLET_BACKUP_FILE_H
#include "backup.h"
/* Held directory FD must be owned0700. A basename, not a path. Store never
 * replaces an existing name. INDETERMINATE means publication happened but
 * durability/cleanup failed: do not retry as though nothing was written.
 * Load requires a regular owned0600 single-link file and exact176 bytes.
 * Buffers must be accessible; caller excludes hostile concurrent mutation. */
int pqbtc_backup_store_at(int dirfd,const char* basename,const uint8_t package[176]);
int pqbtc_backup_load_at(int dirfd,const char* basename,uint8_t package[176]);
#ifdef PQBTC_BACKUP_FILE_TESTING
enum { FILE_INTERRUPT_WRITE=1, FILE_NOSPC, FILE_SYNC, FILE_LINK,
       FILE_UNLINK, FILE_SYNC_DIR, FILE_INTERRUPT_READ, FILE_READ_FAIL,
       FILE_CLOSE, FILE_WRONG_OWNER };
void pqbtc_backup_file_test_stage(int);
#endif
#endif // BITCOIN_ML_DSA_WALLET_BACKUP_FILE_H
