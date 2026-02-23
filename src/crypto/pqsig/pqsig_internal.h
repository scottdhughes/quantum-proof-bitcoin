// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_PQSIG_INTERNAL_H
#define BITCOIN_CRYPTO_PQSIG_PQSIG_INTERNAL_H

#include <cstdint>

namespace pqsig {

struct PQSigMetrics {
    uint64_t hash_calls{0};
    uint64_t compression_calls{0};
    uint64_t outer_search_iters{0};
    uint64_t wots_search_iters_total{0};
};

PQSigMetrics GetLastPQSigMetrics();
void ResetPQSigMetrics();

} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_PQSIG_INTERNAL_H
