// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_SERVICE_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_SERVICE_H
#include <crypto/mldsa44/signer/session.h>
#include <csignal>
namespace pqbtc::mldsa44::signer {
struct ServiceOptions { std::string socket; uid_t node_uid; Network network; Hash spec; uint64_t fee_cap; };
void RunService(Wallet& wallet,const ServiceOptions& options,volatile std::sig_atomic_t& stop);
} // namespace pqbtc::mldsa44::signer
#endif
