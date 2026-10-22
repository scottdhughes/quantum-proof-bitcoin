// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_NODE_H
#define BITCOIN_CRYPTO_MLDSA44_NODE_H
#include <crypto/mldsa44/contract.h>
#include <primitives/transaction.h>
class CChainParams;
class CCoinsViewCache;
namespace pqbtc::mldsa44::node {
// Effective C++ genesis/header and message start must match frozen CONTRACT-1 B.
// This is an identity check, NOT an activation/absence-guard admission decision.
Network ResolveNetwork(const CChainParams& params);
class Snapshot {
    // Declaration order is required: Prepare fills programs from the held tx.
    CTransactionRef m_transaction;
    std::vector<Bytes> m_programs;
    PreparedTransaction m_prepared;
public:
    // Caller holds the node Coin-view validation lock throughout construction.
    // All metadata is copied now; no references to mutable Coin entries escape.
    Snapshot(CTransactionRef tx,const CCoinsViewCache& coins);
    Snapshot(const Snapshot&)=delete;
    Snapshot& operator=(const Snapshot&)=delete;
    Snapshot(Snapshot&&)=delete;
    Snapshot& operator=(Snapshot&&)=delete;
    Hash Message(Network network,size_t index) const; // byte-model interoperability only
    // Signature correctness only, not current Coin liveness/maturity/activation.
    // Callers must discard acceptance results after Coin-state/context changes;
    // this owned snapshot is not a cross-chain or best-block-keyed result cache.
    bool VerifyInput(const CChainParams& params,size_t index) const;
    const CTransaction& Transaction() const { return *m_transaction; }
};
} // namespace pqbtc::mldsa44::node
#endif
