// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_NODE_H
#define BITCOIN_CRYPTO_MLDSA44_NODE_H
#include <crypto/mldsa44/contract.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
class CChainParams;
class CCoinsViewCache;
class uint256;
namespace pqbtc::mldsa44::node {
// Effective C++ genesis/header and message start must match frozen CONTRACT-1 B.
// This is an identity check, NOT an activation/absence-guard admission decision.
Network ResolveNetwork(const CChainParams& params);
// Only for the fixed demo H=1: require the complete effective pre-H UTXO set
// to be empty. This is not a nonempty-chain production inventory algorithm.
void CheckDemoActivation(const CChainParams& params,const uint256& previous,
    const CCoinsViewCache& coins);
void CheckDemoStartup(const CChainParams& params,const CCoinsViewCache& coins);
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
    // Advisory prevout shape only; interpreter dispatch/verification is authoritative.
    bool IsApplicable(size_t index) const;
    // Signature correctness only, not current Coin liveness/maturity/activation.
    // Callers must discard acceptance results after Coin-state/context changes;
    // this owned snapshot is not a cross-chain or best-block-keyed result cache.
    bool VerifyInput(const CChainParams& params,size_t index) const;
    // Requires the exact witness stack storage in Transaction().vin[index],
    // not a copy. The validation caller must share this same CTransactionRef
    // and construct from its actual Coin view while holding the validation lock.
    bool CheckWitness(const CChainParams& params,size_t index,
        std::span<const unsigned char> program,std::span<const Bytes> witness) const;
    const CTransaction& Transaction() const { return *m_transaction; }
};
// Snapshot, params and inherited checker must outlive this scoped checker.
// No caching or network admission is granted by constructing it.
class ScriptChecker final : public DeferringSignatureChecker {
    const Snapshot& m_snapshot;
    const CChainParams& m_params;
    size_t m_index;
public:
    ScriptChecker(const Snapshot& snapshot,const CChainParams& params,size_t index,
        const BaseSignatureChecker& inherited):DeferringSignatureChecker(inherited),
        m_snapshot(snapshot),m_params(params),m_index(index) {}
    bool CheckMLDSA44Witness(std::span<const unsigned char> program,
        std::span<const Bytes> witness) const override;
};
} // namespace pqbtc::mldsa44::node
#endif
