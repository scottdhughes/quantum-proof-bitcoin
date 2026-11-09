// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_SESSION_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_SESSION_H
#include <crypto/mldsa44/signer/wallet.h>
#include <set>
namespace pqbtc::mldsa44::signer {
// One serial worker owns each Session. Transport must authenticate peer first.
class Session {
    Wallet& m_wallet; Network m_network; Hash m_spec; uint64_t m_fee_cap;
    std::set<RequestId> m_seen; unsigned m_completed{0}; bool m_bound{false};
public:
    Session(Wallet& wallet, Network network, Hash spec, uint64_t fee_cap)
        : m_wallet(wallet),m_network(network),m_spec(spec),m_fee_cap(fee_cap) {}
    Response Handle(const Frame& frame);
    bool Done() const { return m_completed>=64; }
};
} // namespace pqbtc::mldsa44::signer
#endif // BITCOIN_CRYPTO_MLDSA44_SIGNER_SESSION_H
