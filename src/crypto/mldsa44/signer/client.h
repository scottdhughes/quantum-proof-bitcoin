// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_CLIENT_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_CLIENT_H
#include <crypto/mldsa44/signer/ipc.h>
#include <crypto/mldsa44/signer/transport.h>
namespace pqbtc::mldsa44::signer {
// Public-only client. Correlation IDs are counters, not authorization nonces.
class Client {
    detail::Fd m_fd;
    uint64_t m_sequence{0};
public:
    Client(const std::string& socket,uid_t signer_uid,Network network,Hash spec);
    Response Call(uint8_t kind,Bytes body);
};
} // namespace pqbtc::mldsa44::signer
#endif // BITCOIN_CRYPTO_MLDSA44_SIGNER_CLIENT_H
