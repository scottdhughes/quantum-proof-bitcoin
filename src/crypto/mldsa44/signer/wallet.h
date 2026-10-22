// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_WALLET_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_WALLET_H
#include <crypto/mldsa44/signer/wallet_crypto.h>
#include <memory>
#include <mutex>
#include <string>

namespace pqbtc::mldsa44::signer {
struct Address {
    uint8_t branch{0}; uint32_t index{0};
    std::array<unsigned char, 1312> public_key{};
    Hash program{};
};
struct Recovery { Identity expected_id; Counters minimum; std::vector<Address> public_entries; };
struct WalletStatus { bool locked; Identity id; Counters next; uint64_t generation; };

// Experimental signer-only custody engine. Not linked to the node, no main/test
// address issuance or activation authority. Caller must serialize operator input;
// the class serializes its methods and never exports root/passphrase/child seeds.
class Wallet {
    struct State;
    std::unique_ptr<State> m_secret;
    Network m_network;
    int m_directory{-1}, m_lock{-1};
    pid_t m_origin{getpid()};
    RecordInfo m_info{};
    bool m_poisoned{false};
    mutable std::mutex m_mutex;
    void CheckLive() const;
    Address PublicUnchecked(uint8_t branch, uint32_t index);
    void Save(Counters next, bool create = false);
public:
    Wallet(const std::string& directory, Network network);
    ~Wallet();
    Wallet(const Wallet&) = delete;
    Wallet& operator=(const Wallet&) = delete;
    void Create(std::span<const unsigned char> passphrase);
    void Unlock(std::span<const unsigned char> passphrase, const Recovery& recovery);
    void Lock();
    Address Reserve(uint8_t branch);
    Address Public(uint8_t branch, uint32_t index);
    WalletStatus Status() const;
};
} // namespace pqbtc::mldsa44::signer
#endif
