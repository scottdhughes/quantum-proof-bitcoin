// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_WALLET_CRYPTO_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_WALLET_CRYPTO_H
#include <crypto/mldsa44/contract.h>
#include <crypto/mldsa44/signer/secret.h>

namespace pqbtc::mldsa44::signer {
using Identity = std::array<unsigned char, 16>;
using Record = std::array<unsigned char, 167>;
struct Counters { uint32_t receive, change; bool operator==(const Counters&) const = default; };
struct RecordInfo { Identity id; uint64_t generation; Counters next; };
void RandomBytes(std::span<unsigned char> output);
void ValidatePassphrase(std::span<const unsigned char> password);
void DeriveSeed(std::span<const unsigned char, 32> root, Network network,
    uint8_t branch, uint32_t index, std::span<unsigned char, 32> output);
Identity WalletId(std::span<const unsigned char, 32> root, Network network);
Record SealRecord(std::span<const unsigned char, 32> root, Network network, Counters next,
    std::span<const unsigned char> password, uint64_t generation);
// Output is ZERO on ANY failure. Plaintext is not published before GCM final+ID checks.
RecordInfo OpenRecord(std::span<const unsigned char> record, Network network,
    std::span<const unsigned char> password, std::span<unsigned char, 40> output);
const char* CryptoVersion();
} // namespace pqbtc::mldsa44::signer
#endif
