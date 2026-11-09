// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_CONTRACT_H
#define BITCOIN_CRYPTO_MLDSA44_CONTRACT_H
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pqbtc::mldsa44 {
using Bytes = std::vector<unsigned char>;
using Hash = std::array<unsigned char, 32>;
enum class Network { MAIN, TEST, REGTEST };
// Views for adapter interoperability, not a replacement for CTransaction or UTXO lookup.
struct Input { Hash hash; uint32_t index; uint32_t sequence; }; // hash in internal/wire order, not display hex.
struct Output { uint64_t amount; Bytes script; };
struct Transaction { int32_t version; std::vector<Input> inputs; std::vector<Output> outputs; uint32_t lock_time; };

// Immutable owned snapshot: component hashes computed once; no signer-policy
// limits become consensus. Caller must apply actual node transaction/resource
// rules before construction. It must bind this object to that same transaction.
class PreparedTransaction {
    Bytes m_body;
    std::vector<Bytes> m_scripts;
public:
    PreparedTransaction(const Transaction& tx, std::span<const Output> prevouts);
    friend Hash SigningMessage(Network, const PreparedTransaction&, size_t);
    friend bool VerifyWitness(Network, const PreparedTransaction&, size_t,
        std::span<const unsigned char>, std::span<const Bytes>);
};

// Invalid model/input data throws std::invalid_argument; allocation failure is not hidden.
Bytes SerializeUnsigned(const Transaction& tx, std::span<const Output> prevouts);
Transaction ParseUnsigned(std::span<const unsigned char> wire, std::span<const Output> prevouts);
Bytes NetworkBinding(Network network);
Hash SigningMessage(Network network, const PreparedTransaction& tx, size_t input_index);
Hash KeyCommitment(Network network, std::span<const unsigned char> public_key);
bool VerifyWitness(Network network, const PreparedTransaction& tx,
    size_t input_index, std::span<const unsigned char> program, std::span<const Bytes> witness);
} // namespace pqbtc::mldsa44
#endif // BITCOIN_CRYPTO_MLDSA44_CONTRACT_H
