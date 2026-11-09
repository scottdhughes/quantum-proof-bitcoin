// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_IPC_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_IPC_H
#include <crypto/mldsa44/contract.h>
#include <crypto/mldsa44/signer/error.h>
namespace pqbtc::mldsa44::signer {
using RequestId = std::array<unsigned char, 16>;
using Witnesses = std::vector<std::array<Bytes, 2>>;
struct Derivation { uint8_t branch; uint32_t index; };
struct Header { uint8_t kind; RequestId id; uint32_t body_size; };
struct Frame { uint8_t kind; RequestId id; Bytes body; };
struct Response { uint16_t status; Bytes payload; };
struct SignRequest { RequestId wallet_id; Transaction transaction; std::vector<Output> prevouts; std::vector<Derivation> paths; };
Header DecodeHeader(std::span<const unsigned char> header, bool response);
Frame DecodeRequest(std::span<const unsigned char> frame);
Bytes EncodeRequest(const Frame& frame);
Bytes EncodeResponse(const Frame& request, const Response& response);
Response DecodeResponse(std::span<const unsigned char> frame, const Frame& expected);
Bytes EncodeSignRequest(const SignRequest& request);
SignRequest DecodeSignRequest(std::span<const unsigned char> body);
} // namespace pqbtc::mldsa44::signer
#endif // BITCOIN_CRYPTO_MLDSA44_SIGNER_IPC_H
