// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_ERROR_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_ERROR_H
#include <cstdint>
#include <stdexcept>
namespace pqbtc::mldsa44::signer {
enum class Code : uint16_t { INVALID_FRAME=1, VERSION, BINDING, AUTH, LOCKED, LIMIT,
    UNSUPPORTED, REPLAY, VALIDATION, ENTROPY, SELFVERIFY, STORAGE, INTERNAL };
struct Error : std::runtime_error {
    Code code;
    explicit Error(Code value) : std::runtime_error("ML-DSA signer operation refused"), code(value) {}
};
inline void Require(bool value, Code code = Code::VALIDATION) { if (!value) throw Error(code); }
} // namespace pqbtc::mldsa44::signer
#endif // BITCOIN_CRYPTO_MLDSA44_SIGNER_ERROR_H
