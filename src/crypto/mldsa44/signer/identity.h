// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_IDENTITY_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_IDENTITY_H

#include <crypto/mldsa44/contract.h>

namespace pqbtc::mldsa44::signer {
// SHA256 of the sealed CONTRACT-1 document bytes. TEST tools must match this
// identity before custody/connect; regtest keeps generic historical fixtures.
inline constexpr Hash CONTRACT_SPEC_SHA256{
    0xc7,0x99,0x3d,0x7f,0x2a,0xe7,0x26,0x23,0xcf,0x3b,0x9e,0x2f,0x45,0xc0,0x21,0x88,
    0x5f,0x61,0x0e,0xf3,0x16,0x9d,0xbf,0x17,0x6e,0x0c,0x2d,0xd1,0xa6,0x19,0xd1,0x26};
} // namespace pqbtc::mldsa44::signer
#endif // BITCOIN_CRYPTO_MLDSA44_SIGNER_IDENTITY_H
