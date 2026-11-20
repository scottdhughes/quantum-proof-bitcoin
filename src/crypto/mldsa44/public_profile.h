// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_PUBLIC_PROFILE_H
#define BITCOIN_CRYPTO_MLDSA44_PUBLIC_PROFILE_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>

namespace pqbtc::mldsa44::node {
inline constexpr char PUBLIC_PROFILE_SHA256[] = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933";
inline constexpr char PUBLIC_MANIFEST_SHA256[] = "8595edee7a9523c2ff615509ed828a2b135e88da95b63d3f336c9d0eb768f0fd";

inline bool IsNativePublicScript(const CScript& script)
{
    return script.size() == 34 && script[0] == OP_2 && script[1] == 32;
}

// Share the sealed signer output grammar with policy without creating a
// bitcoin_common -> bitcoin_mldsa44_node library dependency. "Canonical" here
// means a direct byte push (or PUSHDATA1 for 76..80), as in CONTRACT-1 wallets.
inline bool IsPublicOutput(const CTxOut& output)
{
    if (!MoneyRange(output.nValue)) return false;
    const auto& script = output.scriptPubKey;
    if (IsNativePublicScript(script)) return true;
    if (output.nValue != 0 || script.size() < 2 || script[0] != OP_RETURN) return false;
    const size_t size = script[1];
    if (size <= 75) return script.size() == size + 2;
    return size == OP_PUSHDATA1 && script.size() >= 3 && script[2] >= 76 && script[2] <= 80 &&
        script.size() == size_t{script[2]} + 3;
}
} // namespace pqbtc::mldsa44::node
#endif // BITCOIN_CRYPTO_MLDSA44_PUBLIC_PROFILE_H
