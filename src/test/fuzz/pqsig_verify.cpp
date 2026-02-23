// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <array>
#include <vector>

FUZZ_TARGET(pqsig_verify)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    std::vector<uint8_t> sig = provider.ConsumeBytes<uint8_t>(pqsig::SIG_SIZE);
    std::vector<uint8_t> msg = provider.ConsumeBytes<uint8_t>(pqsig::MSG32_SIZE);
    std::vector<uint8_t> pk = provider.ConsumeBytes<uint8_t>(pqsig::PK_SCRIPT_SIZE);

    (void)pqsig::PQSigVerify(sig, msg, pk);
}
