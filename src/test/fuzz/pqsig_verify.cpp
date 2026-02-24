// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/params.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <algorithm>
#include <array>
#include <vector>

namespace {

std::vector<uint8_t> ConsumeVariableBytes(FuzzedDataProvider& provider, const size_t max_size)
{
    const size_t size = provider.ConsumeIntegralInRange<size_t>(0, max_size);
    return provider.ConsumeBytes<uint8_t>(size);
}

std::vector<uint8_t> BuildValidPkScript(FuzzedDataProvider& provider)
{
    std::array<uint8_t, pqsig::params::N> pk_seed{};
    for (uint8_t& b : pk_seed) {
        b = provider.ConsumeIntegral<uint8_t>();
    }

    const std::array<std::span<const uint8_t>, 1> parts{std::span<const uint8_t>{pk_seed}};
    const auto pk_root = pqsig::domains::HashN(nullptr, "PQSIG-PK-ROOT", parts);

    std::vector<uint8_t> pk(pqsig::PK_SCRIPT_SIZE);
    pk[0] = pqsig::ALG_ID_V1;
    std::copy(pk_seed.begin(), pk_seed.end(), pk.begin() + 1);
    std::copy(pk_root.begin(), pk_root.end(), pk.begin() + 1 + pk_seed.size());
    return pk;
}

void MutateLayerCounter(FuzzedDataProvider& provider, std::vector<uint8_t>& sig)
{
    if (sig.size() != pqsig::SIG_SIZE) return;

    const size_t layer = provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::D - 1);
    const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
    const size_t count_offset = layer_offset + pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
    sig[count_offset] ^= provider.ConsumeIntegral<uint8_t>();
}

} // namespace

FUZZ_TARGET(pqsig_verify)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    std::vector<uint8_t> sig = ConsumeVariableBytes(provider, pqsig::SIG_SIZE + 64);
    std::vector<uint8_t> msg = ConsumeVariableBytes(provider, pqsig::MSG32_SIZE + 16);
    std::vector<uint8_t> pk = ConsumeVariableBytes(provider, pqsig::PK_SCRIPT_SIZE + 16);

    (void)pqsig::PQSigVerify(sig, msg, pk);

    // Structured path to force parser/verify coverage under valid outer wire sizes.
    if (provider.ConsumeBool()) {
        sig = provider.ConsumeBytes<uint8_t>(pqsig::SIG_SIZE);
        sig.resize(pqsig::SIG_SIZE, 0);
        msg = provider.ConsumeBytes<uint8_t>(pqsig::MSG32_SIZE);
        msg.resize(pqsig::MSG32_SIZE, 0);
        pk = BuildValidPkScript(provider);

        if (provider.ConsumeBool()) {
            MutateLayerCounter(provider, sig);
        }
        if (provider.ConsumeBool()) {
            const size_t off = provider.ConsumeIntegralInRange<size_t>(0, pk.size() - 1);
            pk[off] ^= provider.ConsumeIntegral<uint8_t>();
        }
        if (provider.ConsumeBool()) {
            const size_t off = provider.ConsumeIntegralInRange<size_t>(0, msg.size() - 1);
            msg[off] ^= provider.ConsumeIntegral<uint8_t>();
        }

        (void)pqsig::PQSigVerify(sig, msg, pk);
    }
}
