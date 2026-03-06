// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/params.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <univalue.h>

namespace {

struct PQSigCase
{
    std::vector<uint8_t> msg;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sig;
};

std::vector<uint8_t> ConsumeVariableBytes(FuzzedDataProvider& provider, const size_t max_size)
{
    const size_t size = provider.ConsumeIntegralInRange<size_t>(0, max_size);
    return provider.ConsumeBytes<uint8_t>(size);
}

std::vector<uint8_t> BuildValidPkScript(FuzzedDataProvider& provider)
{
    std::array<uint8_t, pqsig::MSG32_SIZE> sk_seed{};
    for (uint8_t& b : sk_seed) {
        b = provider.ConsumeIntegral<uint8_t>();
    }

    std::vector<uint8_t> pk(pqsig::PK_SCRIPT_SIZE);
    assert(pqsig::DerivePkScript(pk, sk_seed));
    return pk;
}

void MutateLayerCounter(FuzzedDataProvider& provider, std::vector<uint8_t>& sig)
{
    if (sig.size() != pqsig::SIG_SIZE) return;

    const size_t layer = provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::D - 1);
    const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
    const size_t count_offset = layer_offset + pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
    sig[count_offset] ^= provider.ConsumeIntegralInRange<uint8_t>(1, 255);
}

PQSigCase LoadStructuredValidCase()
{
    static constexpr const char* KAT_PATHS[] = {
        "src/test/data/pqsig/kat_v1.json",
        "../src/test/data/pqsig/kat_v1.json",
        "../../src/test/data/pqsig/kat_v1.json",
    };

    std::string json_text;
    for (const char* path : KAT_PATHS) {
        std::ifstream input(path);
        if (!input.good()) continue;
        json_text.assign(std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
        break;
    }
    if (json_text.empty()) {
        throw std::runtime_error("failed to locate pqsig kat vectors");
    }

    UniValue root;
    if (!root.read(json_text)) {
        throw std::runtime_error("failed to parse pqsig kat vectors");
    }

    UniValue vectors = root.isArray() ? root.get_array() : root.get_obj().find_value("vectors");
    if (!vectors.isArray() || vectors.get_array().empty()) {
        throw std::runtime_error("missing pqsig kat vectors");
    }

    const UniValue obj = vectors.get_array()[0].get_obj();
    PQSigCase testcase{
        ParseHex(obj.find_value("msg32").get_str()),
        ParseHex(obj.find_value("pk_script33").get_str()),
        ParseHex(obj.find_value("sig4480").get_str()),
    };
    if (testcase.msg.size() != pqsig::MSG32_SIZE ||
        testcase.pk.size() != pqsig::PK_SCRIPT_SIZE ||
        testcase.sig.size() != pqsig::SIG_SIZE) {
        throw std::runtime_error("unexpected pqsig kat vector sizes");
    }
    return testcase;
}

const PQSigCase& GetStructuredValidCase()
{
    static const PQSigCase testcase = LoadStructuredValidCase();
    return testcase;
}

void XorByte(std::vector<uint8_t>& bytes, const size_t offset, const uint8_t delta)
{
    assert(offset < bytes.size());
    assert(delta != 0);
    bytes[offset] ^= delta;
}

void OverflowLayerCounter(FuzzedDataProvider& provider, std::vector<uint8_t>& sig)
{
    assert(sig.size() == pqsig::SIG_SIZE);

    const size_t layer = provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::D - 1);
    const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
    const size_t count_offset = layer_offset + pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
    std::fill_n(sig.begin() + count_offset, pqsig::params::HT_COUNTER_SIZE, 0xff);
}

void ApplyDeterministicRejectMutation(
    FuzzedDataProvider& provider,
    std::vector<uint8_t>& sig,
    std::vector<uint8_t>& msg,
    std::vector<uint8_t>& pk)
{
    switch (provider.ConsumeIntegralInRange<int>(0, 6)) {
    case 0:
        pk[0] = 0x00;
        break;
    case 1:
        XorByte(pk, 1 + provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::N - 1), provider.ConsumeIntegralInRange<uint8_t>(1, 255));
        break;
    case 2:
        XorByte(pk, 1 + pqsig::params::N + provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::N - 1), provider.ConsumeIntegralInRange<uint8_t>(1, 255));
        break;
    case 3:
        MutateLayerCounter(provider, sig);
        break;
    case 4:
        OverflowLayerCounter(provider, sig);
        break;
    case 5:
        XorByte(msg, provider.ConsumeIntegralInRange<size_t>(0, msg.size() - 1), provider.ConsumeIntegralInRange<uint8_t>(1, 255));
        MutateLayerCounter(provider, sig);
        break;
    case 6:
        XorByte(sig, provider.ConsumeIntegralInRange<size_t>(0, pqsig::params::SIG_R_SIZE - 1), provider.ConsumeIntegralInRange<uint8_t>(1, 255));
        OverflowLayerCounter(provider, sig);
        break;
    }
}

} // namespace

FUZZ_TARGET(pqsig_verify)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const PQSigCase& valid_case = GetStructuredValidCase();
    assert(pqsig::PQSigVerify(valid_case.sig, valid_case.msg, valid_case.pk));

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

    if (provider.ConsumeBool()) {
        sig = valid_case.sig;
        msg = valid_case.msg;
        pk = valid_case.pk;

        const size_t mutations = provider.ConsumeIntegralInRange<size_t>(1, 3);
        for (size_t i = 0; i < mutations; ++i) {
            ApplyDeterministicRejectMutation(provider, sig, msg, pk);
        }

        assert(!pqsig::PQSigVerify(sig, msg, pk));
    }

    if (provider.ConsumeBool()) {
        sig = valid_case.sig;
        msg = valid_case.msg;
        pk = valid_case.pk;

        switch (provider.ConsumeIntegralInRange<int>(0, 2)) {
        case 0:
            sig.pop_back();
            break;
        case 1:
            msg.pop_back();
            break;
        case 2:
            pk.pop_back();
            break;
        }

        assert(!pqsig::PQSigVerify(sig, msg, pk));
    }
}
