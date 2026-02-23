// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <crypto/pqsig/params.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <vector>

namespace {

std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> DerivePkScript(const std::span<const uint8_t> sk_seed)
{
    const std::array<std::span<const uint8_t>, 1> parts{sk_seed};
    const auto pk_seed = pqsig::domains::HashN(nullptr, "PQSIG-PK-SEED", parts);
    const std::array<std::span<const uint8_t>, 1> root_parts{std::span<const uint8_t>{pk_seed}};
    const auto pk_root = pqsig::domains::HashN(nullptr, "PQSIG-PK-ROOT", root_parts);

    std::array<uint8_t, pqsig::PK_SCRIPT_SIZE> out{};
    out[0] = pqsig::ALG_ID_V1;
    std::copy(pk_seed.begin(), pk_seed.end(), out.begin() + 1);
    std::copy(pk_root.begin(), pk_root.end(), out.begin() + 1 + pk_seed.size());
    return out;
}

void CheckEnvelopeAndPrint(
    const pqsig::PQSigMetrics& sign_metrics,
    const pqsig::PQSigMetrics& verify_metrics)
{
    assert(sign_metrics.hash_calls == pqsig::params::BENCH_SIGN_HASHES);
    assert(sign_metrics.compression_calls == pqsig::params::BENCH_SIGN_COMPRESSIONS);
    assert(sign_metrics.outer_search_iters == pqsig::params::BENCH_SIGN_OUTER_SEARCH);

    assert(verify_metrics.compression_calls == pqsig::params::BENCH_VERIFY_COMPRESSIONS);

    const double per_byte = static_cast<double>(verify_metrics.compression_calls) / static_cast<double>(pqsig::SIG_SIZE);
    std::cout << "PQSIG_BENCH_ENVELOPE "
              << "verify_compressions=" << verify_metrics.compression_calls << ' '
              << "verify_compressions_per_byte=" << std::setprecision(16) << per_byte << ' '
              << "sign_hashes=" << sign_metrics.hash_calls << ' '
              << "sign_compressions=" << sign_metrics.compression_calls << ' '
              << "outer_search_iters=" << sign_metrics.outer_search_iters << '\n';
}

} // namespace

static void PQSigBenchEnvelope(benchmark::Bench& bench)
{
    const std::array<uint8_t, 32> sk_seed{0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
                                          0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
                                          0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a,
                                          0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a, 0x7a};
    const auto pk_script = DerivePkScript(sk_seed);

    std::array<uint8_t, pqsig::MSG32_SIZE> msg{};
    msg[0] = 0x42;
    msg[31] = 0x99;

    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    const bool sign_ok = pqsig::PQSigSign(sig, msg, sk_seed, pk_script);
    assert(sign_ok);
    const pqsig::PQSigMetrics sign_metrics = pqsig::GetLastPQSigMetrics();

    const bool verify_ok = pqsig::PQSigVerify(sig, msg, pk_script);
    assert(verify_ok);
    const pqsig::PQSigMetrics verify_metrics = pqsig::GetLastPQSigMetrics();

    CheckEnvelopeAndPrint(sign_metrics, verify_metrics);

    bench.run([&] {
        const bool ok = pqsig::PQSigVerify(sig, msg, pk_script);
        assert(ok);
    });
}

static void PQSigVerifyBench(benchmark::Bench& bench)
{
    const std::array<uint8_t, 32> sk_seed{0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
                                          0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
                                          0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
                                          0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};
    const auto pk_script = DerivePkScript(sk_seed);

    std::array<uint8_t, pqsig::MSG32_SIZE> msg{};
    msg.fill(0x11);

    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    const bool sign_ok = pqsig::PQSigSign(sig, msg, sk_seed, pk_script);
    assert(sign_ok);

    bench.run([&] {
        const bool ok = pqsig::PQSigVerify(sig, msg, pk_script);
        assert(ok);
    });
}

BENCHMARK(PQSigBenchEnvelope, benchmark::PriorityLevel::HIGH);
BENCHMARK(PQSigVerifyBench, benchmark::PriorityLevel::HIGH);
