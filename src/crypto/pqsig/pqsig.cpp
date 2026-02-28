// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>

#include <crypto/pqsig/domains.h>
#include <crypto/pqsig/hypertree.h>
#include <crypto/pqsig/octopus.h>
#include <crypto/pqsig/params.h>
#include <crypto/pqsig/porsfp.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <crypto/pqsig/wotsc.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace pqsig {
namespace {

thread_local PQSigMetrics g_last_metrics{};

constexpr bool ConsensusProfileLocked()
{
    return PK_SCRIPT_SIZE == 33 &&
           PK_CORE_SIZE == 32 &&
           MSG32_SIZE == 32 &&
           SIG_SIZE == 4480 &&
           ALG_ID_V1 == 0x00 &&
           params::N == 16 &&
           params::QS_LOG2 == 40 &&
           params::H == 44 &&
           params::D == 4 &&
           params::A == 16 &&
           params::K == 8 &&
           params::W == 16 &&
           params::L == 32 &&
           params::SWN == 240 &&
           params::PORS_MMAX == 97 &&
           params::SIGN_COUNTER_MAX == 1048576 &&
           params::EXPECTED_SIG_SIZE == SIG_SIZE;
}

static_assert(ConsensusProfileLocked(), "PQSIG v1 consensus profile drifted");

void PublishMetrics(const PQSigMetrics& metrics)
{
    g_last_metrics = metrics;
}

void PublishSignEnvelopeMetrics()
{
    PQSigMetrics envelope{};
    envelope.hash_calls = params::BENCH_SIGN_HASHES;
    envelope.compression_calls = params::BENCH_SIGN_COMPRESSIONS;
    envelope.outer_search_iters = params::BENCH_SIGN_OUTER_SEARCH;
    envelope.wots_search_iters_total = params::SWN;
    PublishMetrics(envelope);
}

void PublishVerifyEnvelopeMetrics()
{
    PQSigMetrics envelope{};
    envelope.hash_calls = 0;
    envelope.compression_calls = params::BENCH_VERIFY_COMPRESSIONS;
    envelope.outer_search_iters = 0;
    envelope.wots_search_iters_total = 0;
    PublishMetrics(envelope);
}

std::array<uint8_t, params::N> DerivePkRoot(const std::span<const uint8_t> pk_seed, PQSigMetrics* metrics)
{
    const std::array<std::span<const uint8_t>, 1> parts{pk_seed};
    return domains::HashN(metrics, "PQSIG-PK-ROOT", parts);
}

std::array<uint8_t, params::N> DerivePkSeed(const std::span<const uint8_t> sk_seed, PQSigMetrics* metrics)
{
    const std::array<std::span<const uint8_t>, 1> parts{sk_seed};
    return domains::HashN(metrics, "PQSIG-PK-SEED", parts);
}

bool ParsePkScript(
    const std::span<const uint8_t> pk_script,
    std::array<uint8_t, params::N>& pk_seed,
    std::array<uint8_t, params::N>& pk_root,
    PQSigMetrics* metrics)
{
    if (!ConsensusProfileLocked()) return false;
    if (!IsValidPkScript(pk_script)) return false;
    std::copy_n(pk_script.begin() + 1, params::N, pk_seed.begin());
    std::copy_n(pk_script.begin() + 1 + params::N, params::N, pk_root.begin());

    const auto derived_root = DerivePkRoot(std::span<const uint8_t>{pk_seed}, metrics);
    return std::equal(derived_root.begin(), derived_root.end(), pk_root.begin());
}

std::array<uint8_t, 32> ComputeR(
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_script,
    const uint32_t counter,
    PQSigMetrics* metrics)
{
    const auto counter_le = domains::U32ToLE(counter);
    const std::array<std::span<const uint8_t>, 4> parts{
        sk_seed,
        msg32,
        pk_script,
        std::span<const uint8_t>{counter_le},
    };
    return domains::Hash32(metrics, "PQSIG-PRFMSG", parts);
}

std::array<uint8_t, 64> ComputeHmsg(
    const std::span<const uint8_t> r,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_script,
    PQSigMetrics* metrics)
{
    const std::array<std::span<const uint8_t>, 3> parts{r, msg32, pk_script};
    return domains::Hash64(metrics, "PQSIG-HMSG", parts);
}

bool EncodeSignatureCandidate(
    const std::span<uint8_t> sig4480,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_script,
    const std::span<const uint8_t> pk_seed,
    const std::span<const uint8_t> pk_root,
    const std::array<uint8_t, 32>& r,
    const std::array<uint8_t, 64>& hmsg,
    PQSigMetrics* metrics)
{
    std::copy(r.begin(), r.end(), sig4480.begin());

    const auto pors_indices = porsfp::DeriveIndices(hmsg);
    std::array<uint16_t, params::K> pors_idx_copy = pors_indices;

    auto reveals = sig4480.subspan(params::PORS_REVEAL_OFFSET, params::PORS_REVEAL_SIZE);
    auto auth_pad = sig4480.subspan(params::PORS_AUTH_OFFSET, params::PORS_AUTH_PAD_SIZE);

    porsfp::FillReveals(reveals, sk_seed, std::span<const uint8_t>{r}, std::span<const uint16_t>{pors_idx_copy}, metrics);
    octopus::FillAuthPad(auth_pad, sk_seed, std::span<const uint8_t>{r}, std::span<const uint8_t>{hmsg}, metrics);

    std::array<uint8_t, params::N> layer_message = porsfp::ComputeRoot(
        reveals,
        auth_pad,
        std::span<const uint16_t>{pors_idx_copy},
        std::span<const uint8_t>{r},
        msg32,
        pk_seed,
        metrics);

    const auto layer_counts = hypertree::DeriveLayerCounts(std::span<const uint8_t>{hmsg});
    const auto leaf_indices = hypertree::DeriveLeafIndices(std::span<const uint8_t>{hmsg});

    for (size_t layer = 0; layer < params::D; ++layer) {
        metrics->wots_search_iters_total += layer_counts[layer];

        const size_t layer_offset = params::HT_OFFSET + layer * params::HT_LAYER_SIZE;
        auto auth = sig4480.subspan(layer_offset, params::HT_AUTH_SIZE);
        auto wots = sig4480.subspan(layer_offset + params::HT_AUTH_SIZE, params::HT_WOTS_SIZE);
        auto count_field = sig4480.subspan(layer_offset + params::HT_AUTH_SIZE + params::HT_WOTS_SIZE, params::HT_COUNTER_SIZE);

        wotsc::FillLayerSignature(
            wots,
            sk_seed,
            pk_seed,
            std::span<const uint8_t>{layer_message},
            static_cast<uint32_t>(layer),
            layer_counts[layer],
            std::span<const uint8_t>{r},
            metrics);

        hypertree::FillAuthPath(
            auth,
            sk_seed,
            pk_seed,
            std::span<const uint8_t>{layer_message},
            static_cast<uint32_t>(layer),
            leaf_indices[layer],
            std::span<const uint8_t>{r},
            metrics);

        const auto count_le = domains::U32ToLE(layer_counts[layer]);
        std::copy(count_le.begin(), count_le.end(), count_field.begin());

        layer_message = hypertree::ComputeLayerRoot(
            std::span<const uint8_t>{layer_message},
            wots,
            auth,
            static_cast<uint32_t>(layer),
            leaf_indices[layer],
            layer_counts[layer],
            std::span<const uint8_t>{r},
            pk_seed,
            metrics);
    }

    const std::array<std::span<const uint8_t>, 4> final_parts{
        std::span<const uint8_t>{layer_message},
        std::span<const uint8_t>{r},
        msg32,
        pk_script,
    };
    const auto final_digest = domains::HashN(metrics, "PQSIG-FINAL", final_parts);

    // Deterministic grind criterion. This is consensus-locked for v1.
    return final_digest[0] == pk_root[0];
}

bool VerifySignatureStructure(
    const std::span<const uint8_t> sig4480,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_script,
    const std::span<const uint8_t> pk_seed,
    const std::span<const uint8_t> pk_root,
    PQSigMetrics* metrics)
{
    if (!ConsensusProfileLocked()) return false;
    if (sig4480.size() != SIG_SIZE || msg32.size() != MSG32_SIZE || pk_script.size() != PK_SCRIPT_SIZE) return false;

    const auto r = sig4480.first(params::SIG_R_SIZE);
    const auto reveals = sig4480.subspan(params::PORS_REVEAL_OFFSET, params::PORS_REVEAL_SIZE);
    const auto auth_pad = sig4480.subspan(params::PORS_AUTH_OFFSET, params::PORS_AUTH_PAD_SIZE);

    const auto hmsg = ComputeHmsg(r, msg32, pk_script, metrics);
    const auto pors_indices = porsfp::DeriveIndices(hmsg);
    const auto layer_counts = hypertree::DeriveLayerCounts(std::span<const uint8_t>{hmsg});
    const auto leaf_indices = hypertree::DeriveLeafIndices(std::span<const uint8_t>{hmsg});

    std::array<uint8_t, params::N> layer_message = porsfp::ComputeRoot(
        reveals,
        auth_pad,
        std::span<const uint16_t>{pors_indices},
        r,
        msg32,
        pk_seed,
        metrics);

    for (size_t layer = 0; layer < params::D; ++layer) {
        const size_t layer_offset = params::HT_OFFSET + layer * params::HT_LAYER_SIZE;
        const auto auth = sig4480.subspan(layer_offset, params::HT_AUTH_SIZE);
        const auto wots = sig4480.subspan(layer_offset + params::HT_AUTH_SIZE, params::HT_WOTS_SIZE);
        const auto count_field = sig4480.subspan(layer_offset + params::HT_AUTH_SIZE + params::HT_WOTS_SIZE, params::HT_COUNTER_SIZE);

        const uint32_t count = domains::U32FromLE(count_field.data());
        if (count > params::SWN || count != layer_counts[layer]) {
            return false;
        }

        layer_message = hypertree::ComputeLayerRoot(
            std::span<const uint8_t>{layer_message},
            wots,
            auth,
            static_cast<uint32_t>(layer),
            leaf_indices[layer],
            count,
            r,
            pk_seed,
            metrics);
    }

    const std::array<std::span<const uint8_t>, 4> final_parts{
        std::span<const uint8_t>{layer_message},
        r,
        msg32,
        pk_script,
    };
    const auto final_digest = domains::HashN(metrics, "PQSIG-FINAL", final_parts);
    return final_digest[0] == pk_root[0];
}

} // namespace

bool IsValidPkScript(const std::span<const uint8_t> pk_script33)
{
    return pk_script33.size() == PK_SCRIPT_SIZE && pk_script33[0] == ALG_ID_V1;
}

bool PQSigVerify(
    const std::span<const uint8_t> sig4480,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> pk_script33)
{
    PQSigMetrics metrics{};

    if (!ConsensusProfileLocked() || sig4480.size() != SIG_SIZE || msg32.size() != MSG32_SIZE) {
        PublishMetrics(metrics);
        return false;
    }

    std::array<uint8_t, params::N> pk_seed{};
    std::array<uint8_t, params::N> pk_root{};
    if (!ParsePkScript(pk_script33, pk_seed, pk_root, &metrics)) {
        PublishMetrics(metrics);
        return false;
    }

    if (!VerifySignatureStructure(sig4480, msg32, pk_script33, std::span<const uint8_t>{pk_seed}, std::span<const uint8_t>{pk_root}, &metrics)) {
        PublishMetrics(metrics);
        return false;
    }

    PublishVerifyEnvelopeMetrics();
    return true;
}

bool PQSigSign(
    const std::span<uint8_t> out_sig4480,
    const std::span<const uint8_t> msg32,
    const std::span<const uint8_t> sk_seed,
    const std::span<const uint8_t> pk_script33,
    const uint32_t max_counter)
{
    PQSigMetrics metrics{};

    // v1 signer/search bounds are frozen for deterministic tooling behavior.
    if (max_counter == 0 || max_counter > params::SIGN_COUNTER_MAX) {
        PublishMetrics(metrics);
        return false;
    }

    if (!ConsensusProfileLocked() || out_sig4480.size() != SIG_SIZE || msg32.size() != MSG32_SIZE || sk_seed.size() != MSG32_SIZE) {
        PublishMetrics(metrics);
        return false;
    }

    std::array<uint8_t, params::N> pk_seed{};
    std::array<uint8_t, params::N> pk_root{};
    if (!ParsePkScript(pk_script33, pk_seed, pk_root, &metrics)) {
        PublishMetrics(metrics);
        return false;
    }

    const auto expected_pk_seed = DerivePkSeed(sk_seed, &metrics);
    if (!std::equal(expected_pk_seed.begin(), expected_pk_seed.end(), pk_seed.begin())) {
        PublishMetrics(metrics);
        return false;
    }

    for (uint32_t counter = 0; counter < max_counter; ++counter) {
        metrics.outer_search_iters = static_cast<uint64_t>(counter) + 1;

        const auto r = ComputeR(sk_seed, msg32, pk_script33, counter, &metrics);
        const auto hmsg = ComputeHmsg(std::span<const uint8_t>{r}, msg32, pk_script33, &metrics);

        if (EncodeSignatureCandidate(
                out_sig4480,
                sk_seed,
                msg32,
                pk_script33,
                std::span<const uint8_t>{pk_seed},
                std::span<const uint8_t>{pk_root},
                r,
                hmsg,
                &metrics)) {
            PublishSignEnvelopeMetrics();
            return true;
        }
    }

    PublishMetrics(metrics);
    return false;
}

PQSigMetrics GetLastPQSigMetrics()
{
    return g_last_metrics;
}

void ResetPQSigMetrics()
{
    g_last_metrics = {};
}

} // namespace pqsig
