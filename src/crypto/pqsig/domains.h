// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQSIG_DOMAINS_H
#define BITCOIN_CRYPTO_PQSIG_DOMAINS_H

#include <crypto/pqsig/params.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <crypto/sha256.h>
#include <crypto/sha512.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span.h>
#include <string_view>

namespace pqsig {
namespace domains {

inline uint64_t EstimateSha256Compressions(const size_t payload_bytes)
{
    return (payload_bytes + 9 + 63) / 64;
}

inline uint64_t EstimateSha512Compressions(const size_t payload_bytes)
{
    return (payload_bytes + 17 + 127) / 128;
}

inline void BumpSha256Metrics(PQSigMetrics* metrics, const size_t payload_bytes)
{
    if (metrics == nullptr) return;
    metrics->hash_calls += 1;
    metrics->compression_calls += EstimateSha256Compressions(payload_bytes);
}

inline void BumpSha512Metrics(PQSigMetrics* metrics, const size_t payload_bytes)
{
    if (metrics == nullptr) return;
    metrics->hash_calls += 1;
    metrics->compression_calls += EstimateSha512Compressions(payload_bytes);
}

inline uint16_t U16FromLE(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

inline uint32_t U32FromLE(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

inline std::array<uint8_t, 2> U16ToLE(const uint16_t value)
{
    return {
        static_cast<uint8_t>(value & 0xff),
        static_cast<uint8_t>((value >> 8) & 0xff),
    };
}

inline std::array<uint8_t, 4> U32ToLE(const uint32_t value)
{
    return {
        static_cast<uint8_t>(value & 0xff),
        static_cast<uint8_t>((value >> 8) & 0xff),
        static_cast<uint8_t>((value >> 16) & 0xff),
        static_cast<uint8_t>((value >> 24) & 0xff),
    };
}

inline std::array<uint8_t, 32> Hash32(
    PQSigMetrics* metrics,
    const std::string_view domain,
    const std::span<const std::span<const uint8_t>> parts)
{
    const size_t domain_size = std::min<size_t>(domain.size(), 255);
    size_t payload{1 + domain_size};
    for (const auto part : parts) payload += part.size();
    BumpSha256Metrics(metrics, payload);

    CSHA256 sha;
    const uint8_t len = static_cast<uint8_t>(domain_size);
    sha.Write(&len, 1);
    sha.Write(reinterpret_cast<const uint8_t*>(domain.data()), domain_size);
    for (const auto part : parts) {
        if (!part.empty()) sha.Write(part.data(), part.size());
    }

    std::array<uint8_t, 32> out{};
    sha.Finalize(out.data());
    return out;
}

inline std::array<uint8_t, 64> Hash64(
    PQSigMetrics* metrics,
    const std::string_view domain,
    const std::span<const std::span<const uint8_t>> parts)
{
    const size_t domain_size = std::min<size_t>(domain.size(), 255);
    size_t payload{1 + domain_size};
    for (const auto part : parts) payload += part.size();
    BumpSha512Metrics(metrics, payload);

    CSHA512 sha;
    const uint8_t len = static_cast<uint8_t>(domain_size);
    sha.Write(&len, 1);
    sha.Write(reinterpret_cast<const uint8_t*>(domain.data()), domain_size);
    for (const auto part : parts) {
        if (!part.empty()) sha.Write(part.data(), part.size());
    }

    std::array<uint8_t, 64> out{};
    sha.Finalize(out.data());
    return out;
}

inline std::array<uint8_t, params::N> HashN(
    PQSigMetrics* metrics,
    const std::string_view domain,
    const std::span<const std::span<const uint8_t>> parts)
{
    const auto h = Hash32(metrics, domain, parts);
    std::array<uint8_t, params::N> out{};
    std::copy_n(h.begin(), params::N, out.begin());
    return out;
}

} // namespace domains
} // namespace pqsig

#endif // BITCOIN_CRYPTO_PQSIG_DOMAINS_H
