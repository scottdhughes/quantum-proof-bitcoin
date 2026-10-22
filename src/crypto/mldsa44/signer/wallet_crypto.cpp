// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/wallet_crypto.h>
#include <algorithm>
#include <cerrno>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string_view>
#include <sys/random.h>

#if OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 6 || OPENSSL_VERSION_PATCH != 5
#error "Signer crypto requires pinned OpenSSL 3.6.5, never system fallback"
#endif

namespace pqbtc::mldsa44::signer {
namespace {
struct CryptoContext {
    OSSL_LIB_CTX* lib{OSSL_LIB_CTX_new()};
    OSSL_PROVIDER* provider{nullptr};
    EVP_CIPHER* cipher{nullptr};
    CryptoContext()
    {
        Require(OpenSSL_version_num() == OPENSSL_VERSION_NUMBER && lib, Code::INTERNAL);
        provider = OSSL_PROVIDER_load(lib, "default");
        if (provider) cipher = EVP_CIPHER_fetch(lib, "AES-256-GCM", "provider=default");
        if (!cipher) { OSSL_PROVIDER_unload(provider); OSSL_LIB_CTX_free(lib); throw Error(Code::INTERNAL); }
    }
    ~CryptoContext() { EVP_CIPHER_free(cipher); OSSL_PROVIDER_unload(provider); OSSL_LIB_CTX_free(lib); }
};
CryptoContext& Crypto() { static CryptoContext context; return context; }
std::mutex kdf_mutex;
void Put(std::span<unsigned char> out, uint64_t value)
{
    for (size_t i = 0; i < out.size(); ++i) out[i] = (value >> (i * 8)) & 255;
}
uint64_t Get(std::span<const unsigned char> in)
{
    uint64_t result{0}; for (size_t i = 0; i < in.size(); ++i) result |= uint64_t{in[i]} << (8 * i); return result;
}
Bytes Domain(std::string_view text, Network network)
{
    Bytes data{text.begin(), text.end()}; auto binding = NetworkBinding(network);
    data.insert(data.end(), binding.begin(), binding.end()); return data;
}
void Mac(std::span<const unsigned char> key, std::span<const unsigned char> data, std::span<unsigned char, 32> out)
{
    size_t size{0};
    Require(EVP_Q_mac(Crypto().lib, "HMAC", "provider=default", "SHA256", nullptr,
        key.data(), key.size(), data.data(), data.size(), out.data(), out.size(), &size) && size == 32, Code::INTERNAL);
}
void PasswordKey(std::span<const unsigned char> pass, std::span<const unsigned char> salt, std::span<unsigned char, 32> key)
{
    std::lock_guard lock{kdf_mutex};
    Require(EVP_PBE_scrypt_ex(reinterpret_cast<const char*>(pass.data()), pass.size(), salt.data(), salt.size(),
        131072, 8, 1, 160ULL * 1024 * 1024, key.data(), key.size(), Crypto().lib, "provider=default") == 1, Code::INTERNAL);
}
using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
Cipher NewCipher()
{
    Cipher context{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free}; Require(bool(context), Code::INTERNAL); return context;
}
} // namespace

void RandomBytes(std::span<unsigned char> output)
{
    size_t offset{0};
    while (offset < output.size()) {
        auto count = getrandom(output.data() + offset, output.size() - offset, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { Zero(output); throw Error(Code::ENTROPY); }
        offset += count;
    }
}

void ValidatePassphrase(std::span<const unsigned char> pass)
{
    Require(!pass.empty() && pass.size() <= 1024);
    // Exact UTF8 bytes, including embedded U+0000; no normalization or C-string truncation.
    size_t i{0};
    while (i < pass.size()) {
        auto first = pass[i++]; if (first < 0x80) continue;
        unsigned count; uint32_t value, minimum;
        if (first >= 0xc2 && first <= 0xdf) { count=1; value=first & 31; minimum=0x80; }
        else if (first >= 0xe0 && first <= 0xef) { count=2; value=first & 15; minimum=0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { count=3; value=first & 7; minimum=0x10000; }
        else throw Error(Code::VALIDATION);
        Require(count <= pass.size() - i);
        while (count--) { auto c = pass[i++]; Require((c & 0xc0) == 0x80); value = (value << 6) | (c & 63); }
        Require(value >= minimum && value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff));
    }
}

void DeriveSeed(std::span<const unsigned char, 32> root, Network network, uint8_t branch,
    uint32_t index, std::span<unsigned char, 32> output)
{
    Zero(output); Require(branch <= 1); Require(index < 0x80000000U, Code::LIMIT);
    Secret<32> prk; auto salt = Domain("PQBTC/MLDSA44/wallet-root/v1", network); Mac(salt, root, prk.span());
    constexpr std::string_view label{"PQBTC/MLDSA44/keygen-seed/v1"};
    Bytes info{label.begin(), label.end()};
    for (uint32_t value : {uint32_t{branch} | 0x80000000U, index | 0x80000000U})
        for (int i = 3; i >= 0; --i) info.push_back((value >> (8 * i)) & 255);
    info.push_back(1); Mac(prk.span(), info, output);
}
Identity WalletId(std::span<const unsigned char, 32> root, Network network)
{
    Secret<32> result; Mac(root, Domain("PQBTC/MLDSA44/wallet-id/v1", network), result.span());
    Identity id{}; std::copy_n(result.data(), 16, id.begin()); return id;
}
Record SealRecord(std::span<const unsigned char, 32> root, Network network, Counters next,
    std::span<const unsigned char> pass, uint64_t generation)
{
    ValidatePassphrase(pass); Require(generation != 0 && next.receive <= 0x80000000U && next.change <= 0x80000000U);
    Record record{}; const std::array<unsigned char, 10> magic{'P','Q','W','M','L','D','1',0,1,0};
    std::copy(magic.begin(), magic.end(), record.begin());
    auto binding = NetworkBinding(network); std::copy(binding.begin(), binding.end(), record.begin() + 10);
    auto id = WalletId(root, network); std::copy(id.begin(), id.end(), record.begin() + 46);
    Put(std::span(record).subspan(62, 8), generation); record[70] = 1;
    Put(std::span(record).subspan(71, 4), 131072); Put(std::span(record).subspan(75, 4), 8); Put(std::span(record).subspan(79, 4), 1);
    RandomBytes(std::span(record).subspan(83, 16)); RandomBytes(std::span(record).subspan(99, 12));
    Secret<32> key; PasswordKey(pass, std::span(record).subspan(83, 16), key.span());
    Secret<40> plaintext; std::copy(root.begin(), root.end(), plaintext.data());
    Put(plaintext.span().subspan(32, 4), next.receive); Put(plaintext.span().subspan(36, 4), next.change);
    auto context = NewCipher(); int count{0}, end{0};
    Require(EVP_EncryptInit_ex2(context.get(), Crypto().cipher, key.data(), record.data() + 99, nullptr) == 1, Code::INTERNAL);
    Require(EVP_EncryptUpdate(context.get(), nullptr, &count, record.data(), 111) == 1, Code::INTERNAL);
    Require(EVP_EncryptUpdate(context.get(), record.data() + 111, &count, plaintext.data(), 40) == 1 && count == 40, Code::INTERNAL);
    Require(EVP_EncryptFinal_ex(context.get(), record.data() + 151, &end) == 1 && end == 0, Code::INTERNAL);
    Require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, 16, record.data() + 151) == 1, Code::INTERNAL);
    return record;
}
RecordInfo OpenRecord(std::span<const unsigned char> record, Network network,
    std::span<const unsigned char> pass, std::span<unsigned char, 40> output)
{
    Zero(output); ValidatePassphrase(pass); Require(record.size() == 167);
    const std::array<unsigned char, 10> magic{'P','Q','W','M','L','D','1',0,1,0};
    Require(std::equal(magic.begin(), magic.end(), record.begin()));
    auto binding = NetworkBinding(network);
    Require(std::equal(binding.begin(), binding.end(), record.begin() + 10), Code::BINDING);
    Require(Get(record.subspan(62, 8)) != 0 && record[70] == 1 && Get(record.subspan(71, 4)) == 131072 &&
        Get(record.subspan(75, 4)) == 8 && Get(record.subspan(79, 4)) == 1);
    Secret<32> key; PasswordKey(pass, record.subspan(83, 16), key.span());
    Secret<40> candidate; auto context = NewCipher(); int count{0}, end{0};
    Require(EVP_DecryptInit_ex2(context.get(), Crypto().cipher, key.data(), record.data() + 99, nullptr) == 1, Code::INTERNAL);
    Require(EVP_DecryptUpdate(context.get(), nullptr, &count, record.data(), 111) == 1, Code::INTERNAL);
    Require(EVP_DecryptUpdate(context.get(), candidate.data(), &count, record.data() + 111, 40) == 1 && count == 40, Code::AUTH);
    Require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(record.data()) + 151) == 1, Code::INTERNAL);
    Require(EVP_DecryptFinal_ex(context.get(), candidate.data() + 40, &end) == 1 && end == 0, Code::AUTH);
    auto id = WalletId(std::span<const unsigned char, 32>{candidate.data(), 32}, network);
    Require(CRYPTO_memcmp(id.data(), record.data() + 46, 16) == 0, Code::AUTH);
    Counters next{static_cast<uint32_t>(Get(candidate.span().subspan(32, 4))), static_cast<uint32_t>(Get(candidate.span().subspan(36, 4)))};
    Require(next.receive <= 0x80000000U && next.change <= 0x80000000U, Code::AUTH);
    std::copy(candidate.span().begin(), candidate.span().end(), output.begin());
    return {id, Get(record.subspan(62, 8)), next};
}
const char* CryptoVersion() { (void)Crypto(); return OpenSSL_version(OPENSSL_VERSION); }
} // namespace pqbtc::mldsa44::signer
