// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_SECRET_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_SECRET_H
#include <crypto/mldsa44/signer/error.h>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" int pqbtc_mldsa44_key_runtime_init(void);
namespace pqbtc::mldsa44::signer {
inline void Zero(std::span<unsigned char> data)
{
    volatile unsigned char* p = data.data();
    for (size_t i = 0; i < data.size(); ++i) p[i] = 0;
}
// Dedicated Linux signer only. Policy is initialized before threads/secret input.
// Guard pages and kernel mlock (not ASan's success-without-lock interceptor).
template<size_t N> class Secret {
    void* m_map{MAP_FAILED};
    unsigned char* m_data{nullptr};
    size_t m_page{0};
    pid_t m_origin{getpid()};
public:
    Secret()
    {
        Require(pqbtc_mldsa44_key_runtime_init() == 0, Code::INTERNAL);
        const auto page = sysconf(_SC_PAGESIZE);
        Require(page > 0 && N <= static_cast<size_t>(page), Code::INTERNAL);
        m_page = page;
        m_map = mmap(nullptr, m_page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        Require(m_map != MAP_FAILED, Code::INTERNAL);
        m_data = static_cast<unsigned char*>(m_map) + m_page;
        if (mprotect(m_data, m_page, PROT_READ | PROT_WRITE) != 0 ||
            syscall(SYS_mlock, m_data, m_page) != 0 ||
            madvise(m_data, m_page, MADV_DONTDUMP) != 0 ||
            madvise(m_data, m_page, MADV_DONTFORK) != 0) {
            if (munmap(m_map, m_page * 3) != 0) std::abort();
            m_map = MAP_FAILED;
            throw Error(Code::INTERNAL);
        }
    }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret()
    {
        if (m_map != MAP_FAILED) {
            if (getpid() == m_origin) Zero({m_data, m_page});
            if (munmap(m_map, m_page * 3) != 0) std::abort();
        }
    }
    unsigned char* data()
    {
        Require(getpid() == m_origin && pqbtc_mldsa44_key_runtime_init() == 0, Code::INTERNAL);
        return m_data;
    }
    std::span<unsigned char, N> span() { return std::span<unsigned char, N>{data(), N}; }
};
} // namespace pqbtc::mldsa44::signer
#endif
