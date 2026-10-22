// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#ifndef BITCOIN_CRYPTO_MLDSA44_SIGNER_TRANSPORT_H
#define BITCOIN_CRYPTO_MLDSA44_SIGNER_TRANSPORT_H
#include <crypto/mldsa44/signer/error.h>
#include <chrono>
#include <span>
#include <string>
#include <sys/types.h>
#include <utility>
namespace pqbtc::mldsa44::signer::detail {
struct Fd {
    int value{-1};
    explicit Fd(int fd=-1):value(fd) {}
    Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete;
    Fd(Fd&& other) noexcept:value(std::exchange(other.value,-1)) {}
    Fd& operator=(Fd&& other) noexcept;
    ~Fd();
};
struct Parent { Fd directory; std::string name; };
Parent SocketParent(const std::string& path,uid_t owner);
bool Peer(int fd,uid_t uid);
ssize_t Receive(int fd,std::span<unsigned char> bytes);
using Clock=std::chrono::steady_clock;
void Wait(int fd,short events,Clock::time_point deadline);
} // namespace pqbtc::mldsa44::signer::detail
#endif
