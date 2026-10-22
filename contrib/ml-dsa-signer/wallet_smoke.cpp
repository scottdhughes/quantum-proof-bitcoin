// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// PUBLIC fixtures only. Test fault injection is linked here, never in the library.
#include <crypto/mldsa44/signer/wallet.h>
#include <crypto/mldsa44/signer/wallet_crypto.h>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
static unsigned checks{0}, fail_fsync{0};
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    if (fail_fsync && --fail_fsync == 0) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static void Check(bool value) { if (!value) throw std::runtime_error("wallet fixture assertion"); ++checks; }
template<typename F> static void Reject(Code code, F action)
{
    try { action(); } catch (const Error& error) { Check(error.code == code); return; }
    throw std::runtime_error("wallet accepted invalid operation");
}
static Bytes Hex(const char* value)
{
    Bytes out;
    for (size_t i = 0; value[i]; i += 2) out.push_back(std::stoi(std::string(value + i, 2), nullptr, 16));
    return out;
}
static Bytes Read(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary); return {std::istreambuf_iterator<char>(file), {}};
}
static void Write(const std::filesystem::path& path, const Bytes& bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(bool(file));
}

int main(int argc, char** argv)
{
    try {
        Check(argc == 2);
        std::filesystem::path directory{argv[1]};
        std::filesystem::create_directory(directory); Check(chmod(directory.c_str(), 0700) == 0);
        Secret<32> root; for (size_t i = 0; i < 32; ++i) root.data()[i] = i;
        Secret<32> child;
        DeriveSeed(root.span(), Network::REGTEST, 0, 0, child.span());
        Check(std::equal(child.span().begin(), child.span().end(), Hex("50f6836b8c4e5444b80105c62d26f20126d15b59fd11c8e0035d62f0773f9233").begin()));
        DeriveSeed(root.span(), Network::REGTEST, 1, 0, child.span());
        Check(std::equal(child.span().begin(), child.span().end(), Hex("df57cfa9b4a42773265b30aa0a806a342276339a4b8cf63aed7c28cf9e4bdb53").begin()));
        auto id = WalletId(root.span(), Network::REGTEST);
        Check(std::equal(id.begin(), id.end(), Hex("8ca98dc5aeba704973bc6e43a2b40c7e").begin()));
        Reject(Code::VALIDATION, [&] { DeriveSeed(root.span(), Network::REGTEST, 2, 0, child.span()); });
        Reject(Code::LIMIT, [&] { DeriveSeed(root.span(), Network::REGTEST, 0, 0x80000000U, child.span()); });
        const Bytes password{'p','u','b','l','i','c','-','f','i','x','t','u','r','e'};
        auto record = SealRecord(root.span(), Network::REGTEST, {3, 7}, password, 1);
        Check(record.size() == 167);
        Secret<40> plaintext;
        auto info = OpenRecord(record, Network::REGTEST, password, plaintext.span());
        Check(info.id == id && info.generation == 1 && info.next == Counters{3, 7});
        Check(std::equal(root.span().begin(), root.span().end(), plaintext.span().begin()));
        Reject(Code::AUTH, [&] { OpenRecord(record, Network::REGTEST, Bytes{'x'}, plaintext.span()); });
        Check(std::all_of(plaintext.span().begin(), plaintext.span().end(), [](auto x) { return x == 0; }));
        Reject(Code::BINDING, [&] { OpenRecord(record, Network::MAIN, password, plaintext.span()); });
        auto bad_kdf = record; bad_kdf[71] ^= 1;
        Reject(Code::VALIDATION, [&] { OpenRecord(bad_kdf, Network::REGTEST, password, plaintext.span()); });
        for (size_t offset : {size_t{46}, size_t{63}, size_t{83}, size_t{99}, size_t{111}, size_t{166}}) {
            auto altered = record; altered[offset] ^= 1;
            Reject(Code::AUTH, [&] { OpenRecord(altered, Network::REGTEST, password, plaintext.span()); });
            Check(std::all_of(plaintext.span().begin(), plaintext.span().end(), [](auto x) { return x == 0; }));
        }
        Reject(Code::VALIDATION, [&] { OpenRecord(std::span(record).first(166), Network::REGTEST, password, plaintext.span()); });
        Reject(Code::VALIDATION, [&] { SealRecord(root.span(), Network::REGTEST, {0, 0}, Bytes{0xff}, 1); });
        Reject(Code::VALIDATION, [&] { SealRecord(root.span(), Network::REGTEST, {0, 0}, {}, 1); });

        Identity wallet_id{}; Address first{}, restored{}; Bytes old_record;
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            Check(wallet.Status().locked);
            wallet.Create(password);
            wallet_id = wallet.Status().id;
            Reject(Code::STORAGE, [&] { Wallet second{directory.string(), Network::REGTEST}; });
            first = wallet.Reserve(0);
            Check(first.branch == 0 && first.index == 0 && wallet.Status().next == Counters{1, 0});
            old_record = Read(directory / "wallet.dat"); Check(old_record.size() == 167);
            auto second = wallet.Reserve(0); Check(second.index == 1 && second.public_key != first.public_key);
            Check(Read(directory / "wallet.dat") != old_record);
            // An older valid record cannot lower counters already known in this process.
            wallet.Lock(); Write(directory / "wallet.dat", old_record);
            wallet.Unlock(password, {wallet_id, {0, 0}, {}});
            Check(wallet.Status().next == Counters{2, 0});
            auto wrong_entry = first; wrong_entry.program[0] ^= 1;
            wallet.Lock(); Write(directory / "wallet.dat", old_record);
            Reject(Code::AUTH, [&] { wallet.Unlock(password, {wallet_id, {2, 0}, {wrong_entry}}); });
            Check(wallet.Status().locked && wallet.Status().next == Counters{2, 0});
            wallet.Lock(); Check(wallet.Status().locked);
            Reject(Code::LOCKED, [&] { wallet.Reserve(0); });
            auto wrong_id = wallet_id; wrong_id[0] ^= 1;
            Reject(Code::AUTH, [&] { wallet.Unlock(password, {wrong_id, {2, 0}, {first}}); });
            Check(wallet.Status().locked);
            wallet.Unlock(password, {wallet_id, {2, 0}, {first}});
            restored = wallet.Public(0, 0); Check(restored.public_key == first.public_key && restored.program == first.program);
            fail_fsync = 2; // real file fsync succeeds; simulated directory fsync fails after rename.
            Reject(Code::STORAGE, [&] { wallet.Reserve(1); });
            Check(wallet.Status().locked); fail_fsync = 0;
        }
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            wallet.Unlock(password, {wallet_id, {2, 1}, {first}});
            Check(wallet.Status().next == Counters{2, 1});
            auto next = wallet.Reserve(1); Check(next.index == 1);
        }
        // Explicit operator recovery of an older valid encrypted record: floor
        // comes from retained public high water, never an invented gap guarantee.
        Write(directory / "wallet.dat", old_record);
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            wallet.Unlock(password, {wallet_id, {10, 4}, {first}});
            Check(wallet.Status().next == Counters{10, 4});
            Check(wallet.Reserve(0).index == 10);
            auto bad_entry = first; bad_entry.public_key[0] ^= 1;
            wallet.Lock();
            Reject(Code::AUTH, [&] { wallet.Unlock(password, {wallet_id, {11, 4}, {bad_entry}}); });
            Check(wallet.Status().locked);
        }
        auto honest = Read(directory / "wallet.dat");
        auto target = directory / "wallet.dat";
        std::filesystem::rename(target, directory / "retained.dat");
        std::filesystem::create_symlink("retained.dat", target);
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            Reject(Code::STORAGE, [&] { wallet.Unlock(password, {wallet_id, {11, 4}, {first}}); });
        }
        std::filesystem::remove(target);
        std::filesystem::create_hard_link(directory / "retained.dat", target);
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            Reject(Code::STORAGE, [&] { wallet.Unlock(password, {wallet_id, {11, 4}, {first}}); });
        }
        std::filesystem::remove(target); std::filesystem::rename(directory / "retained.dat", target);
        Check(Read(target) == honest);
        Check(chmod(target.c_str(), 0644) == 0);
        {
            Wallet wallet{directory.string(), Network::REGTEST};
            Reject(Code::STORAGE, [&] { wallet.Unlock(password, {wallet_id, {11, 4}, {first}}); });
        }
        Check(chmod(target.c_str(), 0600) == 0);
        Check(chmod(directory.c_str(), 0755) == 0);
        Reject(Code::STORAGE, [&] { Wallet wallet{directory.string(), Network::REGTEST}; });
        Check(chmod(directory.c_str(), 0700) == 0);
        std::cout << "{\"result\":\"PASS\",\"checks\":" << checks << ",\"record_bytes\":167,\"runtime\":\"" << CryptoVersion() << "\"}\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
