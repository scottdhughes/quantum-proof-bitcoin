// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/wallet.h>
#include <contrib/ml-dsa-key-lifecycle/key_lifecycle.h>
#include <contrib/ml-dsa-engineering/pqbtc_mldsa44.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <sys/file.h>
#include <sys/stat.h>

namespace pqbtc::mldsa44::signer {
namespace {
struct Fd {
    int value;
    explicit Fd(int fd = -1) : value(fd) {}
    Fd(const Fd&) = delete;
    ~Fd() { if (value >= 0) close(value); }
    int Release() { auto fd = value; value = -1; return fd; }
};
bool OwnedRegular(int fd)
{
    struct stat info{};
    return fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == geteuid() && (info.st_mode & 07777) == 0600 && info.st_nlink == 1;
}
int OpenDirectory(const std::string& path)
{
    Require(!path.empty() && path[0] == '/', Code::STORAGE);
    Fd directory{open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    Require(directory.value >= 0, Code::STORAGE);
    size_t start{1};
    while (start < path.size()) {
        auto end = path.find('/', start); if (end == std::string::npos) end = path.size();
        auto name = path.substr(start, end - start);
        Require(!name.empty() && name != "." && name != "..", Code::STORAGE);
        Fd next{openat(directory.value, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
        Require(next.value >= 0, Code::STORAGE);
        close(directory.value); directory.value = next.Release(); start = end + 1;
    }
    struct stat info{};
    Require(fstat(directory.value, &info) == 0 && info.st_uid == geteuid() && (info.st_mode & 07777) == 0700, Code::STORAGE);
    return directory.Release();
}
Record ReadRecord(int directory)
{
    Fd fd{openat(directory, "wallet.dat", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
    Require(OwnedRegular(fd.value), Code::STORAGE);
    struct stat info{}; Require(fstat(fd.value, &info) == 0 && info.st_size == 167, Code::STORAGE);
    Record result{}; size_t offset{0};
    while (offset < result.size()) {
        auto count = read(fd.value, result.data() + offset, result.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        Require(count > 0, Code::STORAGE); offset += count;
    }
    unsigned char trailing{}; Require(read(fd.value, &trailing, 1) == 0, Code::STORAGE);
    return result;
}
void Publish(int directory, const Record& record, bool create)
{
    std::array<unsigned char, 16> random{}; RandomBytes(random);
    std::string name{".wallet-tmp-"}; constexpr char digits[]{"0123456789abcdef"};
    for (auto c : random) { name.push_back(digits[c >> 4]); name.push_back(digits[c & 15]); }
    Fd fd{openat(directory, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)};
    Require(OwnedRegular(fd.value), Code::STORAGE);
    try {
        size_t offset{0};
        while (offset < record.size()) {
            auto count = write(fd.value, record.data() + offset, record.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            Require(count > 0, Code::STORAGE); offset += count;
        }
        Require(fsync(fd.value) == 0, Code::STORAGE);
        if (create) {
            // Atomic create without clobbering an existing wallet or symlink.
            Require(linkat(directory, name.c_str(), directory, "wallet.dat", 0) == 0, Code::STORAGE);
            Require(unlinkat(directory, name.c_str(), 0) == 0, Code::STORAGE);
        } else {
            Fd previous{openat(directory, "wallet.dat", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
            Require(OwnedRegular(previous.value), Code::STORAGE);
            Require(renameat(directory, name.c_str(), directory, "wallet.dat") == 0, Code::STORAGE);
        }
        Require(fsync(directory) == 0, Code::STORAGE);
    } catch (...) {
        (void)unlinkat(directory, name.c_str(), 0); // This call's own ciphertext-only temporary file.
        throw;
    }
}
struct Key {
    pqbtc_mldsa44_key* owner{nullptr};
    ~Key() { pqbtc_mldsa44_key_destroy(&owner); }
};
} // namespace

struct Wallet::State {
    Secret<1056> bytes; size_t pass_size;
    explicit State(std::span<const unsigned char> password) : pass_size(password.size())
    {
        ValidatePassphrase(password); std::copy(password.begin(), password.end(), bytes.data() + 32);
    }
    auto Root() { return std::span<unsigned char, 32>{bytes.data(), 32}; }
    auto Pass() { return std::span<const unsigned char>{bytes.data() + 32, pass_size}; }
};

Wallet::Wallet(const std::string& directory, Network network) : m_network(network)
{
    // This phase can run only as a valueless regtest pilot, never issue main/test funds.
    Require(network == Network::REGTEST, Code::UNSUPPORTED);
    Require(pqbtc_mldsa44_key_runtime_init() == 0, Code::INTERNAL);
    Fd dir{OpenDirectory(directory)};
    Fd lock{openat(dir.value, "wallet.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600)};
    Require(OwnedRegular(lock.value) && flock(lock.value, LOCK_EX | LOCK_NB) == 0, Code::STORAGE);
    m_directory = dir.Release(); m_lock = lock.Release();
}
Wallet::~Wallet()
{
    m_secret.reset(); if (m_lock >= 0) close(m_lock); if (m_directory >= 0) close(m_directory);
}
void Wallet::CheckLive() const
{
    Require(getpid() == m_origin && !m_poisoned, Code::STORAGE);
    Require(bool(m_secret), Code::LOCKED);
    Require(pqbtc_mldsa44_key_runtime_init() == 0, Code::INTERNAL);
}
void Wallet::Save(RecordInfo& info, Counters next, bool create)
{
    CheckLive();
    try {
        Require(info.generation < std::numeric_limits<uint64_t>::max(), Code::LIMIT);
        auto record = SealRecord(m_secret->Root(), m_network, next, m_secret->Pass(), info.generation + 1);
        Publish(m_directory, record, create);
        ++info.generation; info.next = next;
    } catch (...) { m_secret.reset(); m_poisoned = true; throw; }
}
void Wallet::Create(std::span<const unsigned char> passphrase)
{
    std::lock_guard guard{m_mutex}; Require(getpid() == m_origin && !m_poisoned, Code::STORAGE);
    Require(!m_secret, Code::VALIDATION);
    auto candidate = std::make_unique<State>(passphrase); RandomBytes(candidate->Root());
    auto id = WalletId(candidate->Root(), m_network);
    m_info = {id, 0, {0, 0}}; m_secret = std::move(candidate); Save(m_info, {0, 0}, true);
}
Address Wallet::PublicUnchecked(uint8_t branch, uint32_t index)
{
    CheckLive(); Secret<32> seed; DeriveSeed(m_secret->Root(), m_network, branch, index, seed.span());
    Key key; Require(pqbtc_mldsa44_key_import_seed(&key.owner, seed.data(), 32) == 0, Code::INTERNAL);
    Zero(seed.span()); Address address{}; address.branch = branch; address.index = index;
    Require(pqbtc_mldsa44_key_public(key.owner, address.public_key.data(), address.public_key.size()) == 0, Code::INTERNAL);
    address.program = KeyCommitment(m_network, address.public_key); return address;
}
void Wallet::Unlock(std::span<const unsigned char> passphrase, const Recovery& recovery)
{
    std::lock_guard guard{m_mutex};
    Require(getpid() == m_origin && !m_poisoned, Code::STORAGE); m_secret.reset();
    Require(recovery.minimum.receive <= 0x80000000U && recovery.minimum.change <= 0x80000000U && recovery.public_entries.size() <= 10000);
    auto record = ReadRecord(m_directory); Secret<40> plaintext;
    auto info = OpenRecord(record, m_network, passphrase, plaintext.span());
    Require(info.id == recovery.expected_id, Code::AUTH);
    auto candidate = std::make_unique<State>(passphrase);
    std::copy_n(plaintext.data(), 32, candidate->Root().begin()); Zero(plaintext.span());
    m_secret = std::move(candidate);
    try {
        for (const auto& entry : recovery.public_entries) {
            Require(entry.branch <= 1 && entry.index < (entry.branch == 0 ? recovery.minimum.receive : recovery.minimum.change));
            auto observed = PublicUnchecked(entry.branch, entry.index);
            Require(observed.public_key == entry.public_key && observed.program == entry.program, Code::AUTH);
        }
        Counters floor{std::max(info.next.receive, recovery.minimum.receive), std::max(info.next.change, recovery.minimum.change)};
        if (m_info.generation && m_info.id == info.id) {
            floor.receive = std::max(floor.receive, m_info.next.receive);
            floor.change = std::max(floor.change, m_info.next.change);
        }
        if (floor != info.next) Save(info, floor);
        m_info = info;
    } catch (...) { m_secret.reset(); throw; }
}
void Wallet::Lock()
{
    std::lock_guard guard{m_mutex}; Require(getpid() == m_origin, Code::STORAGE); m_secret.reset();
}
Address Wallet::Reserve(uint8_t branch)
{
    std::lock_guard guard{m_mutex}; CheckLive(); Require(branch <= 1);
    auto next = m_info.next; auto& index = branch == 0 ? next.receive : next.change;
    Require(index < 0x80000000U, Code::LIMIT);
    auto address = PublicUnchecked(branch, index++); Save(m_info, next); return address;
}
Address Wallet::Public(uint8_t branch, uint32_t index)
{
    std::lock_guard guard{m_mutex}; CheckLive(); Require(branch <= 1);
    Require(index < (branch == 0 ? m_info.next.receive : m_info.next.change), Code::VALIDATION);
    return PublicUnchecked(branch, index);
}
WalletStatus Wallet::Status() const
{
    std::lock_guard guard{m_mutex}; Require(getpid() == m_origin, Code::STORAGE);
    return {!m_secret, m_info.id, m_info.next, m_info.generation};
}
Witnesses Wallet::SignTransaction(const Transaction& tx, std::span<const Output> prevouts,
    std::span<const Derivation> paths, uint64_t fee_cap)
{
    std::lock_guard guard{m_mutex}; CheckLive();
    try { (void)SerializeUnsigned(tx,prevouts); } catch (const std::invalid_argument&) { throw Error(Code::VALIDATION); }
    Require(paths.size()==tx.inputs.size() && fee_cap<=2100000000000000ULL);
    uint64_t incoming{0},outgoing{0};
    for (const auto& p:prevouts) incoming+=p.amount;
    for (const auto& output:tx.outputs) {
        outgoing+=output.amount; const auto& script=output.script;
        bool v2=script.size()==34 && script[0]==0x52 && script[1]==0x20;
        bool data=false;
        if (output.amount==0 && script.size()>=2 && script[0]==0x6a) {
            size_t size=script[1];
            if (size<=75) data=script.size()==size+2;
            else if (size==0x4c && script.size()>=3) data=script[2]>=76 && script[2]<=80 && script.size()==size_t{script[2]}+3;
        }
        Require(v2 || data);
    }
    Require(incoming>=outgoing && incoming-outgoing<=fee_cap);
    std::vector<Address> addresses;
    for (size_t i=0;i<paths.size();++i) {
        const auto& path=paths[i]; Require(path.branch<=1 && path.index<(path.branch==0?m_info.next.receive:m_info.next.change));
        auto address=PublicUnchecked(path.branch,path.index);
        const auto& script=prevouts[i].script;
        Require(script.size()==34 && script[0]==0x52 && script[1]==0x20 && std::equal(address.program.begin(),address.program.end(),script.begin()+2));
        addresses.push_back(address);
    }
    PreparedTransaction prepared{tx,prevouts}; Witnesses result;
    constexpr unsigned char context[]{"PQBTC/MLDSA44/tx/v1"};
    for (size_t i=0;i<paths.size();++i) {
        Secret<32> seed; DeriveSeed(m_secret->Root(),m_network,paths[i].branch,paths[i].index,seed.span());
        Key key; Require(pqbtc_mldsa44_key_import_seed(&key.owner,seed.data(),32)==0,Code::INTERNAL); Zero(seed.span());
        auto message=SigningMessage(m_network,prepared,i);
        std::array<Bytes,2> witness{Bytes(2420),Bytes(addresses[i].public_key.begin(),addresses[i].public_key.end())};
        auto code=pqbtc_mldsa44_key_sign_hedged(key.owner,witness[0].data(),witness[0].size(),message.data(),32,context,sizeof(context)-1);
        if (code<=PQBTC_MLDSA44_ERR_ENTROPY_SOURCE && code>=PQBTC_MLDSA44_ERR_ENTROPY_REPEAT) throw Error(Code::ENTROPY);
        Require(code==0,Code::INTERNAL);
        Require(VerifyWitness(m_network,prepared,i,addresses[i].program,witness),Code::SELFVERIFY);
        result.push_back(std::move(witness));
    }
    return result;
}
} // namespace pqbtc::mldsa44::signer
