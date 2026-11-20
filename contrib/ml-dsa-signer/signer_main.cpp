// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Experimental valueless pilot launcher. No node RPC or passphrase argv/env input.
#include <crypto/mldsa44/signer/service.h>
#include <crypto/mldsa44/signer/identity.h>
#include <crypto/mldsa44/signer/transport.h>
#include <crypto/sha256.h>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <atomic>
#include <csignal>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <map>
#include <poll.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
static std::atomic<bool> stopped{false};
static_assert(decltype(stopped)::is_always_lock_free);
static void Stop(int) { stopped.store(true,std::memory_order_relaxed); }
static uint64_t Number(const std::string& text)
{
    Require(!text.empty() && std::all_of(text.begin(),text.end(),[](char c){return c>='0'&&c<='9';}));
    uint64_t value{};
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),value);
    // Decimal overflow previously reached the generic INTERNAL refusal path.
    Require(parsed.ec==std::errc{} && parsed.ptr==text.data()+text.size(),Code::INTERNAL);
    return value;
}
static std::string Decimal(uint64_t value)
{
    char buffer[20];
    const auto encoded=std::to_chars(buffer,buffer+sizeof(buffer),value);
    Require(encoded.ec==std::errc{},Code::INTERNAL);
    return {buffer,encoded.ptr};
}
static Identity Id(const std::string& text)
{
    Require(text.size()==32); Identity id{};
    auto hex=[](char c) { Require((c>='0'&&c<='9')||(c>='a'&&c<='f')); return c<='9'?c-'0':c-'a'+10; };
    for (size_t i=0;i<16;++i) id[i]=hex(text[2*i])*16+hex(text[2*i+1]);
    return id;
}
static Hash Spec(const std::string& path)
{
    std::ifstream input(path,std::ios::binary); Require(bool(input));
    Bytes data; char c;
    while (input.get(c)) { Require(data.size()<32768); data.push_back(c); }
    Require(input.eof() && !data.empty()); Hash hash{}; CSHA256{}.Write(data.data(),data.size()).Finalize(hash.data()); return hash;
}
static void ReadOperator(int fd,std::span<unsigned char> output,detail::Clock::time_point deadline)
{
    size_t offset{0};
    while (offset<output.size()) {
        detail::Wait(fd,POLLIN,deadline); auto count=read(fd,output.data()+offset,output.size()-offset);
        if (count<0 && errno==EINTR) continue;
        Require(count>0); offset+=count;
    }
}
// Unsealed operator-only extension. No change to signer IPC or wallet records.
static uint32_t ReadOperatorNumber(int fd,size_t size,detail::Clock::time_point deadline)
{
    std::array<unsigned char,4> bytes{};Require(size==1 || size==4);
    ReadOperator(fd,std::span(bytes).first(size),deadline);uint32_t value{0};
    for(size_t i=0;i<size;++i) value|=uint32_t{bytes[i]}<<(8*i);
    return value;
}
static void ReadRecoveryPublic(int fd,Recovery& recovery,detail::Clock::time_point deadline)
{
    const auto count=ReadOperatorNumber(fd,4,deadline);Require(count<=4096);
    recovery.public_entries.reserve(count);
    std::set<std::pair<uint8_t,uint32_t>> paths;std::set<Hash> programs;
    for(uint32_t i=0;i<count;++i) {
        Address entry{};entry.branch=ReadOperatorNumber(fd,1,deadline);
        entry.index=ReadOperatorNumber(fd,4,deadline);
        Require(entry.branch<=1 && entry.index<0x80000000U &&
            entry.index<(entry.branch==0?recovery.minimum.receive:recovery.minimum.change));
        ReadOperator(fd,entry.public_key,deadline);ReadOperator(fd,entry.program,deadline);
        Require(paths.emplace(entry.branch,entry.index).second && programs.insert(entry.program).second);
        recovery.public_entries.push_back(entry);
    }
    // A flagged restore must provide one finite frame, not a prefix followed by
    // ignored bytes. The same deadline bounds both partial input and EOF.
    unsigned char extra{};
    for(;;) {
        detail::Wait(fd,POLLIN,deadline);const auto count=read(fd,&extra,1);
        if(count<0 && errno==EINTR) continue;
        Require(count==0);break;
    }
}
static void Checkpoint(int fd,const WalletStatus& status)
{
    constexpr char digits[]{"0123456789abcdef"}; std::string id;
    for (auto byte:status.id) { id.push_back(digits[byte>>4]); id.push_back(digits[byte&15]); }
    auto line="MLDSA_WALLET_STATUS_V1 "+id+" "+Decimal(status.generation)+" "+
        Decimal(status.next.receive)+" "+Decimal(status.next.change)+"\n";
    auto deadline=detail::Clock::now()+std::chrono::seconds{5};size_t offset{0};
    while (offset<line.size()) {
        detail::Wait(fd,POLLOUT,deadline);auto count=write(fd,line.data()+offset,line.size()-offset);
        if (count<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        Require(count>0,Code::STORAGE);offset+=count;
    }
}
int main(int argc,char** argv)
{
    try {
        const std::set<std::string> flags{"--valueless-pilot","--create","--restore","--acknowledge-restore-scan-range","--crypto-version",
            "--recovery-public-input"};
        const std::set<std::string> values{"--socket","--wallet-dir","--node-uid","--fee-cap","--spec-file","--operator-fd",
            "--expected-wallet-id","--min-receive","--min-change","--operator-out-fd","--network"};
        std::map<std::string,std::string> options;
        for (int i=1;i<argc;++i) {
            std::string name{argv[i]}; Require(!options.contains(name));
            if (flags.contains(name)) options[name]="yes";
            else { Require(values.contains(name) && i+1<argc); options[name]=argv[++i]; }
        }
        Network network{Network::REGTEST};
        if (options.contains("--network")) {
            const auto& name=options.at("--network");
            Require(name=="test" || name=="regtest",Code::UNSUPPORTED);
            network=name=="test"?Network::TEST:Network::REGTEST;
        }
        if (options.contains("--crypto-version")) {
            Require(options.size()==(options.contains("--network")?3U:2U) && options.contains("--valueless-pilot"));
            std::cout<<CryptoVersion()<<'\n';return 0;
        }
        Require(options.contains("--valueless-pilot") && (options.contains("--create")!=options.contains("--restore")));
        Require(!options.contains("--recovery-public-input") || options.contains("--restore"));
        for (auto name:{"--socket","--wallet-dir","--node-uid","--fee-cap","--spec-file","--operator-fd","--operator-out-fd"}) Require(options.contains(name));
        auto uid=Number(options.at("--node-uid")),fee=Number(options.at("--fee-cap")),fd=Number(options.at("--operator-fd"));
        auto out_fd=Number(options.at("--operator-out-fd"));
        Require(uid>0 && uid<std::numeric_limits<uid_t>::max() && uid!=geteuid() && geteuid()!=0 && fd>=3 &&
            fd<=std::numeric_limits<int>::max() && out_fd>=3 && out_fd<=std::numeric_limits<int>::max() && out_fd!=fd,Code::AUTH);
        struct stat input_info{},output_info{};
        Require(fstat(fd,&input_info)==0 && fstat(out_fd,&output_info)==0,Code::AUTH);
        auto output_flags=fcntl(out_fd,F_GETFL);Require(output_flags>=0 && (output_flags&O_ACCMODE)!=O_RDONLY &&
            fcntl(out_fd,F_SETFL,output_flags|O_NONBLOCK)==0,Code::AUTH);
        Recovery recovery{};
        if (options.contains("--restore")) {
            for (auto name:{"--expected-wallet-id","--min-receive","--min-change","--acknowledge-restore-scan-range"}) Require(options.contains(name));
            recovery.expected_id=Id(options.at("--expected-wallet-id"));
            auto receive=Number(options.at("--min-receive")),change=Number(options.at("--min-change"));
            Require(receive<=0x80000000ULL && change<=0x80000000ULL); recovery.minimum={static_cast<uint32_t>(receive),static_cast<uint32_t>(change)};
        }
        auto spec=Spec(options.at("--spec-file"));
        Require(network!=Network::TEST || spec==CONTRACT_SPEC_SHA256,Code::BINDING);
        Wallet wallet{options.at("--wallet-dir"),network}; // Policy initialization precedes secret FD input and threads.
        Secret<1024> password; std::array<unsigned char,2> size{};
        auto deadline=detail::Clock::now()+std::chrono::seconds{5}; ReadOperator(fd,size,deadline);
        size_t length=size[0]|size_t{size[1]}<<8; Require(length>0 && length<=1024);
        ReadOperator(fd,password.span().first(length),deadline);
        if(options.contains("--recovery-public-input")) ReadRecoveryPublic(fd,recovery,deadline);
        close(fd);
        if (options.contains("--create")) wallet.Create(password.span().first(length));
        else wallet.Unlock(password.span().first(length),recovery);
        Zero(password.span());
        Checkpoint(out_fd,wallet.Status());
        struct sigaction action{}; action.sa_handler=Stop; sigemptyset(&action.sa_mask);
        Require(sigaction(SIGTERM,&action,nullptr)==0 && sigaction(SIGINT,&action,nullptr)==0,Code::INTERNAL);
        RunService(wallet,{options.at("--socket"),static_cast<uid_t>(uid),network,spec,fee},stopped);
        wallet.Lock();Checkpoint(out_fd,wallet.Status());return 0;
    } catch (const Error& error) { std::cerr<<"MLDSA_PILOT_ERROR "<<static_cast<uint16_t>(error.code)<<'\n';return 1; }
    catch (const std::exception&) { std::cerr<<"MLDSA_PILOT_ERROR 13\n";return 1; }
}
