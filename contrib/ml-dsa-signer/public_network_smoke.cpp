// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// PUBLIC temporary TEST fixture. No public network or node execution.
#include <crypto/mldsa44/signer/service.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
static unsigned checks{0};
static void Check(bool value) { if (!value) throw std::runtime_error("public network fixture assertion"); ++checks; }
template<typename F> static void Reject(Code code, F action)
{
    try { action(); } catch (const Error& error) { Check(error.code==code); return; }
    throw std::runtime_error("public network accepted invalid operation");
}
static Frame Request(uint8_t kind,unsigned sequence,Bytes body={})
{
    RequestId id{};id[0]=sequence;return {kind,id,std::move(body)};
}
static Bytes Hello(Network network,Hash spec)
{
    auto result=NetworkBinding(network);result.insert(result.end(),spec.begin(),spec.end());return result;
}
int main(int argc,char** argv)
{
    try {
        Check(argc==2);
        std::filesystem::path directory{argv[1]};
        std::filesystem::create_directory(directory);Check(chmod(argv[1],0700)==0);
        const Bytes password{'p','u','b','l','i','c','-','t','e','s','t'};
        Identity identity{};Address address{};
        {
            Reject(Code::UNSUPPORTED,[&]{Wallet main{directory.string(),Network::MAIN};});
            Wallet wallet{directory.string(),Network::TEST};
            const auto ipc=directory/"ipc";
            std::filesystem::create_directory(ipc);Check(chmod(ipc.c_str(),0750)==0);
            const auto socket=(ipc/"signer.sock").string();
            const uid_t peer=geteuid()==1001?1000:1001;
            const std::atomic<bool> stopped{true};
            Reject(Code::BINDING,[&]{RunService(wallet,{socket,peer,Network::TEST,{},1000},stopped);});
            Check(!std::filesystem::exists(ipc/"signer.sock") && !std::filesystem::exists(directory/"wallet.dat"));
            Check(wallet.Status().locked && wallet.Status().next==Counters{0,0});
            // Historical regtest services may still use a generic fixture digest.
            const auto generic=directory/"generic";
            std::filesystem::create_directory(generic);Check(chmod(generic.c_str(),0700)==0);
            {
                Wallet old{generic.string(),Network::REGTEST};
                RunService(old,{socket,peer,Network::REGTEST,{},1000},stopped);
                Check(!std::filesystem::exists(generic/"wallet.dat"));
            }
            wallet.Create(password);
            identity=wallet.Status().id;address=wallet.Reserve(0);
            Check(address.index==0 && wallet.Status().next==Counters{1,0});
            Check(address.program==KeyCommitment(Network::TEST,address.public_key));
            Check(address.program!=KeyCommitment(Network::REGTEST,address.public_key));
            Hash spec{};Session session{wallet,Network::TEST,spec,1000};
            Check(session.Handle(Request(1,1,Hello(Network::REGTEST,spec))).status==static_cast<uint16_t>(Code::BINDING));
            Check(session.Handle(Request(2,2,{0})).status==static_cast<uint16_t>(Code::AUTH));
            Check(wallet.Status().next==Counters{1,0});
            Check(session.Handle(Request(1,3,Hello(Network::TEST,spec))).status==0);
            Bytes script{0x52,0x20};script.insert(script.end(),address.program.begin(),address.program.end());
            Input input{};input.hash[0]=1;input.sequence=0xfffffffe;
            Transaction transaction{2,{input},{{99000,script}},0};
            std::vector<Output> prevouts{{100000,script}};
            std::vector<Derivation> paths{{0,0}};
            auto witnesses=wallet.SignTransaction(transaction,prevouts,paths,1000);
            PreparedTransaction prepared{transaction,prevouts};
            Check(witnesses.size()==1 && VerifyWitness(Network::TEST,prepared,0,address.program,witnesses[0]));
            Check(!VerifyWitness(Network::REGTEST,prepared,0,address.program,witnesses[0]));
            auto wrong=prevouts;auto wrong_program=KeyCommitment(Network::REGTEST,address.public_key);
            std::copy(wrong_program.begin(),wrong_program.end(),wrong[0].script.begin()+2);
            Reject(Code::VALIDATION,[&]{wallet.SignTransaction(transaction,wrong,paths,1000);});
        }
        {
            Wallet wrong{directory.string(),Network::REGTEST};
            Reject(Code::BINDING,[&]{wrong.Unlock(password,{identity,{1,0},{}});});
            Check(wrong.Status().locked);
        }
        {
            Wallet restored{directory.string(),Network::TEST};
            restored.Unlock(password,{identity,{7,3},{address}});
            Check(restored.Status().next==Counters{7,3});
            Check(restored.Public(0,0).program==address.program);
            Check(restored.Reserve(0).index==7);
        }
        std::cout<<"{\"result\":\"PASS\",\"checks\":"<<checks<<",\"test_signatures_verified\":1}\n";
        return 0;
    } catch(const Error& error) { std::cerr<<"public network signer refusal "<<static_cast<unsigned>(error.code)<<'\n';return 1; }
    catch(const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
