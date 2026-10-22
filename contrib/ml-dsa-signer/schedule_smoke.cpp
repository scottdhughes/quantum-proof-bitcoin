// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Test-only translation unit: exercise the actual private scheduler without
// adding test controls to the production service API or pilot executable.
#include <crypto/mldsa44/signer/service.cpp>
#include "../ml-dsa-key-lifecycle/key_lifecycle.h"
#include "../ml-dsa-engineering/pqbtc_mldsa44.h"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <atomic>
#include <type_traits>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
static_assert(std::is_invocable_v<decltype(RunService),Wallet&,const ServiceOptions&,const std::atomic<bool>&>,
    "service stop signal must be lock-free atomic across its threads");
static unsigned checks{0};
static void Check(bool ok) { if (!ok) throw std::runtime_error("scheduler fixture assertion"); ++checks; }
static std::mutex gate_mutex;
static std::condition_variable gate_wake;
static bool block_sign{false}, entered{false};
static int forced_code{0};static bool corrupt{false};static unsigned fault_call{0};
extern "C" int __real_pqbtc_mldsa44_key_sign_hedged(const pqbtc_mldsa44_key*,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
extern "C" int __wrap_pqbtc_mldsa44_key_sign_hedged(const pqbtc_mldsa44_key* key,uint8_t* signature,size_t size,
    const uint8_t* message,size_t message_size,const uint8_t* context,size_t context_size)
{
    { std::unique_lock lock{gate_mutex}; entered=true; gate_wake.notify_all();
      gate_wake.wait(lock,[]{return !block_sign;}); }
    bool inject=fault_call && --fault_call==0;
    if (inject && forced_code) return forced_code;
    auto code=__real_pqbtc_mldsa44_key_sign_hedged(key,signature,size,message,message_size,context,context_size);
    if (inject && corrupt && code==0) signature[0]^=1;
    return code;
}
static void Block() { std::lock_guard lock{gate_mutex}; block_sign=true; entered=false; }
static void Entered()
{
    std::unique_lock lock{gate_mutex};
    Check(gate_wake.wait_for(lock,std::chrono::seconds{5},[]{return entered;}));
}
static void Release() { {std::lock_guard lock{gate_mutex};block_sign=false;} gate_wake.notify_all(); }
struct ReleaseOnFailure { ~ReleaseOnFailure() { Release(); } };
static Frame Request(uint8_t kind,unsigned id,Bytes body={})
{
    RequestId identity{}; identity[0]=id; identity[1]=id>>8; return {kind,identity,std::move(body)};
}
static std::deque<Result> Await(Worker& worker,size_t count)
{
    std::deque<Result> out; auto deadline=Clock::now()+std::chrono::seconds{5};
    while (out.size()<count) {
        auto batch=worker.Drain(); for (auto& item:batch) out.push_back(std::move(item));
        if (Clock::now()>deadline) throw std::runtime_error("scheduler result deadline");
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    Check(out.size()==count); return out;
}
int main(int argc,char** argv)
{
    try {
        Check(argc==2); std::filesystem::create_directory(argv[1]); Check(chmod(argv[1],0700)==0);
        Wallet wallet{argv[1],Network::REGTEST}; wallet.Create(Bytes{'p','u','b','l','i','c'});
        auto address=wallet.Reserve(0); Bytes script{0x52,0x20}; script.insert(script.end(),address.program.begin(),address.program.end());
        Input input{};input.hash[0]=1;input.sequence=0xfffffffe;
        Transaction tx{2,{input},{{49000,script}},0};
        auto encoded=EncodeSignRequest({wallet.Status().id,tx,{{50000,script}},{{0,0}}});
        ServiceOptions options{"",1001,Network::REGTEST,{},1000};
        auto connection=std::make_shared<Connection>(-1,wallet,options);
        auto now=Clock::now();
        Result result{{connection,Request(2,30,{0}),0,now+std::chrono::seconds{60}},{0,{}},false};
        Check(DiscardResult(result,1,now));result.job.frame.kind=3;Check(DiscardResult(result,1,now));
        Check(!DiscardResult(result,0,now));Check(DiscardResult(result,0,result.job.deadline));
        result.response.status=5;Check(!DiscardResult(result,1,now));
        result.close=true;Check(DiscardResult(result,0,now));
        for (uint8_t kind:{uint8_t{2},uint8_t{3}}) {
            Reply(*connection,Request(kind,31),{0,Bytes{1}},now+std::chrono::seconds{60});
            Check(DiscardPending(*connection,true,now));Check(!DiscardPending(*connection,false,now));
            Check(DiscardPending(*connection,false,now+std::chrono::seconds{60}));
            Reply(*connection,Request(kind,31),{5,{}},now-std::chrono::seconds{1});
            Check(!DiscardPending(*connection,true,now));
        }
        connection->output.clear();
        int peers[2];Check(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,peers)==0);
        detail::Fd peer_a{peers[0]},peer_b{peers[1]};
        Check(detail::Peer(peer_a.value,geteuid()));Check(!detail::Peer(peer_a.value,geteuid()+1));
        auto hello=NetworkBinding(Network::REGTEST);hello.resize(68,0);
        Check(connection->session.Handle(Request(1,1,hello)).status==0);
        // Fail the second real input after the first succeeded: never return a partial set.
        auto two=tx;auto second=input;second.hash[0]=2;two.inputs.push_back(second);two.outputs[0].amount=99000;
        auto multi=EncodeSignRequest({wallet.Status().id,two,{{50000,script},{50000,script}},{{0,0},{0,0}}});
        unsigned control_id=40;
        for (int code:{PQBTC_MLDSA44_ERR_ENTROPY_SOURCE,PQBTC_MLDSA44_ERR_ENTROPY_LENGTH,
                       PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO,PQBTC_MLDSA44_ERR_ENTROPY_REPEAT}) {
            forced_code=code;fault_call=2;
            auto failed=connection->session.Handle(Request(3,control_id++,multi));
            Check(failed.status==10 && failed.payload.empty() && fault_call==0);
        }
        forced_code=0;corrupt=true;fault_call=2;
        auto invalid=connection->session.Handle(Request(3,control_id,multi));
        Check(invalid.status==11 && invalid.payload.empty() && fault_call==0);corrupt=false;
        Worker worker; ReleaseOnFailure release;
        auto push=[&](Frame frame,bool barrier=false,Clock::time_point deadline=Clock::now()+std::chrono::seconds{60}) {
            return worker.Push({connection,std::move(frame),0,deadline},barrier);
        };
        // Removing the queue bound would accept the seventeenth waiting job.
        Block();Check(push(Request(3,2,encoded)));Entered();
        for (unsigned i=3;i<19;++i) Check(push(Request(5,i)));
        Check(!push(Request(5,19)));Check(worker.Drain().empty());Release();
        auto full=Await(worker,17);for (const auto& item:full) Check(item.response.status==0 && !item.close);
        // Expired queued work must not reserve a durable address.
        auto before=wallet.Status().next.receive;
        Check(push(Request(2,20,{0}),false,Clock::now()-std::chrono::seconds{1}));
        auto expired=Await(worker,1);Check(expired[0].close && expired[0].response.status==6);
        Check(wallet.Status().next.receive==before);
        // Deadline expiry while inside real signing must mark the result for discard.
        Block();auto deadline=Clock::now()+std::chrono::milliseconds{100};
        Check(push(Request(3,21,encoded),false,deadline));Entered();
        std::this_thread::sleep_until(deadline+std::chrono::milliseconds{10});Release();
        auto late=Await(worker,1);Check(late[0].close);
        // LOCK cancels queued private work, waits for active signing, then wipes.
        Block();Check(push(Request(3,22,encoded)));Entered();
        Check(push(Request(2,23,{0})));Check(push(Request(3,24,encoded)));Check(push(Request(4,25),true));
        auto cancelled=Await(worker,2);
        for (const auto& item:cancelled) Check(item.response.status==5 && item.response.payload.empty());
        Release();auto locked=Await(worker,2);Check(locked[0].job.frame.kind==3 && locked[1].job.frame.kind==4);
        Check(locked[1].response.status==0 && wallet.Status().locked && wallet.Status().next.receive==before);
        std::cout<<"{\"result\":\"PASS\",\"checks\":"<<checks<<",\"queue_capacity\":16,\"expired_work_not_executed\":true,\"late_result_discard\":true,\"lock_cancels_queued_private_work\":true}\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n';return 1; }
}
