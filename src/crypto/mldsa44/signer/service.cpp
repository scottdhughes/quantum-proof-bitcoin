// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/service.h>
#include <crypto/mldsa44/signer/transport.h>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <fcntl.h>
#include <map>
#include <limits>
#include <memory>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace pqbtc::mldsa44::signer {
namespace {
using detail::Clock;
struct Connection {
    detail::Fd socket; Session session; Bytes input=Bytes(32),output;
    size_t read{0},written{0}; bool inflight{false},bound{false};
    unsigned count{0}; std::set<RequestId> seen;
    uint8_t output_kind{0}; uint16_t output_status{0};
    Clock::time_point deadline=Clock::now()+std::chrono::seconds{5};
    Clock::time_point private_deadline=Clock::time_point::max();
    Connection(int fd,Wallet& wallet,const ServiceOptions& options):socket(fd),session(wallet,options.network,options.spec,options.fee_cap) {}
};
struct Job { std::shared_ptr<Connection> connection; Frame frame; uint64_t epoch; Clock::time_point deadline; };
struct Result { Job job; Response response; bool close{false}; };
class Worker {
    std::mutex mutex; std::condition_variable wake; bool stop{false};
    std::deque<Job> queue; std::deque<Result> results; std::thread thread;
    void Loop()
    {
        for (;;) {
            Job job;
            { std::unique_lock lock{mutex}; wake.wait(lock,[&]{return stop || !queue.empty();});
              if (stop) return;
              job=std::move(queue.front()); queue.pop_front(); }
            bool late=job.frame.kind!=4 && Clock::now()>=job.deadline;
            Response response{static_cast<uint16_t>(Code::LIMIT),{}};
            if (!late) response=job.connection->session.Handle(job.frame);
            late=late || (job.frame.kind!=4 && Clock::now()>=job.deadline);
            { std::lock_guard lock{mutex}; results.push_back({std::move(job),std::move(response),late}); }
        }
    }
public:
    Worker():thread([this]{Loop();}) {}
    ~Worker() { {std::lock_guard lock{mutex};stop=true;queue.clear();} wake.notify_one(); thread.join(); }
    bool Push(Job job,bool barrier)
    {
        std::lock_guard lock{mutex};
        if (barrier) {
            for (auto it=queue.begin();it!=queue.end();) {
                if (it->frame.kind==2 || it->frame.kind==3) {
                    results.push_back({std::move(*it),{static_cast<uint16_t>(Code::LOCKED),{}},false}); it=queue.erase(it);
                } else ++it;
            }
            if (queue.size()>=16) { results.push_back({std::move(queue.back()),{static_cast<uint16_t>(Code::LIMIT),{}},false});queue.pop_back(); }
            queue.push_front(std::move(job));
        } else { if (queue.size()>=16) return false; queue.push_back(std::move(job)); }
        wake.notify_one(); return true;
    }
    std::deque<Result> Drain() { std::lock_guard lock{mutex}; std::deque<Result> out; out.swap(results); return out; }
};
struct SocketCleanup {
    int directory; std::string name; ino_t inode{0};
    ~SocketCleanup() { struct stat info{}; if (inode && fstatat(directory,name.c_str(),&info,AT_SYMLINK_NOFOLLOW)==0 &&
        S_ISSOCK(info.st_mode) && info.st_uid==geteuid() && info.st_ino==inode) (void)unlinkat(directory,name.c_str(),0); }
};
bool DiscardResult(const Result& result,uint64_t epoch,Clock::time_point now)
{
    return result.close || (result.response.status==0 && (result.job.frame.kind==2 || result.job.frame.kind==3) &&
        (result.job.epoch!=epoch || now>=result.job.deadline));
}
bool DiscardPending(const Connection& connection,bool barrier,Clock::time_point now)
{
    return !connection.output.empty() && connection.output_status==0 &&
        (connection.output_kind==2 || connection.output_kind==3) && (barrier || now>=connection.private_deadline);
}
void Reply(Connection& connection,const Frame& frame,Response response,Clock::time_point private_deadline=Clock::time_point::max())
{
    connection.output_kind=frame.kind; connection.output_status=response.status;
    connection.output=EncodeResponse(frame,response); connection.written=0;
    connection.deadline=Clock::now()+std::chrono::seconds{5};
    connection.private_deadline=private_deadline;
}
} // namespace

void RunService(Wallet& wallet,const ServiceOptions& options,const std::atomic<bool>& stop)
{
    Require(geteuid()!=0 && options.node_uid!=0 && options.node_uid!=geteuid(),Code::AUTH);
    Require(options.network==Network::REGTEST,Code::UNSUPPORTED);
    Require(options.fee_cap<=2100000000000000ULL);
    auto parent=detail::SocketParent(options.socket,geteuid()); struct stat old{};
    Require(fstatat(parent.directory.value,parent.name.c_str(),&old,AT_SYMLINK_NOFOLLOW)!=0 && errno==ENOENT,Code::STORAGE);
    detail::Fd listener{socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0)};
    Require(listener.value>=0,Code::INTERNAL);
    sockaddr_un address{};address.sun_family=AF_UNIX;
    char descriptor[std::numeric_limits<int>::digits10+2];
    const auto encoded=std::to_chars(descriptor,descriptor+sizeof(descriptor),parent.directory.value);
    Require(encoded.ec==std::errc{},Code::INTERNAL);
    std::string stable="/proc/self/fd/"+std::string(descriptor,encoded.ptr)+"/"+parent.name;
    Require(stable.size()<sizeof(address.sun_path) && options.socket.size()<sizeof(address.sun_path),Code::STORAGE);
    std::copy(stable.begin(),stable.end(),address.sun_path);
    Require(bind(listener.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,Code::STORAGE);
    Require(fchmodat(parent.directory.value,parent.name.c_str(),0660,0)==0,Code::STORAGE);
    struct stat current{}; Require(fstatat(parent.directory.value,parent.name.c_str(),&current,AT_SYMLINK_NOFOLLOW)==0 &&
        S_ISSOCK(current.st_mode) && current.st_uid==geteuid() && current.st_gid==getegid(),Code::STORAGE);
    SocketCleanup cleanup{parent.directory.value,parent.name,current.st_ino};
    Require(listen(listener.value,64)==0,Code::INTERNAL);
    uint64_t epoch{0}; bool locked_barrier{false};
    Worker worker; std::map<int,std::shared_ptr<Connection>> connections;
    while (!stop.load(std::memory_order_relaxed)) {
        for (auto& result:worker.Drain()) {
            auto& c=*result.job.connection; if (c.socket.value<0) continue;
            if (DiscardResult(result,epoch,Clock::now())) {
                c.socket=detail::Fd{}; continue;
            }
            if (result.job.frame.kind==1 && result.response.status==0) c.bound=true;
            Reply(c,result.job.frame,std::move(result.response),result.job.deadline);
        }
        std::vector<pollfd> polls{{listener.value,POLLIN,0}};
        for (auto it=connections.begin();it!=connections.end();) {
            auto& c=*it->second;
            if (c.socket.value<0 || DiscardPending(c,false,Clock::now()) || ((!c.inflight || !c.output.empty()) && Clock::now()>=c.deadline)) { c.socket=detail::Fd{};it=connections.erase(it); }
            else { polls.push_back({it->first,static_cast<short>(!c.output.empty()?POLLOUT:c.inflight?0:POLLIN),0});++it; }
        }
        auto polled=poll(polls.data(),polls.size(),50);
        if (polled<0 && errno==EINTR) continue;
        Require(polled>=0,Code::INTERNAL);
        if (polls[0].revents&POLLIN) {
            for (;;) {
                int fd=accept4(listener.value,nullptr,nullptr,SOCK_CLOEXEC|SOCK_NONBLOCK);
                if (fd<0) { if (errno==EINTR) continue;break; }
                detail::Fd accepted{fd};
                if (connections.size()>=64 || !detail::Peer(fd,options.node_uid)) continue;
                auto connection=std::make_shared<Connection>(accepted.value,wallet,options);accepted.value=-1;
                connections.emplace(fd,std::move(connection));
            }
        }
        for (size_t i=1;i<polls.size();++i) {
            auto found=connections.find(polls[i].fd); if (found==connections.end()) continue;
            auto connection=found->second; auto& c=*connection;
            try {
                if (polls[i].revents&(POLLHUP|POLLERR|POLLNVAL)) { c.socket=detail::Fd{}; continue; }
                if (!c.output.empty() && (polls[i].revents&POLLOUT)) {
                    if (DiscardPending(c,false,Clock::now())) { c.socket=detail::Fd{};continue; }
                    auto sent=send(c.socket.value,c.output.data()+c.written,c.output.size()-c.written,MSG_DONTWAIT|MSG_NOSIGNAL);
                    if (sent<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
                    Require(sent>0,Code::INVALID_FRAME); c.written+=sent;
                    if (c.written==c.output.size()) {
                        if (c.count>=64) { c.socket=detail::Fd{};continue; }
                        c.output.clear();c.inflight=false;c.input.assign(32,0);c.read=0;c.deadline=Clock::now()+std::chrono::seconds{5};
                    }
                } else if (!c.inflight && c.output.empty() && (polls[i].revents&POLLIN)) {
                    while (c.read<c.input.size()) {
                        auto count=detail::Receive(c.socket.value,std::span(c.input).subspan(c.read));
                        if (count<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) break;
                        Require(count>0,Code::INVALID_FRAME);c.read+=count;
                        if (c.read==32 && c.input.size()==32) { auto h=DecodeHeader(c.input,false);c.input.resize(32+h.body_size); }
                    }
                    if (c.read!=c.input.size()) continue;
                    auto frame=DecodeRequest(c.input);++c.count;c.inflight=true;
                    if (!c.seen.insert(frame.id).second) { Reply(c,frame,{static_cast<uint16_t>(Code::REPLAY),{}});continue; }
                    bool barrier=frame.kind==4 && frame.body.empty() && c.bound && !locked_barrier;
                    if (barrier) {
                        locked_barrier=true;++epoch;
                        for (auto& [fd,pending]:connections) {
                            (void)fd;
                            if (DiscardPending(*pending,true,Clock::now())) pending->socket=detail::Fd{};
                        }
                    }
                    Job job{connection,std::move(frame),epoch,Clock::now()+std::chrono::seconds{60}};
                    if (!worker.Push(job,barrier)) Reply(c,job.frame,{static_cast<uint16_t>(Code::LIMIT),{}});
                }
            } catch (const Error&) { c.socket=detail::Fd{}; }
        }
    }
    for (auto& [fd,c]:connections) { (void)fd;c->socket=detail::Fd{}; }
    // Worker destruction joins active work; no asynchronous secret-memory kill.
}
} // namespace pqbtc::mldsa44::signer
