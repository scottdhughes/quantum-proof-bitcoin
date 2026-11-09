// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/transport.h>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pqbtc::mldsa44::signer::detail {
Fd::~Fd() { if (value>=0) close(value); }
Fd& Fd::operator=(Fd&& other) noexcept { if (value>=0) close(value); value=std::exchange(other.value,-1); return *this; }
Parent SocketParent(const std::string& path,uid_t owner)
{
    Require(!path.empty() && path[0]=='/',Code::AUTH);
    auto split=path.rfind('/'); auto name=path.substr(split+1);
    Require(!name.empty() && name!="." && name!="..",Code::AUTH);
    Fd directory{open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC)}; Require(directory.value>=0,Code::AUTH);
    size_t start=1;
    while (start<split) {
        auto end=path.find('/',start); Require(end!=std::string::npos && end<=split,Code::AUTH);
        auto part=path.substr(start,end-start); Require(!part.empty() && part!="." && part!="..",Code::AUTH);
        Fd next{openat(directory.value,part.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)};
        Require(next.value>=0,Code::AUTH); directory=std::move(next); start=end+1;
    }
    struct stat info{};
    Require(fstat(directory.value,&info)==0 && info.st_uid==owner && info.st_gid==getegid() && (info.st_mode&07777)==0750,Code::AUTH);
    return {std::move(directory),std::move(name)};
}
bool Peer(int fd,uid_t uid)
{
    struct ucred cred{}; socklen_t size=sizeof(cred);
    return getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&size)==0 && size==sizeof(cred) && cred.uid==uid;
}
ssize_t Receive(int fd,std::span<unsigned char> bytes)
{
    alignas(cmsghdr) std::array<unsigned char,CMSG_SPACE(8*sizeof(int))> control{};
    iovec iov{bytes.data(),bytes.size()}; msghdr message{}; message.msg_iov=&iov; message.msg_iovlen=1;
    message.msg_control=control.data(); message.msg_controllen=control.size();
    auto count=recvmsg(fd,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (count<0) return count;
    bool ancillary=(message.msg_flags&MSG_CTRUNC)!=0;
    for (auto* cmsg=CMSG_FIRSTHDR(&message);cmsg;cmsg=CMSG_NXTHDR(&message,cmsg)) {
        ancillary=true;
        if (cmsg->cmsg_level==SOL_SOCKET && cmsg->cmsg_type==SCM_RIGHTS && cmsg->cmsg_len>=CMSG_LEN(0)) {
            auto* fds=reinterpret_cast<int*>(CMSG_DATA(cmsg));
            auto n=(cmsg->cmsg_len-CMSG_LEN(0))/sizeof(int); for (size_t i=0;i<n;++i) close(fds[i]);
        }
    }
    if (ancillary) { errno=EPROTO; return -1; }
    return count;
}
void Wait(int fd,short events,Clock::time_point deadline)
{
    for (;;) {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
        Require(left>0,Code::LIMIT); pollfd entry{fd,events,0};
        auto result=poll(&entry,1,static_cast<int>(std::min<int64_t>(left,1000)));
        if (result<0 && errno==EINTR) continue;
        Require(result>=0,Code::INTERNAL);
        if (result>0) { Require((entry.revents&(POLLERR|POLLNVAL))==0,Code::INVALID_FRAME); return; }
    }
}
} // namespace pqbtc::mldsa44::signer::detail
