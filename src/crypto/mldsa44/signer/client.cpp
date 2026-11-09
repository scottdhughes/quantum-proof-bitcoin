// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/client.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
namespace pqbtc::mldsa44::signer {
namespace {
void Read(int fd,std::span<unsigned char> bytes,detail::Clock::time_point& deadline,bool first)
{
    size_t offset=0;
    while (offset<bytes.size()) {
        detail::Wait(fd,POLLIN,deadline);
        auto count=detail::Receive(fd,bytes.subspan(offset));
        if (count<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        Require(count>0,Code::INVALID_FRAME);
        if (first) { deadline=detail::Clock::now()+std::chrono::seconds{5}; first=false; }
        offset+=count;
    }
}
}
Client::Client(const std::string& path,uid_t signer_uid,Network network,Hash spec)
{
    Require(signer_uid!=0 && signer_uid!=geteuid(),Code::AUTH);
    auto parent=detail::SocketParent(path,signer_uid); struct stat info{};
    Require(fstatat(parent.directory.value,parent.name.c_str(),&info,AT_SYMLINK_NOFOLLOW)==0 && S_ISSOCK(info.st_mode) &&
        info.st_uid==signer_uid && info.st_gid==getegid() && (info.st_mode&07777)==0660,Code::AUTH);
    sockaddr_un address{}; address.sun_family=AF_UNIX; Require(path.size()<sizeof(address.sun_path),Code::AUTH);
    std::copy(path.begin(),path.end(),address.sun_path);
    m_fd=detail::Fd{socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0)}; Require(m_fd.value>=0,Code::INTERNAL);
    auto result=connect(m_fd.value,reinterpret_cast<sockaddr*>(&address),sizeof(address));
    if (result!=0) {
        Require(errno==EINPROGRESS,Code::AUTH); detail::Wait(m_fd.value,POLLOUT,detail::Clock::now()+std::chrono::seconds{5});
        int error{0}; socklen_t size=sizeof(error); Require(getsockopt(m_fd.value,SOL_SOCKET,SO_ERROR,&error,&size)==0 && error==0,Code::AUTH);
    }
    Require(detail::Peer(m_fd.value,signer_uid),Code::AUTH);
    auto hello=NetworkBinding(network); hello.insert(hello.end(),spec.begin(),spec.end());
    auto response=Call(1,hello); if (response.status) throw Error(static_cast<Code>(response.status));
    Require(response.payload==hello,Code::BINDING);
}
Response Client::Call(uint8_t kind,Bytes body)
{
    Require(m_sequence<64,Code::LIMIT); RequestId id{}; ++m_sequence;
    for (size_t i=0;i<8;++i) id[i]=(m_sequence>>(8*i))&255;
    Frame request{kind,id,std::move(body)}; auto wire=EncodeRequest(request);
    auto deadline=detail::Clock::now()+std::chrono::seconds{5}; size_t offset{0};
    while (offset<wire.size()) {
        detail::Wait(m_fd.value,POLLOUT,deadline);
        auto count=send(m_fd.value,wire.data()+offset,wire.size()-offset,MSG_DONTWAIT|MSG_NOSIGNAL);
        if (count<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        Require(count>0,Code::INVALID_FRAME); offset+=count;
    }
    // Operation wait is distinct from the5s deadline after the first response byte.
    deadline=detail::Clock::now()+std::chrono::seconds{65}; Bytes response(32);
    Read(m_fd.value,response,deadline,true); auto header=DecodeHeader(response,true);
    response.resize(32+header.body_size); Read(m_fd.value,std::span(response).subspan(32),deadline,false);
    return DecodeResponse(response,request);
}
} // namespace pqbtc::mldsa44::signer
