// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Public byte codec only: no wallet, key generation, entropy or secret policy.
#include <crypto/mldsa44/signer/ipc.h>
#include <algorithm>

namespace pqbtc::mldsa44::signer {
namespace {
constexpr size_t MAX_BODY{1048576};
void Put(Bytes& out, uint64_t value, size_t size) { for (size_t i=0; i<size; ++i) out.push_back((value >> (8*i)) & 255); }
void Append(Bytes& out, std::span<const unsigned char> bytes) { out.insert(out.end(), bytes.begin(), bytes.end()); }
void Compact(Bytes& out, uint64_t n)
{
    if (n < 253) Put(out,n,1);
    else if (n <= 65535) { out.push_back(253); Put(out,n,2); }
    else if (n <= 0xffffffffULL) { out.push_back(254); Put(out,n,4); }
    else { out.push_back(255); Put(out,n,8); }
}
void Blob(Bytes& out, std::span<const unsigned char> bytes) { Compact(out,bytes.size()); Append(out,bytes); }
class Reader {
    std::span<const unsigned char> m_bytes; size_t m_offset{0};
public:
    explicit Reader(std::span<const unsigned char> bytes) : m_bytes(bytes) { Require(bytes.size() <= MAX_BODY); }
    auto Take(size_t size)
    {
        Require(size <= m_bytes.size()-m_offset); auto part=m_bytes.subspan(m_offset,size); m_offset+=size; return part;
    }
    uint64_t Number(size_t size) { uint64_t n=0; auto part=Take(size); for (size_t i=0;i<size;++i) n|=uint64_t{part[i]}<<(8*i); return n; }
    size_t Count(size_t max)
    {
        auto n=Number(1);
        if (n >= 253) { auto size=n==253?2:n==254?4:8; n=Number(size); Require(n >= (size==2?253:size==4?65536:uint64_t{1}<<32)); }
        Require(n <= max); return n;
    }
    Bytes Blob(size_t max) { auto bytes=Take(Count(max)); return {bytes.begin(),bytes.end()}; }
    void End() { Require(m_offset==m_bytes.size()); }
};
Bytes Wire(uint8_t kind, RequestId id, std::span<const unsigned char> body, bool response)
{
    Require(body.size() <= MAX_BODY,Code::LIMIT);
    Bytes out{'P','Q','M','S','I','P','C','1',1,0,kind,0}; Append(out,id); Put(out,body.size(),4);
    (void)DecodeHeader(out,response); Append(out,body); return out;
}
void ValidateResponse(const Response& response)
{
    Require(response.status <= 13 && (response.status==0 || response.payload.empty()) && response.payload.size() <= MAX_BODY-2);
}
} // namespace
Header DecodeHeader(std::span<const unsigned char> bytes, bool response)
{
    Require(bytes.size()==32,Code::INVALID_FRAME);
    constexpr std::array<unsigned char,8> magic{'P','Q','M','S','I','P','C','1'};
    Require(std::equal(magic.begin(),magic.end(),bytes.begin()),Code::INVALID_FRAME);
    Require(bytes[8]==1 && bytes[9]==0,Code::VERSION);
    auto kind=bytes[10];
    Require(bytes[11]==0 && (response ? kind>=129 && kind<=133 : kind>=1 && kind<=5),Code::INVALID_FRAME);
    RequestId id{}; std::copy_n(bytes.begin()+12,16,id.begin());
    Require(std::any_of(id.begin(),id.end(),[](auto b){return b!=0;}),Code::INVALID_FRAME);
    uint32_t size{0}; for (size_t i=0;i<4;++i) size |= uint32_t{bytes[28+i]}<<(8*i);
    Require(size <= MAX_BODY,Code::LIMIT); return {kind,id,size};
}
Frame DecodeRequest(std::span<const unsigned char> frame)
{
    Require(frame.size()>=32,Code::INVALID_FRAME); auto h=DecodeHeader(frame.first(32),false);
    Require(frame.size()==32+h.body_size,Code::INVALID_FRAME);
    return {h.kind,h.id,Bytes{frame.begin()+32,frame.end()}};
}
Bytes EncodeRequest(const Frame& frame) { return Wire(frame.kind,frame.id,frame.body,false); }
Bytes EncodeResponse(const Frame& request, const Response& response)
{
    Require(request.kind>=1 && request.kind<=5); ValidateResponse(response);
    Bytes body; Put(body,response.status,2); Append(body,response.payload); return Wire(request.kind|128,request.id,body,true);
}
Response DecodeResponse(std::span<const unsigned char> frame, const Frame& expected)
{
    Require(frame.size()>=32,Code::INVALID_FRAME); auto h=DecodeHeader(frame.first(32),true);
    Require(expected.kind>=1 && expected.kind<=5 && h.kind==(expected.kind|128) && h.id==expected.id &&
        frame.size()==32+h.body_size && h.body_size>=2,Code::INVALID_FRAME);
    Response response{static_cast<uint16_t>(frame[32] | uint16_t{frame[33]}<<8),{frame.begin()+34,frame.end()}};
    ValidateResponse(response); return response;
}
Bytes EncodeSignRequest(const SignRequest& request)
{
    try {
        auto wire=SerializeUnsigned(request.transaction,request.prevouts);
        Require(request.paths.size()==request.transaction.inputs.size());
        Bytes out; Append(out,request.wallet_id); Blob(out,wire); Compact(out,request.paths.size());
        for (size_t i=0;i<request.paths.size();++i) {
            const auto& path=request.paths[i]; Require(path.branch<=1 && path.index<0x80000000U);
            Put(out,request.prevouts[i].amount,8); Blob(out,request.prevouts[i].script); Put(out,path.branch,1); Put(out,path.index,4);
        }
        Require(out.size()<=MAX_BODY); return out;
    } catch (const std::invalid_argument&) { throw Error(Code::VALIDATION); }
}
SignRequest DecodeSignRequest(std::span<const unsigned char> body)
{
    try {
        Reader reader{body}; SignRequest request{}; auto id=reader.Take(16); std::copy(id.begin(),id.end(),request.wallet_id.begin());
        auto wire=reader.Blob(MAX_BODY); auto count=reader.Count(100); Require(count!=0);
        for (size_t i=0;i<count;++i) {
            auto amount=reader.Number(8); auto script=reader.Blob(10000);
            auto branch=reader.Number(1), index=reader.Number(4); Require(branch<=1 && index<0x80000000U);
            request.prevouts.push_back({amount,std::move(script)}); request.paths.push_back({static_cast<uint8_t>(branch),static_cast<uint32_t>(index)});
        }
        reader.End(); request.transaction=ParseUnsigned(wire,request.prevouts); return request;
    } catch (const std::invalid_argument&) { throw Error(Code::VALIDATION); }
}
} // namespace pqbtc::mldsa44::signer
