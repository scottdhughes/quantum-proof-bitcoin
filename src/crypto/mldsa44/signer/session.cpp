// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/signer/session.h>
#include <algorithm>
namespace pqbtc::mldsa44::signer {
namespace {
void Put(Bytes& out,uint64_t n,size_t size) { for (size_t i=0;i<size;++i) out.push_back((n>>(8*i))&255); }
void Append(Bytes& out,std::span<const unsigned char> bytes) { out.insert(out.end(),bytes.begin(),bytes.end()); }
}
Response Session::Handle(const Frame& frame)
{
    if (Done()) return {static_cast<uint16_t>(Code::LIMIT),{}};
    ++m_completed;
    try {
        (void)EncodeRequest(frame); // Enforce direction/ID/body bounds even for library callers.
        Require(m_seen.insert(frame.id).second,Code::REPLAY);
        Bytes payload;
        if (frame.kind==1) {
            auto want=NetworkBinding(m_network); Append(want,m_spec);
            Require(frame.body==want,Code::BINDING); m_bound=true; return {0,want};
        }
        Require(m_bound,Code::AUTH);
        if (frame.kind==2) {
            Require(frame.body.size()==1 && frame.body[0]<=1);
            auto address=m_wallet.Reserve(frame.body[0]);
            Put(payload,address.branch,1); Put(payload,address.index,4); Append(payload,address.public_key); Append(payload,address.program);
        } else if (frame.kind==3) {
            auto request=DecodeSignRequest(frame.body);
            Require(request.wallet_id==m_wallet.Status().id,Code::AUTH);
            auto witnesses=m_wallet.SignTransaction(request.transaction,request.prevouts,request.paths,m_fee_cap);
            Require(witnesses.size()<=100);
            Put(payload,witnesses.size(),1);
            for (const auto& witness:witnesses) { Append(payload,witness[0]); Append(payload,witness[1]); }
        } else if (frame.kind==4) {
            Require(frame.body.empty()); m_wallet.Lock();
        } else if (frame.kind==5) {
            Require(frame.body.empty()); auto status=m_wallet.Status();
            Put(payload,status.locked?1:0,1); Append(payload,status.id); Put(payload,status.next.receive,4); Put(payload,status.next.change,4);
        }
        return {0,std::move(payload)};
    } catch (const Error& error) { return {static_cast<uint16_t>(error.code),{}}; }
    catch (const std::exception&) { return {static_cast<uint16_t>(Code::INTERNAL),{}}; }
}
} // namespace pqbtc::mldsa44::signer
