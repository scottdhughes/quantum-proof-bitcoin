// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Public node-side client fixture: MUST NOT link wallet/key-owner/libcrypto.
#include <crypto/mldsa44/signer/client.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
static unsigned checks{0};
static void Check(bool ok) { if (!ok) throw std::runtime_error("client fixture assertion"); ++checks; }
static Hash HashHex(const char* text)
{
    Check(std::string(text).size()==64); Hash out{};
    for (size_t i=0;i<32;++i) out[i]=std::stoi(std::string(text+i*2,2),nullptr,16);
    return out;
}
static std::string Hex(std::span<const unsigned char> data)
{
    std::string out; constexpr char digits[]{"0123456789abcdef"};
    for (auto c:data) { out.push_back(digits[c>>4]); out.push_back(digits[c&15]); } return out;
}
static uint32_t Number(std::span<const unsigned char> data)
{
    uint32_t n{0}; Check(data.size()<=4); for (size_t i=0;i<data.size();++i) n|=uint32_t{data[i]}<<(8*i); return n;
}
struct PublicAddress { uint32_t index; Bytes pk, script; Hash program; };
static PublicAddress Address(Client& client,uint8_t branch)
{
    auto response=client.Call(2,{branch}); Check(response.status==0 && response.payload.size()==1349);
    const auto& p=response.payload; Check(p[0]==branch);
    PublicAddress address{}; address.index=Number(std::span(p).subspan(1,4)); address.pk.assign(p.begin()+5,p.begin()+1317);
    std::copy_n(p.begin()+1317,32,address.program.begin());
    Check(KeyCommitment(Network::REGTEST,address.pk)==address.program);
    address.script={0x52,0x20}; address.script.insert(address.script.end(),address.program.begin(),address.program.end()); return address;
}
int main(int argc,char** argv)
{
    try {
        Check(argc>=5); auto uid=std::stoul(argv[2]); Check(uid<1000000);
        auto spec=HashHex(argv[3]); std::string scene{argv[4]};
        if (scene=="wrong-peer") {
            try { Client client{argv[1],static_cast<uid_t>(uid+7),Network::REGTEST,spec}; }
            catch (const Error& error) { Check(error.code==Code::AUTH); std::cout<<"{\"result\":\"PASS\",\"control\":\"wrong-peer\"}\n"; return 0; }
            throw std::runtime_error("client accepted wrong peer");
        }
        if (scene=="wrong-spec") {
            spec[0]^=1;
            try { Client client{argv[1],static_cast<uid_t>(uid),Network::REGTEST,spec}; }
            catch (const Error& error) { Check(error.code==Code::BINDING); std::cout<<"{\"result\":\"PASS\",\"control\":\"wrong-spec\"}\n"; return 0; }
            throw std::runtime_error("client accepted wrong spec");
        }
        Client client{argv[1],static_cast<uid_t>(uid),Network::REGTEST,spec};
        auto status=client.Call(5,{}); Check(status.status==0 && status.payload.size()==25);
        RequestId wallet_id{}; std::copy_n(status.payload.begin()+1,16,wallet_id.begin());
        if (scene=="spend") {
            Check(status.payload[0]==0);
            auto a=Address(client,0),b=Address(client,1); Check(a.index==0 && b.index==0);
            Input in{}; in.hash[0]=17; in.index=0; in.sequence=0xfffffffe; auto second=in; second.hash[0]=18;
            Transaction tx{2,{in,second},{{99000,a.script},{0,{0x6a,1,0x42}}},7};
            std::vector<Output> prevouts{{50000,a.script},{50000,b.script}};
            SignRequest request{wallet_id,tx,prevouts,{{0,a.index},{1,b.index}}};
            auto response=client.Call(3,EncodeSignRequest(request));
            Check(response.status==0 && response.payload.size()==1+2*(2420+1312) && response.payload[0]==2);
            PreparedTransaction prepared{tx,prevouts};
            for (size_t i=0;i<2;++i) {
                auto offset=1+i*3732;
                std::array<Bytes,2> witness{Bytes{response.payload.begin()+offset,response.payload.begin()+offset+2420},
                    Bytes{response.payload.begin()+offset+2420,response.payload.begin()+offset+3732}};
                Check(VerifyWitness(Network::REGTEST,prepared,i,i==0?a.program:b.program,witness));
                auto changed=prevouts; changed[0].amount++;
                Check(!VerifyWitness(Network::REGTEST,PreparedTransaction{tx,changed},i,i==0?a.program:b.program,witness));
            }
            auto wrong=request; wrong.wallet_id[0]^=1;
            Check(client.Call(3,EncodeSignRequest(wrong)).status==static_cast<uint16_t>(Code::AUTH));
            Check(client.Call(4,{}).status==0);
            Check(client.Call(5,{}).payload[0]==1);
            Check(client.Call(3,EncodeSignRequest(request)).status==static_cast<uint16_t>(Code::LOCKED));
            Check(client.Call(2,{0}).status==static_cast<uint16_t>(Code::LOCKED));
        } else if (scene=="reserve") {
            Check(argc==6 && status.payload[0]==0); auto address=Address(client,0);
            Check(address.index==std::stoul(argv[5]));
        } else { Check(scene=="status"); }
        status=client.Call(5,{}); Check(status.status==0 && status.payload.size()==25);
        std::cout<<"{\"result\":\"PASS\",\"checks\":"<<checks<<",\"wallet_id\":\""<<Hex(wallet_id)
                 <<"\",\"locked\":"<<unsigned(status.payload[0])<<",\"next_receive\":"<<Number(std::span(status.payload).subspan(17,4))
                 <<",\"next_change\":"<<Number(std::span(status.payload).subspan(21,4))<<"}\n"; return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
