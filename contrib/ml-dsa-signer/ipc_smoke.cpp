// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// PUBLIC temporary wallet fixture, not a node or network activation test.
#include <crypto/mldsa44/signer/ipc.h>
#include <crypto/mldsa44/signer/session.h>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd) { return __real_fsync(fd); }
static unsigned checks{0};
static void Check(bool value) { if (!value) throw std::runtime_error("IPC fixture assertion"); ++checks; }
template<typename F> static void Reject(Code code, F action)
{
    try { action(); } catch (const Error& error) { Check(error.code == code); return; }
    throw std::runtime_error("IPC accepted invalid operation");
}
static Bytes Hex(const char* text)
{
    const std::string input{text}; Check(input.size()%2==0);
    Bytes result;
    for (size_t i=0;i<input.size();i+=2) {
        unsigned byte{};
        const auto parsed=std::from_chars(input.data()+i,input.data()+i+2,byte,16);
        Check(parsed.ec==std::errc{} && parsed.ptr==input.data()+i+2);
        result.push_back(byte);
    }
    return result;
}
static Frame Request(uint8_t kind, unsigned id, Bytes body = {})
{
    RequestId identity{}; identity[0] = id & 255; identity[1] = id >> 8; return {kind, identity, std::move(body)};
}
static Bytes Script(const Address& address)
{
    Bytes script{0x52, 0x20}; script.insert(script.end(), address.program.begin(), address.program.end()); return script;
}
static std::string Hex(std::span<const unsigned char> bytes)
{
    std::string text; constexpr char digits[]{"0123456789abcdef"};
    for (auto byte:bytes) { text.push_back(digits[byte>>4]); text.push_back(digits[byte&15]); } return text;
}
int main(int argc, char** argv)
{
    try {
        Check(argc == 2);
        auto status = Request(5, 1);
        auto literal = Hex("50514d5349504331010005000100000000000000000000000000000000000000");
        Check(EncodeRequest(status) == literal);
        auto decoded = DecodeRequest(literal); Check(decoded.kind == 5 && decoded.id == status.id && decoded.body.empty());
        for (size_t i = 0; i < literal.size(); ++i)
            Reject(Code::INVALID_FRAME, [&] { DecodeRequest(std::span(literal).first(i)); });
        for (size_t offset : {size_t{0}, size_t{11}, size_t{28}}) {
            auto bad = literal; bad[offset] ^= 1;
            Reject(Code::INVALID_FRAME, [&] { DecodeRequest(bad); });
        }
        auto version = literal; version[8] = 2; Reject(Code::VERSION, [&] { DecodeRequest(version); });
        auto response = literal; response[10] |= 0x80; Reject(Code::INVALID_FRAME, [&] { DecodeRequest(response); });
        auto zero = literal; zero[12] = 0; Reject(Code::INVALID_FRAME, [&] { DecodeRequest(zero); });
        auto huge = literal; huge[28] = 1; huge[30] = 16; Reject(Code::LIMIT, [&] { DecodeHeader(huge, false); });
        auto reply = EncodeResponse(status, {0, Bytes{1}});
        Check(DecodeResponse(reply, status).payload == Bytes{1});
        Reject(Code::INVALID_FRAME, [&] { DecodeResponse(reply, Request(5, 2)); });
        Reject(Code::INVALID_FRAME, [&] { DecodeResponse(reply, Request(4, 1)); });
        Reject(Code::VALIDATION, [&] { EncodeResponse(status, {5, Bytes{1}}); });
        Reject(Code::VALIDATION, [&] { EncodeResponse(status, {14, {}}); });

        std::filesystem::create_directory(argv[1]); Check(chmod(argv[1], 0700) == 0);
        Wallet wallet{argv[1], Network::REGTEST}; wallet.Create(Bytes{'p','u','b','l','i','c'});
        auto a = wallet.Reserve(0), b = wallet.Reserve(1);
        Input in0{}; in0.hash[0]=1; in0.index=0; in0.sequence=0xfffffffe;
        auto in1=in0; in1.hash[0]=2;
        Transaction tx{2, {in0,in1}, {{99000, Script(a)}, {0, {0x6a,1,0x42}}}, 7};
        std::vector<Output> prevouts{{50000, Script(a)}, {50000, Script(b)}};
        std::vector<Derivation> paths{{0,0},{1,0}};
        SignRequest sign{wallet.Status().id, tx, prevouts, paths};
        auto encoded = EncodeSignRequest(sign); auto parsed = DecodeSignRequest(encoded);
        Check(parsed.wallet_id == sign.wallet_id && parsed.paths.size() == 2);
        Check(SerializeUnsigned(parsed.transaction, parsed.prevouts) == SerializeUnsigned(tx, prevouts));
        auto witnesses = wallet.SignTransaction(tx, prevouts, paths, 1000);
        PreparedTransaction prepared{tx, prevouts};
        Check(witnesses.size() == 2);
        Check(VerifyWitness(Network::REGTEST, prepared, 0, a.program, witnesses[0]));
        Check(VerifyWitness(Network::REGTEST, prepared, 1, b.program, witnesses[1]));
        auto wrong_amount = prevouts; wrong_amount[0].amount++;
        Check(!VerifyWitness(Network::REGTEST, PreparedTransaction{tx, wrong_amount}, 1, b.program, witnesses[1]));
        auto wrong_paths = paths; wrong_paths[1].index=1;
        Reject(Code::VALIDATION, [&] { wallet.SignTransaction(tx, prevouts, wrong_paths, 1000); });
        auto wrong_scripts = prevouts; wrong_scripts[1].script[3]^=1;
        Reject(Code::VALIDATION, [&] { wallet.SignTransaction(tx, wrong_scripts, paths, 1000); });
        Reject(Code::VALIDATION, [&] { wallet.SignTransaction(tx, prevouts, paths, 999); });
        auto bad_output=tx; bad_output.outputs[0].script={0x51};
        Reject(Code::VALIDATION, [&] { wallet.SignTransaction(bad_output, prevouts, paths, 1000); });
        for (Bytes script : {Bytes{0x6a}, Bytes{0x6a,0x4c,1,0x42}, Bytes{0x6a,1,0x42,0}, Bytes{0x6a,81}}) {
            auto invalid=tx; invalid.outputs[1].script=script;
            Reject(Code::VALIDATION, [&] { wallet.SignTransaction(invalid, prevouts, paths, 1000); });
        }
        auto extra=encoded; extra.push_back(0);
        Reject(Code::VALIDATION, [&] { DecodeSignRequest(extra); });
        for (size_t i=0; i<encoded.size(); ++i)
            Reject(Code::VALIDATION, [&] { DecodeSignRequest(std::span(encoded).first(i)); });
        Hash spec{}; Session session{wallet, Network::REGTEST, spec, 1000};
        Check(session.Handle(Request(5,1)).status == static_cast<uint16_t>(Code::AUTH));
        auto hello=NetworkBinding(Network::REGTEST); hello.insert(hello.end(), spec.begin(), spec.end());
        Check(session.Handle(Request(1,2,hello)).status == 0);
        Check(session.Handle(Request(1,2,hello)).status == static_cast<uint16_t>(Code::REPLAY));
        Check(session.Handle(Request(3,3,encoded)).status == 0);
        auto wrong_id=sign; wrong_id.wallet_id[0]^=1;
        Check(session.Handle(Request(3,4,EncodeSignRequest(wrong_id))).status == static_cast<uint16_t>(Code::AUTH));
        Check(session.Handle(Request(4,5)).status == 0 && wallet.Status().locked);
        Check(session.Handle(Request(3,6,encoded)).status == static_cast<uint16_t>(Code::LOCKED));
        Check(session.Handle(Request(2,7,{0})).status == static_cast<uint16_t>(Code::LOCKED));
        Session bounded{wallet, Network::REGTEST, spec, 1000};
        Check(bounded.Handle(Request(1,1,hello)).status == 0);
        for (unsigned id=2; id<=64; ++id) Check(bounded.Handle(Request(5,id)).status == 0);
        Check(bounded.Done()); Check(bounded.Handle(Request(5,65)).status == static_cast<uint16_t>(Code::LIMIT));
        std::cout << "{\"result\":\"PASS\",\"checks\":" << checks << ",\"signatures_verified\":2,\"sign_request_hex\":\"" << Hex(encoded) << "\"}\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
