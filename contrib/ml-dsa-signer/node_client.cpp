// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// PUBLIC valueless-demo bridge. Never link the private wallet or libcrypto.
#include <crypto/mldsa44/signer/client.h>
#include <algorithm>
#include <charconv>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <unistd.h>

using namespace pqbtc::mldsa44;
using namespace pqbtc::mldsa44::signer;
namespace {
uint64_t Number(std::string_view text)
{
    uint64_t result{};const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    Require(!text.empty() && parsed.ec==std::errc{} && parsed.ptr==text.data()+text.size());return result;
}
Bytes Unhex(const std::string& text)
{
    Require(text.size()<=2097152 && text.size()%2==0);Bytes result;result.reserve(text.size()/2);
    auto digit=[](char c)->unsigned char {
        Require((c>='0'&&c<='9')||(c>='a'&&c<='f'));return c<='9'?c-'0':c-'a'+10;
    };
    for(size_t i=0;i<text.size();i+=2)result.push_back((digit(text[i])<<4)|digit(text[i+1]));
    return result;
}
std::string Hex(std::span<const unsigned char> bytes)
{
    constexpr char digits[]{"0123456789abcdef"};std::string result;result.reserve(bytes.size()*2);
    for(auto c:bytes){result.push_back(digits[c>>4]);result.push_back(digits[c&15]);}return result;
}
}
int main(int argc,char** argv)
{
    try {
        Require(argc==6 && std::string_view(argv[1])=="--valueless-demo");
        const auto uid=Number(argv[3]),kind=Number(argv[5]);
        Require(uid>0 && uid<std::numeric_limits<uid_t>::max() && geteuid()!=0,Code::AUTH);
        Require(kind>=2 && kind<=5);
        const auto digest=Unhex(argv[4]);Require(digest.size()==32);Hash spec{};std::copy(digest.begin(),digest.end(),spec.begin());
        std::string input;char c;
        while(std::cin.get(c)){Require(input.size()<2097153);input.push_back(c);}
        Require(std::cin.eof());if(!input.empty() && input.back()=='\n')input.pop_back();
        const auto body=Unhex(input);
        Client client{argv[2],static_cast<uid_t>(uid),Network::REGTEST,spec};
        const auto response=client.Call(static_cast<uint8_t>(kind),body);
        std::cout<<"{\"status\":"<<response.status<<",\"payload\":\""<<Hex(response.payload)<<"\"}\n";
        return 0;
    } catch(const Error& error) {
        std::cerr<<"MLDSA_CLIENT_ERROR "<<static_cast<unsigned>(error.code)<<'\n';return 1;
    } catch(const std::exception&) {
        std::cerr<<"MLDSA_CLIENT_ERROR 9\n";return 1;
    }
}
