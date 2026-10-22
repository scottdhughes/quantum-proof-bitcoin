// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <crypto/mldsa44/node.h>
#include <coins.h>
#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <algorithm>
#include <bit>
#include <stdexcept>

namespace pqbtc::mldsa44::node {
namespace {
void Require(bool ok) { if(!ok)throw std::invalid_argument("invalid ML-DSA node snapshot"); }
PreparedTransaction Prepare(const CTransactionRef& tx,const CCoinsViewCache& coins,std::vector<Bytes>& programs)
{
    Require(bool(tx));pqbtc::mldsa44::Transaction model{std::bit_cast<int32_t>(tx->version),{}, {},tx->nLockTime};
    std::vector<Output> prevouts;model.inputs.reserve(tx->vin.size());prevouts.reserve(tx->vin.size());
    programs.reserve(tx->vin.size());model.outputs.reserve(tx->vout.size());
    for(const auto& input:tx->vin) {
        const auto& coin=coins.AccessCoin(input.prevout);
        Require(!coin.IsSpent() && MoneyRange(coin.out.nValue));
        Input out{};const auto& hash=input.prevout.hash.ToUint256();std::copy(hash.begin(),hash.end(),out.hash.begin());
        out.index=input.prevout.n;out.sequence=input.nSequence;model.inputs.push_back(out);
        const auto& script=coin.out.scriptPubKey;
        prevouts.push_back({static_cast<uint64_t>(coin.out.nValue),Bytes(script.begin(),script.end())});
        programs.push_back(script.size()==34 && script[0]==0x52 && script[1]==0x20 ? Bytes(script.begin()+2,script.end()):Bytes{});
    }
    for(const auto& output:tx->vout) {
        Require(MoneyRange(output.nValue));
        model.outputs.push_back({static_cast<uint64_t>(output.nValue),Bytes(output.scriptPubKey.begin(),output.scriptPubKey.end())});
    }
    // Never route node validation through SerializeUnsigned's signer-only policy.
    return PreparedTransaction{model,prevouts};
}
} // namespace
Network ResolveNetwork(const CChainParams& params)
{
    const auto actual_genesis=params.GenesisBlock().GetHash();
    Require(params.GetConsensus().hashGenesisBlock==actual_genesis);
    const auto& magic=params.MessageStart();Bytes binding(magic.begin(),magic.end());
    binding.insert(binding.end(),actual_genesis.begin(),actual_genesis.end());
    for(auto network:{Network::MAIN,Network::TEST,Network::REGTEST})
        if(NetworkBinding(network)==binding)return network;
    throw std::invalid_argument("effective node network is not CONTRACT-1");
}
Snapshot::Snapshot(CTransactionRef tx,const CCoinsViewCache& coins):m_transaction(std::move(tx)),m_programs{},
    m_prepared(Prepare(m_transaction,coins,m_programs)) {}
Hash Snapshot::Message(Network network,size_t index) const { return SigningMessage(network,m_prepared,index); }
bool Snapshot::VerifyInput(const CChainParams& params,size_t index) const
{
    if(index>=m_programs.size() || m_programs[index].size()!=32 || !m_transaction->vin[index].scriptSig.empty())return false;
    try { return VerifyWitness(ResolveNetwork(params),m_prepared,index,m_programs[index],m_transaction->vin[index].scriptWitness.stack); }
    catch(const std::invalid_argument&) { return false; }
}
} // namespace pqbtc::mldsa44::node
