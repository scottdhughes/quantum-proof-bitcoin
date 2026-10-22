// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Public signatures only: no signer/key-owner/OpenSSL dependency in this target.
#include <crypto/mldsa44/node.h>
#include <coins.h>
#include <core_io.h>
#include <kernel/chainparams.h>
#include <test/data/mldsa44_node.json.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <boost/test/unit_test.hpp>

using namespace pqbtc::mldsa44;
namespace {
// Explicit byte-model chain fixture, NOT registered/admitted network parameters.
struct FrozenRegtest : CChainParams {
    FrozenRegtest()
    {
        pchMessageStart={0x96,0xbd,0x87,0x9e};
        genesis.nVersion=1;genesis.nTime=1772086429;genesis.nBits=545259519;genesis.nNonce=17489643;
        genesis.hashMerkleRoot=uint256::FromHex("eff22c74638125519d38bab3d58d460f93ff0d5ef57dfbabc9514353bdb458cb").value();
        consensus.hashGenesisBlock=genesis.GetHash();
    }
    void ChangeHeader() { ++genesis.nNonce; }
    void ChangeCachedGenesis() { consensus.hashGenesisBlock=uint256::ONE; }
};
struct Fixture {
    UniValue data;CMutableTransaction tx;CCoinsView base;CCoinsViewCache coins{&base,true};FrozenRegtest params;
    Fixture()
    {
        BOOST_REQUIRE(data.read(json_tests::mldsa44_node));
        BOOST_REQUIRE(DecodeHexTx(tx,data["unsigned"].get_str(),true,false));
        auto script=ParseHex(data["script"].get_str());
        for (size_t i=0;i<tx.vin.size();++i) {
            coins.AddCoin(tx.vin[i].prevout,Coin{CTxOut{data["amounts"][i].getInt<int64_t>(),CScript(script.begin(),script.end())},1,false},false);
            tx.vin[i].scriptWitness.stack={ParseHex(data["signatures"][i].get_str()),ParseHex(data["public_key"].get_str())};
        }
    }
    void Replace(size_t input,CAmount amount,CScript script)
    {
        BOOST_REQUIRE(coins.SpendCoin(tx.vin[input].prevout));
        coins.AddCoin(tx.vin[input].prevout,Coin{CTxOut{amount,std::move(script)},1,false},false);
    }
};
bool Verify(const CMutableTransaction& tx,const CCoinsViewCache& coins,const CChainParams& params,size_t index=0)
{
    try {return node::Snapshot{MakeTransactionRef(tx),coins}.VerifyInput(params,index);}
    catch(const std::invalid_argument&) {return false;}
}
} // namespace

BOOST_AUTO_TEST_SUITE(mldsa44_node_tests)
BOOST_AUTO_TEST_CASE(actual_coins_and_transaction_verify_public_fixture)
{
    Fixture f;node::Snapshot snapshot{MakeTransactionRef(f.tx),f.coins};
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,0)),f.data["messages"][0].get_str());
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,1)),f.data["messages"][1].get_str());
    BOOST_CHECK(snapshot.VerifyInput(f.params,0));BOOST_CHECK(snapshot.VerifyInput(f.params,1));
    BOOST_CHECK(!snapshot.VerifyInput(f.params,2));
    BOOST_CHECK(snapshot.Transaction().GetHash()==MakeTransactionRef(f.tx)->GetHash());
    BOOST_CHECK_THROW((node::Snapshot{CTransactionRef{},f.coins}),std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(effective_network_not_just_cached_or_model_network)
{
    Fixture f;BOOST_CHECK(node::ResolveNetwork(f.params)==Network::REGTEST);
    auto inherited=CChainParams::RegTest({});
    BOOST_CHECK_THROW(node::ResolveNetwork(*inherited),std::invalid_argument);
    BOOST_CHECK(!Verify(f.tx,f.coins,*inherited));
    auto wrong=f.params;wrong.ChangeHeader();BOOST_CHECK_THROW(node::ResolveNetwork(wrong),std::invalid_argument);
    wrong=f.params;wrong.ChangeCachedGenesis();BOOST_CHECK_THROW(node::ResolveNetwork(wrong),std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(transaction_version_sign_bit_is_wire_preserved)
{
    Fixture f;f.tx.version=0x80000000U;node::Snapshot snapshot{MakeTransactionRef(f.tx),f.coins};
    // Literal independently encoded protocol_v1 expectations, not adapter output.
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,0)),"24eea89dea4146e79b97c517fab06598b69c47a3c643894973a3308303327853");
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,1)),"f0b9f521194f99cc7068cffe999af1eec097738f1969b6cdf48a2f944ca0b02a");
    BOOST_CHECK(!snapshot.VerifyInput(f.params,0));
}
BOOST_AUTO_TEST_CASE(missing_spent_negative_and_changed_metadata_reject)
{
    for (int mutation=0;mutation<8;++mutation) {
        Fixture f;auto script=f.coins.AccessCoin(f.tx.vin[1].prevout).out.scriptPubKey;
        switch(mutation) {
        case 0: BOOST_REQUIRE(f.coins.SpendCoin(f.tx.vin[1].prevout));break;
        case 1: f.Replace(1,-2,script);break;
        case 2: f.Replace(1,51001,script);break;
        case 3: script[3]^=1;f.Replace(1,51000,script);break;
        case 4: ++f.tx.vin[0].prevout.n;break;
        case 5: --f.tx.vout[0].nValue;break;
        case 6: f.tx.vin[0].scriptSig<<OP_0;break;
        case 7: f.tx.vin[0].scriptWitness.stack.push_back({});break;
        }
        BOOST_CHECK_MESSAGE(!Verify(f.tx,f.coins,f.params),"mutation "<<mutation);
    }
}
BOOST_AUTO_TEST_CASE(snapshot_is_owned_and_signer_policy_is_not_consensus)
{
    Fixture f;node::Snapshot old{MakeTransactionRef(f.tx),f.coins};auto message=old.Message(Network::REGTEST,0);
    f.Replace(1,51001,f.coins.AccessCoin(f.tx.vin[1].prevout).out.scriptPubKey);
    BOOST_CHECK(old.Message(Network::REGTEST,0)==message);BOOST_CHECK(old.VerifyInput(f.params,0));
    BOOST_CHECK(!Verify(f.tx,f.coins,f.params));
    f.tx.vout.resize(101,CTxOut{0,CScript{}});f.tx.vout[1].scriptPubKey.resize(10001);
    BOOST_CHECK_NO_THROW((node::Snapshot{MakeTransactionRef(f.tx),f.coins}));
}
BOOST_AUTO_TEST_SUITE_END()
