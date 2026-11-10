// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <coins.h>
#include <crypto/mldsa44/node.h>
#include <crypto/mldsa44/public_profile.h>
#include <kernel/chainparams.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <univalue.h>
#include <boost/test/unit_test.hpp>
#include <functional>
#include <initializer_list>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace mldsa_node = pqbtc::mldsa44::node;
namespace {
struct Inventory final : CCoinsView {
    std::map<COutPoint,Coin> records;
    std::optional<Coin> GetCoin(const COutPoint& out) const override
    {
        const auto it=records.find(out);
        return it==records.end()?std::nullopt:std::optional<Coin>{it->second};
    }
    bool ForEachUnspentCoin(const std::function<bool(const COutPoint&,const Coin&)>& visitor) const override
    {
        for (const auto& [out,coin] : records) if (!coin.IsSpent() && !visitor(out,coin)) return false;
        return true;
    }
};
CScript NativeScript() { return CScript{} << OP_2 << std::vector<unsigned char>(32,0x42); }
CScript Raw(std::initializer_list<unsigned char> bytes) { return CScript{bytes.begin(),bytes.end()}; }
CMutableTransaction Spend()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE),0});
    tx.vout.emplace_back(100000,NativeScript());
    return tx;
}
struct MutatedPublicParams : CChainParams {
    MutatedPublicParams() : CChainParams(*MLDSA44Test()) {}
    void ChangeMagic() { pchMessageStart[0]^=1; }
    void ChangeHeader() { ++genesis.nNonce;consensus.hashGenesisBlock=genesis.GetHash(); }
};
} // namespace

BOOST_AUTO_TEST_SUITE(mldsa44_public_tests)

// A public flag that silently selects inherited testnet would expose a different
// network and custody namespace. These expectations come from GENESIS-v1.
BOOST_AUTO_TEST_CASE(explicit_test_selects_the_frozen_identity)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);
    args.ForceSetArg("-chain","test");args.ForceSetArg("-mldsa44test","1");
    const auto params=CreateChainParams(args,ChainType::TESTNET);
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),
        "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979");
    BOOST_CHECK_EQUAL(params->Bech32HRP(),"tq");
    BOOST_CHECK_EQUAL(params->GetDefaultPort(),23833);
    BOOST_CHECK(params->DNSSeeds().empty());
    BOOST_CHECK(params->FixedSeeds().empty());
    BOOST_CHECK(params->GetConsensus().nMinimumChainWork.IsNull());
    BOOST_CHECK(params->GetConsensus().defaultAssumeValid.IsNull());
    BOOST_CHECK(params->MineBlocksOnDemand());
    BOOST_CHECK(params->IsMLDSA44Test());
    BOOST_CHECK(params->IsMLDSA44Enabled());
    BOOST_CHECK(!params->IsMLDSA44Demo());
    BOOST_CHECK_EQUAL(params->GetConsensus().nPowTargetSpacing,60);
    BOOST_CHECK_EQUAL(params->GetConsensus().nSubsidyHalvingInterval,210000);
    BOOST_CHECK(params->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK_EQUAL(params->GenesisBlock().hashMerkleRoot.ToString(),
        "d3bf22ef43098736f11406c5bff808e933df335705f4c8c022dcffaa0d26164a");
    BOOST_CHECK_EQUAL(params->GenesisBlock().vtx.size(),1U);
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::PUBKEY_ADDRESS).at(0),191);
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::SCRIPT_ADDRESS).at(0),187);
    BOOST_CHECK_EQUAL(params->Base58Prefix(CChainParams::SECRET_KEY).at(0),64);
    BOOST_CHECK_EQUAL(params->GetConsensus().BIP34Height,1);
    BOOST_CHECK_EQUAL(params->GetConsensus().BIP65Height,1);
    BOOST_CHECK_EQUAL(params->GetConsensus().BIP66Height,1);
    BOOST_CHECK_EQUAL(params->GetConsensus().CSVHeight,1);
    BOOST_CHECK_EQUAL(params->GetConsensus().SegwitHeight,0);
    BOOST_CHECK(mldsa_node::ResolveNetwork(*params)==pqbtc::mldsa44::Network::TEST);
    const auto base=CreateBaseChainParams(ChainType::TESTNET,false,true);
    BOOST_CHECK_EQUAL(base->DataDir(),"mldsa44-test-v1");
    BOOST_CHECK_EQUAL(base->RPCPort(),23832);
    BOOST_CHECK_THROW(CreateBaseChainParams(ChainType::REGTEST,false,true),std::invalid_argument);
    BOOST_CHECK_THROW(CreateBaseChainParams(ChainType::TESTNET,true,true),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_selection_cannot_come_from_config)
{
    struct ConfigArgs : ArgsManager {using ArgsManager::ReadConfigStream;};
    for (const auto config : {"mldsa44test=1\n", "[test]\nmldsa44test=1\n", "[main]\nmldsa44test=0\n"}) {
        ConfigArgs args;SetupChainParamsBaseOptions(args);
        std::istringstream input{config};std::string error;
        BOOST_REQUIRE(args.ReadConfigStream(input,"public-test.conf",error));
        BOOST_CHECK_THROW(CreateChainParams(args,ChainType::TESTNET),std::invalid_argument);
        args.SelectConfigNetwork("test");
        BOOST_CHECK_THROW(CreateChainParams(args,ChainType::TESTNET),std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(public_flag_refuses_wrong_or_implicit_network)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);args.ForceSetArg("-mldsa44test","1");
    for (const auto chain : {ChainType::MAIN,ChainType::TESTNET,ChainType::TESTNET4,ChainType::SIGNET,ChainType::REGTEST}) {
        BOOST_CHECK_THROW(CreateChainParams(args,chain),std::invalid_argument);
    }
    args.ForceSetArg("-chain","test");args.ForceSetArg("-mldsa44demo","1");
    BOOST_CHECK_THROW(CreateChainParams(args,ChainType::TESTNET),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(public_flag_refuses_network_aliases_and_deployment_overrides)
{
    for (const auto flag : {"-regtest","-testnet","-testnet4","-signet","-vbparams","-testactivationheight","-signetchallenge","-signetseednode"}) {
        ArgsManager args;SetupChainParamsBaseOptions(args);
        args.ForceSetArg("-chain","test");args.ForceSetArg("-mldsa44test","1");args.ForceSetArg(flag,"1");
        BOOST_CHECK_THROW(CreateChainParams(args,ChainType::TESTNET),std::invalid_argument);
    }
    struct ConfigArgs : ArgsManager {using ArgsManager::ReadConfigStream;};
    ConfigArgs config;SetupChainParamsBaseOptions(config);
    std::istringstream input{"chain=test\n"};std::string error;
    BOOST_REQUIRE(config.ReadConfigStream(input,"public-test.conf",error));
    config.ForceSetArg("-mldsa44test","1");
    BOOST_CHECK_THROW(CreateChainParams(config,ChainType::TESTNET),std::invalid_argument);
    ArgsManager settings;SetupChainParamsBaseOptions(settings);
    settings.LockSettings([](auto& values){values.rw_settings["mldsa44test"]=true;});
    BOOST_CHECK_THROW(CreateChainParams(settings,ChainType::TESTNET),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(unselected_networks_keep_their_inherited_identity)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);
    for (const auto& [chain,hash] : std::vector<std::pair<ChainType,std::string>>{
        {ChainType::MAIN,"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
        {ChainType::TESTNET4,"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"},
        {ChainType::SIGNET,"00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"}}) {
        const auto inherited=CreateChainParams(args,chain);
        BOOST_CHECK_EQUAL(inherited->GenesisBlock().GetHash().ToString(),hash);
        BOOST_CHECK(!inherited->IsMLDSA44Enabled());
    }
    BOOST_CHECK_EQUAL(CreateChainParams(args,ChainType::TESTNET)->GenesisBlock().GetHash().ToString(),
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");
    BOOST_CHECK_EQUAL(CreateChainParams(args,ChainType::REGTEST)->GenesisBlock().GetHash().ToString(),
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
    BOOST_CHECK_EQUAL(CreateBaseChainParams(ChainType::TESTNET)->DataDir(),"testnet3");
    args.ForceSetArg("-mldsa44demo","1");
    BOOST_CHECK_EQUAL(CreateChainParams(args,ChainType::REGTEST)->GenesisBlock().GetHash().ToString(),
        "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2");
}

BOOST_AUTO_TEST_CASE(public_activation_and_startup_require_exact_identity_and_empty_inventory)
{
    const auto params=CChainParams::MLDSA44Test();const auto genesis=params->GenesisBlock().GetHash();
    Inventory disk;CCoinsViewCache parent{&disk,true},view{&parent,true};
    BOOST_CHECK_NO_THROW(mldsa_node::CheckStartup(*params,view));
    view.SetBestBlock(genesis);
    BOOST_CHECK_NO_THROW(mldsa_node::CheckActivation(*params,genesis,view));
    BOOST_CHECK_THROW(mldsa_node::CheckDemoStartup(*params,view),std::invalid_argument);
    BOOST_CHECK_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view),std::invalid_argument);
    const COutPoint out{Txid::FromUint256(uint256::ONE),0};
    disk.records.emplace(out,Coin{CTxOut{1000,NativeScript()},0,false});
    BOOST_CHECK_THROW(mldsa_node::CheckActivation(*params,genesis,view),std::invalid_argument);
    BOOST_CHECK_THROW(mldsa_node::CheckStartup(*params,view),std::invalid_argument);
    BOOST_REQUIRE(parent.SpendCoin(out));
    BOOST_CHECK_NO_THROW(mldsa_node::CheckActivation(*params,genesis,view));
    const COutPoint local{Txid::FromUint256(uint256::ONE),1};
    view.AddCoin(local,Coin{CTxOut{1000,CScript{}<<OP_TRUE},0,false},false);
    BOOST_CHECK_THROW(mldsa_node::CheckActivation(*params,genesis,view),std::invalid_argument);
    BOOST_REQUIRE(view.SpendCoin(local));
    BOOST_CHECK_THROW(mldsa_node::CheckActivation(*params,uint256::ONE,view),std::invalid_argument);
    view.SetBestBlock(uint256::ONE);
    BOOST_CHECK_THROW(mldsa_node::CheckActivation(*params,genesis,view),std::invalid_argument);
    MutatedPublicParams wrong_magic;wrong_magic.ChangeMagic();
    BOOST_CHECK_THROW(mldsa_node::CheckStartup(wrong_magic,view),std::invalid_argument);
    MutatedPublicParams wrong_genesis;wrong_genesis.ChangeHeader();
    BOOST_CHECK_THROW(mldsa_node::CheckStartup(wrong_genesis,view),std::invalid_argument);
    const auto inherited=CChainParams::TestNet();
    BOOST_CHECK_THROW(mldsa_node::CheckStartup(*inherited,view),std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(public_outputs_accept_only_native_and_sealed_direct_push_data)
{
    auto tx=Spend();
    BOOST_CHECK(mldsa_node::CheckPublicOutputs(CTransaction{tx}));
    for (const auto size : {0,1,75,76,80}) {
        tx.vout[0]=CTxOut{0,CScript{}<<OP_RETURN<<std::vector<unsigned char>(size,1)};
        BOOST_CHECK(mldsa_node::CheckPublicOutputs(CTransaction{tx}));
    }
    for (const auto& script : std::vector<CScript>{
        CScript{}<<OP_TRUE, CScript{}<<OP_0<<std::vector<unsigned char>(32,1),
        CScript{}<<OP_1<<std::vector<unsigned char>(32,1), CScript{}<<OP_3<<std::vector<unsigned char>(32,1),
        CScript{}<<OP_HASH160<<std::vector<unsigned char>(20,1)<<OP_EQUAL,
        CScript{}<<OP_2<<std::vector<unsigned char>(31,1), CScript{}<<OP_RETURN,
        CScript{}<<OP_RETURN<<OP_1, CScript{}<<OP_RETURN<<OP_1NEGATE,
        CScript{}<<OP_RETURN<<std::vector<unsigned char>(81,1), CScript{}<<OP_RETURN<<OP_0<<OP_0,
        Raw({OP_RETURN,OP_PUSHDATA1,1,0x42}), Raw({OP_RETURN,OP_PUSHDATA1,80}),
        Raw({OP_RETURN,OP_PUSHDATA2,0,0})}) {
        tx.vout[0]=CTxOut{0,script};
        BOOST_CHECK(!mldsa_node::CheckPublicOutputs(CTransaction{tx}));
    }
    tx.vout[0]=CTxOut{1,CScript{}<<OP_RETURN<<OP_0};
    BOOST_CHECK(!mldsa_node::CheckPublicOutputs(CTransaction{tx}));
    tx.vout[0]=CTxOut{-1,NativeScript()};
    BOOST_CHECK(!mldsa_node::CheckPublicOutputs(CTransaction{tx}));
    // The frozen legacy genesis is handled only by ConnectBlock's genesis case.
    BOOST_CHECK(!mldsa_node::CheckPublicOutputs(*CChainParams::MLDSA44Test()->GenesisBlock().vtx[0]));
}

BOOST_AUTO_TEST_CASE(public_inputs_require_live_native_prevouts_and_empty_scriptsig)
{
    auto tx=Spend();Inventory disk;CCoinsViewCache view{&disk,true};
    BOOST_CHECK(!mldsa_node::CheckPublicInputs(CTransaction{tx},view));
    const auto out=tx.vin[0].prevout;
    for (const auto& script : std::vector<CScript>{NativeScript(),CScript{}<<OP_TRUE,
        CScript{}<<OP_0<<std::vector<unsigned char>(32,1),CScript{}<<OP_1<<std::vector<unsigned char>(32,1),
        CScript{}<<OP_3<<std::vector<unsigned char>(32,1),
        CScript{}<<OP_HASH160<<std::vector<unsigned char>(20,1)<<OP_EQUAL}) {
        view.AddCoin(out,Coin{CTxOut{100000,script},1,false},false);
        BOOST_CHECK_EQUAL(mldsa_node::CheckPublicInputs(CTransaction{tx},view),script==NativeScript());
        tx.vin[0].scriptSig=CScript{}<<OP_0;
        BOOST_CHECK(!mldsa_node::CheckPublicInputs(CTransaction{tx},view));
        tx.vin[0].scriptSig.clear();BOOST_REQUIRE(view.SpendCoin(out));
    }
    tx.vin[0].prevout.SetNull();
    BOOST_CHECK(mldsa_node::CheckPublicInputs(CTransaction{tx},view));
}

BOOST_AUTO_TEST_CASE(public_standardness_preserves_size_version_dust_and_data_limits)
{
    auto tx=Spend();std::string reason;
    auto standard=[&](bool profile,unsigned data=83) {
        return IsStandardTx(CTransaction{tx},data,true,CFeeRate{3000},reason,profile);
    };
    BOOST_CHECK(standard(true));
    tx.vout[0].scriptPubKey=CScript{}<<OP_3<<std::vector<unsigned char>(32,1);
    BOOST_CHECK(standard(false));BOOST_CHECK(!standard(true));
    tx.vout[0]=CTxOut{0,CScript{}<<OP_RETURN<<std::vector<unsigned char>(80,1)};
    BOOST_CHECK(standard(true));BOOST_CHECK(!standard(true,0));
    tx=Spend();tx.version=100;BOOST_CHECK(!standard(true));
    tx=Spend();tx.vin[0].scriptWitness.stack.emplace_back(MAX_STANDARD_TX_WEIGHT+1,0);
    BOOST_CHECK(!standard(true));
    tx=Spend();tx.vin[0].scriptSig=CScript{}<<OP_ADD;BOOST_CHECK(!standard(true));
    tx=Spend();tx.vout.assign(2,CTxOut{0,NativeScript()});BOOST_CHECK(!standard(true));
}

BOOST_AUTO_TEST_SUITE_END()
