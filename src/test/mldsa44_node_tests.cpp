// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
// Public signatures only: no signer/key-owner/OpenSSL dependency in this target.
#include <crypto/mldsa44/node.h>
#include <addresstype.h>
#include <coins.h>
#include <dbwrapper.h>
#include <txdb.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <core_io.h>
#include <kernel/chainparams.h>
#include <script/interpreter.h>
#include <test/data/mldsa44_node.json.h>
#include <test/data/mldsa44_script.json.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <validation.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <memory>
#include <sstream>
#include <type_traits>

static_assert(!std::is_copy_assignable_v<pqbtc::mldsa44::node::Snapshot> &&
    !std::is_move_assignable_v<pqbtc::mldsa44::node::Snapshot> &&
    !std::is_move_constructible_v<pqbtc::mldsa44::node::Snapshot>,
    "a cached snapshot cannot be rebound or left with a moved-from transaction");

using namespace pqbtc::mldsa44;
namespace mldsa_node = pqbtc::mldsa44::node;
namespace {
class InventoryView final : public CCoinsView {
public:
    std::map<COutPoint,Coin> records;
    struct CursorImpl final : CCoinsViewCursor {
        decltype(records)::const_iterator current,end;
        explicit CursorImpl(const decltype(records)& source):CCoinsViewCursor(uint256{}),current(source.begin()),end(source.end()) {}
        bool GetKey(COutPoint& out) const override {if(!Valid())return false;out=current->first;return true;}
        bool GetValue(Coin& out) const override {if(!Valid())return false;out=current->second;return true;}
        bool Valid() const override {return current!=end;}
        void Next() override {++current;}
    };
    std::optional<Coin> GetCoin(const COutPoint& out) const override
    {
        auto it=records.find(out);return it==records.end()?std::nullopt:std::optional<Coin>{it->second};
    }
    std::unique_ptr<CCoinsViewCursor> Cursor() const override {return std::make_unique<CursorImpl>(records);}
};
// Explicit byte-model chain fixture, NOT registered/admitted network parameters.
struct FrozenParams : CChainParams {
    static std::unique_ptr<const CChainParams> Inherited(Network network)
    {
        switch(network) {
        case Network::MAIN:return CChainParams::Main();
        case Network::TEST:return CChainParams::TestNet();
        case Network::REGTEST:return CChainParams::RegTest({});
        }
        throw std::invalid_argument("unknown fixture network");
    }
    explicit FrozenParams(Network network=Network::REGTEST):CChainParams(*Inherited(network))
    {
        genesis=CBlock{};genesis.nVersion=1;genesis.nBits=545259519;
        const char* merkle;
        switch(network) {
        case Network::MAIN:
            pchMessageStart={0x85,0x92,0xa7,0xad};genesis.nTime=1772116563;genesis.nNonce=4185130280;
            merkle="f586d6aae001c2f2fc69588582695650a8247bf628a2c21c40c334d527398838";break;
        case Network::TEST:
            pchMessageStart={0xa7,0xe2,0x9c,0xf7};genesis.nTime=1772119544;genesis.nNonce=2499947721;
            merkle="d3bf22ef43098736f11406c5bff808e933df335705f4c8c022dcffaa0d26164a";break;
        case Network::REGTEST:
            pchMessageStart={0x96,0xbd,0x87,0x9e};genesis.nTime=1772086429;genesis.nNonce=17489643;
            merkle="eff22c74638125519d38bab3d58d460f93ff0d5ef57dfbabc9514353bdb458cb";break;
        default:throw std::invalid_argument("unknown fixture network");
        }
        genesis.hashMerkleRoot=uint256::FromHex(merkle).value();
        consensus.hashGenesisBlock=genesis.GetHash();
    }
    void ChangeHeader() { ++genesis.nNonce; }
    void ChangeCachedGenesis() { consensus.hashGenesisBlock=uint256::ONE; }
    void Magic(MessageStartChars value) { pchMessageStart=value; }
    void Header(const CBlock& value) { genesis=value;consensus.hashGenesisBlock=genesis.GetHash(); }
};
struct Fixture {
    UniValue data;CMutableTransaction tx;CCoinsView base;CCoinsViewCache coins{&base,true};FrozenParams params;
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
    try {return mldsa_node::Snapshot{MakeTransactionRef(tx),coins}.VerifyInput(params,index);}
    catch(const std::invalid_argument&) {return false;}
}
class PermissiveShapeProbe final : public BaseSignatureChecker {
public:
    mutable size_t calls{0};
    bool CheckMLDSA44Witness(std::span<const unsigned char>,std::span<const Bytes>) const override
    {
        ++calls;return true;
    }
};
struct ScriptFixture {
    UniValue data;CMutableTransaction tx;CCoinsView base;CCoinsViewCache coins{&base,true};FrozenParams params;
    explicit ScriptFixture(size_t profile)
    {
        UniValue all;BOOST_REQUIRE(all.read(json_tests::mldsa44_script));data=all[profile];
        BOOST_REQUIRE(DecodeHexTx(tx,data["unsigned"].get_str(),true,false));
        for(size_t i=0;i<tx.vin.size();++i) {
            auto script=ParseHex(data["scripts"][i].get_str());
            coins.AddCoin(tx.vin[i].prevout,Coin{CTxOut{data["amounts"][i].getInt<int64_t>(),CScript(script.begin(),script.end())},1,false},false);
            for(const auto& item:data["witnesses"][i].getValues())tx.vin[i].scriptWitness.stack.push_back(ParseHex(item.get_str()));
        }
    }
};
class LegacyProbe final : public BaseSignatureChecker {
public:
    bool CheckLockTime(const CScriptNum&) const override {return true;}
    bool CheckSequence(const CScriptNum&) const override {return true;}
    bool CheckECDSASignature(const Bytes&,const Bytes&,const CScript&,SigVersion) const override {return true;}
    bool CheckSchnorrSignature(std::span<const unsigned char>,std::span<const unsigned char>,
        SigVersion,ScriptExecutionData&,ScriptError*) const override {return true;}
};
} // namespace

BOOST_AUTO_TEST_SUITE(mldsa44_node_tests)
BOOST_AUTO_TEST_CASE(demo_configuration_cannot_select_a_different_namespace)
{
    struct ConfigArgs : ArgsManager { using ArgsManager::ReadConfigStream; };
    for(const auto& config:{"mldsa44demo=1\n", "[regtest]\nmldsa44demo=1\n", "mldsa44demo=1\n[regtest]\nmldsa44demo=0\n", "[main]\nmldsa44demo=0\n"}) {
        ConfigArgs args;SetupChainParamsBaseOptions(args);std::istringstream input(config);std::string error;
        BOOST_REQUIRE(args.ReadConfigStream(input,"public-test.conf",error));
        BOOST_CHECK_THROW(IsMLDSA44Demo(args,ChainType::REGTEST),std::invalid_argument);
        args.SelectConfigNetwork("regtest");
        BOOST_CHECK_THROW(IsMLDSA44Demo(args,ChainType::REGTEST),std::invalid_argument);
    }
}
BOOST_FIXTURE_TEST_CASE(demo_inventory_refuses_malformed_db_keys_and_unsupported_overlays,BasicTestingSetup)
{
    const auto path=m_args.GetDataDirBase()/"demo-malformed-coins";
    {
        CDBWrapper db{{.path=path,.cache_bytes=1<<20,.wipe_data=true}};
        // A real malformed key in the Coin namespace, not a simulated EOF.
        BOOST_REQUIRE(db.Write(uint8_t{'C'},Coin{CTxOut{1000,CScript{}<<OP_TRUE},0,false}));
    }
    CCoinsViewDB disk{{.path=path,.cache_bytes=1<<20},{}};
    BOOST_CHECK_THROW(disk.ForEachUnspentCoin([](const auto&,const auto&){return true;}),std::runtime_error);
    InventoryView empty;CCoinsViewBacked unsupported{&empty};
    BOOST_CHECK_THROW(unsupported.ForEachUnspentCoin([](const auto&,const auto&){return true;}),std::runtime_error);
    CCoinsView bare;
    BOOST_CHECK_THROW(bare.ForEachUnspentCoin([](const auto&,const auto&){return true;}),std::runtime_error);
}
BOOST_AUTO_TEST_CASE(explicit_demo_selects_complete_frozen_network)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);
    args.ForceSetArg("-mldsa44demo","1");
    auto params=CreateChainParams(args,ChainType::REGTEST);
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),"36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2");
    BOOST_REQUIRE_EQUAL(params->GenesisBlock().vtx.size(),1U);
    BOOST_CHECK_EQUAL(params->GenesisBlock().hashMerkleRoot.ToString(),"eff22c74638125519d38bab3d58d460f93ff0d5ef57dfbabc9514353bdb458cb");
    BOOST_CHECK_EQUAL(params->GetDefaultPort(),24833);
    BOOST_CHECK_EQUAL(params->Bech32HRP(),"rq");
    auto base=CreateBaseChainParams(ChainType::REGTEST,true);
    BOOST_CHECK_EQUAL(base->DataDir(),"mldsa44-regtest-v1");
    BOOST_CHECK_EQUAL(base->RPCPort(),24832);
    BOOST_CHECK(params->DNSSeeds().empty());
    BOOST_CHECK_NO_THROW(mldsa_node::ResolveNetwork(*params));
    BOOST_CHECK_THROW(CreateChainParams(args,ChainType::MAIN),std::invalid_argument);
    BOOST_CHECK_THROW(CreateChainParams(args,ChainType::TESTNET),std::invalid_argument);
    args.ForceSetArg("-mldsa44demo","0");
    BOOST_CHECK_EQUAL(CreateChainParams(args,ChainType::REGTEST)->GenesisBlock().GetHash().ToString(),
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
}
BOOST_AUTO_TEST_CASE(demo_absence_guard_reads_complete_effective_utxo_overlay)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);args.ForceSetArg("-mldsa44demo","1");
    auto params=CreateChainParams(args,ChainType::REGTEST);const auto genesis=params->GenesisBlock().GetHash();
    InventoryView disk;CCoinsViewCache parent{&disk,true},view{&parent,true};view.SetBestBlock(genesis);
    BOOST_CHECK_NO_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view));
    const COutPoint out{Txid::FromUint256(uint256::ONE),0};
    view.AddCoin(out,Coin{CTxOut{1000,CScript{}<<OP_TRUE},0,false},false);
    BOOST_CHECK_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view),std::invalid_argument);
    BOOST_REQUIRE(view.SpendCoin(out));
    BOOST_CHECK_NO_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view));
    disk.records.emplace(out,Coin{CTxOut{1000,CScript{}<<OP_2<<Bytes(32,0x42)},0,false});
    BOOST_CHECK_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view),std::invalid_argument);
    BOOST_REQUIRE(parent.SpendCoin(out));
    BOOST_CHECK_NO_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view));
    BOOST_CHECK_THROW(mldsa_node::CheckDemoActivation(*params,uint256::ONE,view),std::invalid_argument);
    view.SetBestBlock(uint256::ONE);
    BOOST_CHECK_THROW(mldsa_node::CheckDemoActivation(*params,genesis,view),std::invalid_argument);
}
BOOST_FIXTURE_TEST_CASE(actual_validation_owns_context_and_does_not_cache_mutations,BasicTestingSetup)
{
    Fixture f;ArgsManager args;SetupChainParamsBaseOptions(args);args.ForceSetArg("-mldsa44demo","1");
    auto params=CreateChainParams(args,ChainType::REGTEST);
    LOCK(cs_main);
    ValidationCache cache{1<<20,1<<20};
    const unsigned flags=STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_MLDSA44;
    auto run=[&](const CTransactionRef& tx,unsigned verify_flags,bool queued) {
        TxValidationState state;PrecomputedTransactionData data;std::vector<CScriptCheck> checks;
        bool ok=CheckInputScripts(tx,state,f.coins,verify_flags,true,true,data,cache,*params,queued?&checks:nullptr);
        if(ok)for(auto& check:checks)if(check())ok=false;
        return ok;
    };
    auto tx=MakeTransactionRef(f.tx);
    BOOST_CHECK(run(tx,flags,false));
    BOOST_CHECK(run(tx,flags,true));
    // Cache hit from the valid witness cannot authorize a modified signature.
    f.tx.vin[0].scriptWitness.stack[0][0]^=1;
    auto bad=MakeTransactionRef(f.tx);
    BOOST_CHECK(!run(bad,flags,false));BOOST_CHECK(!run(bad,flags,true));
    TxValidationState state;PrecomputedTransactionData data;
    BOOST_CHECK(!CheckInputScripts(bad,state,f.coins,flags,true,false,data,cache,*params));
    BOOST_CHECK(state.GetResult()==TxValidationResult::TX_CONSENSUS);
    f.tx.vin[0].scriptWitness.stack[0][0]^=1;--f.tx.vout[0].nValue;
    BOOST_CHECK(!run(MakeTransactionRef(f.tx),flags,false));
    BOOST_CHECK(!run(tx,STANDARD_SCRIPT_VERIFY_FLAGS,false));
    // The queued closure owns the exact transaction and immutable Coin snapshot.
    TxValidationState queued_state;PrecomputedTransactionData queued_data;std::vector<CScriptCheck> checks;
    ValidationCache lifetime_cache{1<<20,1<<20};
    BOOST_REQUIRE(CheckInputScripts(tx,queued_state,f.coins,flags,true,false,queued_data,lifetime_cache,*params,&checks));
    tx.reset();f.Replace(0,49999,CScript{}<<OP_TRUE);
    BOOST_REQUIRE_EQUAL(checks.size(),2U);
    for(auto& check:checks)BOOST_CHECK(!check().has_value());
}
BOOST_AUTO_TEST_CASE(demo_startup_rejects_coins_in_uninitialized_or_genesis_state)
{
    ArgsManager args;SetupChainParamsBaseOptions(args);args.ForceSetArg("-mldsa44demo","1");
    auto params=CreateChainParams(args,ChainType::REGTEST);
    InventoryView disk;CCoinsViewCache view{&disk,true};
    BOOST_CHECK_NO_THROW(mldsa_node::CheckDemoStartup(*params,view));
    const COutPoint out{Txid::FromUint256(uint256::ONE),0};
    view.AddCoin(out,Coin{CTxOut{1000,CScript{}<<OP_TRUE},0,false},false);
    BOOST_CHECK_THROW(mldsa_node::CheckDemoStartup(*params,view),std::invalid_argument);
    view.SetBestBlock(params->GenesisBlock().GetHash());
    BOOST_CHECK_THROW(mldsa_node::CheckDemoStartup(*params,view),std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(actual_coins_and_transaction_verify_public_fixture)
{
    Fixture f;mldsa_node::Snapshot snapshot{MakeTransactionRef(f.tx),f.coins};
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,0)),f.data["messages"][0].get_str());
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,1)),f.data["messages"][1].get_str());
    BOOST_CHECK(snapshot.VerifyInput(f.params,0));BOOST_CHECK(snapshot.VerifyInput(f.params,1));
    BOOST_CHECK(!snapshot.VerifyInput(f.params,2));
    BOOST_CHECK(snapshot.Transaction().GetHash()==MakeTransactionRef(f.tx)->GetHash());
    BOOST_CHECK_THROW((mldsa_node::Snapshot{CTransactionRef{},f.coins}),std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(native_v2_policy_permission_is_explicit_and_shape_scoped)
{
    Fixture f;
    BOOST_CHECK(!AreInputsStandard(CTransaction(f.tx),f.coins));
    BOOST_CHECK(AreInputsStandard(CTransaction(f.tx),f.coins,true));
    f.Replace(0,50000,CScript{}<<OP_2<<Bytes(31,0x42));
    BOOST_CHECK(!AreInputsStandard(CTransaction(f.tx),f.coins,true));
    f.Replace(0,50000,CScript{}<<OP_3<<Bytes(32,0x42));
    BOOST_CHECK(!AreInputsStandard(CTransaction(f.tx),f.coins,true));
}
BOOST_AUTO_TEST_CASE(effective_network_not_just_cached_or_model_network)
{
    Fixture f;BOOST_CHECK(mldsa_node::ResolveNetwork(f.params)==Network::REGTEST);
    alignas(FrozenParams) unsigned char storage[sizeof(FrozenParams)];
    std::fill(std::begin(storage),std::end(storage),0xa5);
    auto initialized=std::construct_at(reinterpret_cast<FrozenParams*>(storage));
    BOOST_CHECK(initialized->GetChainType()==ChainType::REGTEST);
    BOOST_CHECK(initialized->IsMockableChain());std::destroy_at(initialized);
    auto inherited=CChainParams::RegTest({});
    BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(*inherited),std::invalid_argument);
    BOOST_CHECK(!Verify(f.tx,f.coins,*inherited));
    auto wrong=f.params;wrong.ChangeHeader();BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(wrong),std::invalid_argument);
    wrong=f.params;wrong.ChangeCachedGenesis();BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(wrong),std::invalid_argument);
    wrong=f.params;wrong.Magic({0x96,0xbd,0x87,0xe9});BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(wrong),std::invalid_argument);
    wrong=f.params;wrong.Header(inherited->GenesisBlock());BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(wrong),std::invalid_argument);
    FrozenParams main{Network::MAIN};main.Magic(f.params.MessageStart());BOOST_CHECK_THROW(mldsa_node::ResolveNetwork(main),std::invalid_argument);
    for(auto network:{Network::MAIN,Network::TEST,Network::REGTEST}) {
        FrozenParams params{network};BOOST_CHECK(mldsa_node::ResolveNetwork(params)==network);
    }
}
BOOST_AUTO_TEST_CASE(transaction_version_sign_bit_is_wire_preserved)
{
    Fixture f;f.tx.version=0x80000000U;mldsa_node::Snapshot snapshot{MakeTransactionRef(f.tx),f.coins};
    // Literal independently encoded protocol_v1 expectations, not adapter output.
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,0)),"24eea89dea4146e79b97c517fab06598b69c47a3c643894973a3308303327853");
    BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,1)),"f0b9f521194f99cc7068cffe999af1eec097738f1969b6cdf48a2f944ca0b02a");
    BOOST_CHECK(!snapshot.VerifyInput(f.params,0));
}
BOOST_AUTO_TEST_CASE(missing_spent_negative_and_changed_metadata_reject)
{
    for (int mutation=0;mutation<9;++mutation) {
        Fixture f;auto script=f.coins.AccessCoin(f.tx.vin[1].prevout).out.scriptPubKey;
        switch(mutation) {
        case 0: BOOST_REQUIRE(f.coins.SpendCoin(f.tx.vin[1].prevout));break;
        case 1: f.Replace(1,-2,script);break;
        case 2: f.Replace(1,51001,script);break;
        case 3: script[3]^=1;f.Replace(1,51000,script);break;
        case 4: {
            auto moved=f.tx.vin[0].prevout;++moved.n;
            f.coins.AddCoin(moved,Coin{f.coins.AccessCoin(f.tx.vin[0].prevout).out,1,false},false);
            f.tx.vin[0].prevout=moved;break;
        }
        case 5: --f.tx.vout[0].nValue;break;
        case 6: f.tx.vin[0].scriptSig<<OP_0;break;
        case 7: f.tx.vin[0].scriptWitness.stack.push_back({});break;
        case 8: {
            auto bytes=f.tx.vin[0].prevout.hash.ToUint256();std::reverse(bytes.begin(),bytes.end());
            auto moved=COutPoint{Txid::FromUint256(bytes),f.tx.vin[0].prevout.n};
            f.coins.AddCoin(moved,Coin{f.coins.AccessCoin(f.tx.vin[0].prevout).out,1,false},false);
            f.tx.vin[0].prevout=moved;break;
        }
        }
        if(mutation<2) {
            BOOST_CHECK_THROW((mldsa_node::Snapshot{MakeTransactionRef(f.tx),f.coins}),std::invalid_argument);
        } else {
            std::unique_ptr<mldsa_node::Snapshot> snapshot;
            BOOST_REQUIRE_NO_THROW(snapshot=std::make_unique<mldsa_node::Snapshot>(MakeTransactionRef(f.tx),f.coins));
            BOOST_REQUIRE(snapshot);BOOST_CHECK_MESSAGE(!snapshot->VerifyInput(f.params,0),"mutation "<<mutation);
        }
    }
}
BOOST_AUTO_TEST_CASE(snapshot_is_owned_and_signer_policy_is_not_consensus)
{
    Fixture f;mldsa_node::Snapshot old{MakeTransactionRef(f.tx),f.coins};auto message=old.Message(Network::REGTEST,0);
    f.Replace(1,51001,f.coins.AccessCoin(f.tx.vin[1].prevout).out.scriptPubKey);
    BOOST_CHECK(old.Message(Network::REGTEST,0)==message);BOOST_CHECK(old.VerifyInput(f.params,0));
    BOOST_CHECK(!Verify(f.tx,f.coins,f.params));
    f.tx.vout.resize(101,CTxOut{0,CScript{}});f.tx.vout[1].scriptPubKey.resize(10001);
    BOOST_CHECK_NO_THROW((mldsa_node::Snapshot{MakeTransactionRef(f.tx),f.coins}));
}
BOOST_AUTO_TEST_CASE(script_native_v2_is_explicit_and_bound_to_actual_input)
{
    Fixture f;auto tx=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{tx,f.coins};
    BaseSignatureChecker fallback;mldsa_node::ScriptChecker checker{snapshot,f.params,0,fallback};
    const auto script=f.coins.AccessCoin(tx->vin[0].prevout).out.scriptPubKey;
    constexpr unsigned flags=SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_CLEANSTACK;
    ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(snapshot.IsApplicable(0));BOOST_CHECK(!snapshot.IsApplicable(2));
    BOOST_CHECK(VerifyScript({},script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,checker,&error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_OK);
    mldsa_node::ScriptChecker second{snapshot,f.params,1,fallback};
    BOOST_CHECK(VerifyScript({},script,&tx->vin[1].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,second,&error));
    // Select the wrapping constructor, not a copy of the inherited deferrer.
    const BaseSignatureChecker& underlying=checker;
    DeferringSignatureChecker forwarded{underlying};
    BOOST_CHECK(VerifyScript({},script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,forwarded,&error));
    BOOST_CHECK(!VerifyScript({},script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,fallback,&error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    auto changed_script=script;changed_script[4]^=1;
    BOOST_CHECK(!VerifyScript({},changed_script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,checker,&error));
    auto changed_witness=tx->vin[0].scriptWitness;changed_witness.stack[0][100]^=1;
    BOOST_CHECK(!VerifyScript({},script,&changed_witness,flags|SCRIPT_VERIFY_MLDSA44,checker,&error));
    mldsa_node::ScriptChecker wrong_input{snapshot,f.params,1,fallback};
    BOOST_CHECK(!VerifyScript({},script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,wrong_input,&error));
    auto inherited=CChainParams::RegTest({});mldsa_node::ScriptChecker wrong_network{snapshot,*inherited,0,fallback};
    BOOST_CHECK(!VerifyScript({},script,&tx->vin[0].scriptWitness,flags|SCRIPT_VERIFY_MLDSA44,wrong_network,&error));
    BOOST_CHECK(VerifyScript({},script,&changed_witness,flags,checker,&error));
    BOOST_CHECK(!VerifyScript({},script,&changed_witness,flags|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,checker,&error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}
BOOST_AUTO_TEST_CASE(script_v2_shape_and_crypto_fail_closed_without_generic_limit_change)
{
    constexpr unsigned flags=SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_MLDSA44;
    for(int mutation=0;mutation<8;++mutation) {
        Fixture f;auto& stack=f.tx.vin[0].scriptWitness.stack;
        switch(mutation) {
        case 0:stack.clear();break;
        case 1:stack.pop_back();break;
        case 2:stack.push_back({});break;
        case 3:stack[0].pop_back();break;
        case 4:stack[0].push_back(1);break;
        case 5:stack[1].pop_back();break;
        case 6:stack[1].push_back(1);break;
        case 7:stack[0][100]^=1;break;
        }
        auto tx=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{tx,f.coins};
        BaseSignatureChecker fallback;mldsa_node::ScriptChecker checker{snapshot,f.params,0,fallback};
        const auto script=f.coins.AccessCoin(tx->vin[0].prevout).out.scriptPubKey;
        ScriptError error=SCRIPT_ERR_OK;
        BOOST_CHECK_MESSAGE(!VerifyScript({},script,&tx->vin[0].scriptWitness,flags,checker,&error),"malformed v2 mutation "<<mutation);
        BOOST_CHECK_EQUAL(error,SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        if(mutation<7) {
            PermissiveShapeProbe probe;
            BOOST_CHECK(!VerifyScript({},script,&tx->vin[0].scriptWitness,flags,probe,&error));
            BOOST_CHECK_EQUAL(probe.calls,0U);
        }
    }
    BaseSignatureChecker checker;std::vector<Bytes> stack;ScriptError error=SCRIPT_ERR_OK;
    BOOST_CHECK(!EvalScript(stack,CScript{}<<Bytes(521,1),0,checker,SigVersion::BASE,&error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_PUSH_SIZE);
}
BOOST_AUTO_TEST_CASE(script_checker_rejects_copied_witness_from_another_transaction)
{
    Fixture f;auto original=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{original,f.coins};
    --f.tx.vout[0].nValue;auto other=MakeTransactionRef(f.tx);
    TransactionSignatureChecker inherited{other.get(),0,50000,MissingDataBehavior::FAIL};
    mldsa_node::ScriptChecker checker{snapshot,f.params,0,inherited};
    const auto script=f.coins.AccessCoin(original->vin[0].prevout).out.scriptPubKey;
    constexpr unsigned common=SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS;
    constexpr unsigned active=common|SCRIPT_VERIFY_MLDSA44|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(VerifyScript({},script,&original->vin[0].scriptWitness,active,checker,&error));
    BOOST_CHECK(!VerifyScript({},script,&other->vin[0].scriptWitness,active,checker,&error));
    auto copied=original->vin[0].scriptWitness;
    BOOST_CHECK(!VerifyScript({},script,&copied,active,checker,&error));
    // The policy/activation pair is intentionally not flag-monotone.
    BOOST_CHECK(!VerifyScript({},script,&original->vin[0].scriptWitness,
        common|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,checker,&error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}
BOOST_AUTO_TEST_CASE(script_applicability_and_legacy_checker_delegation_are_separate)
{
    Fixture f;f.Replace(1,51000,CScript{}<<OP_TRUE);
    auto tx=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{tx,f.coins};
    BOOST_CHECK(snapshot.IsApplicable(0));BOOST_CHECK(!snapshot.IsApplicable(1));
    LegacyProbe inherited;mldsa_node::ScriptChecker checker{snapshot,f.params,1,inherited};
    BOOST_CHECK(checker.CheckLockTime(CScriptNum{1}));BOOST_CHECK(checker.CheckSequence(CScriptNum{1}));
    BOOST_CHECK(checker.CheckECDSASignature({},{},{},SigVersion::BASE));
    ScriptExecutionData data;
    BOOST_CHECK(checker.CheckSchnorrSignature({},{},SigVersion::TAPROOT,data,nullptr));
    BOOST_CHECK(!checker.CheckMLDSA44Witness({},{}));
    // The old v2 signatures no longer authorize the changed mixed prevouts.
    BOOST_CHECK(!snapshot.VerifyInput(f.params,0));
}
BOOST_AUTO_TEST_CASE(script_unrelated_and_nested_programs_keep_unknown_semantics)
{
    Fixture f;auto tx=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{tx,f.coins};
    BaseSignatureChecker fallback;mldsa_node::ScriptChecker checker{snapshot,f.params,0,fallback};
    constexpr unsigned flags=SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_MLDSA44;
    CScriptWitness witness;witness.stack={Bytes(700,1)};ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
    for(auto [version,size]:{std::pair{OP_2,31},std::pair{OP_3,32}}) {
        CScript script;script<<version<<Bytes(size,1);
        BOOST_CHECK(VerifyScript({},script,&witness,flags,checker,&error));
        BOOST_CHECK(!VerifyScript({},script,&witness,flags|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,checker,&error));
    }
    const auto native=f.coins.AccessCoin(tx->vin[0].prevout).out.scriptPubKey;
    const auto nested=GetScriptForDestination(ScriptHash{native});
    const auto redeem=CScript{}<<Bytes(native.begin(),native.end());
    BOOST_CHECK(VerifyScript(redeem,nested,&witness,flags,checker,&error));
    BOOST_CHECK(!VerifyScript(redeem,nested,&witness,flags|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,checker,&error));
}
BOOST_AUTO_TEST_CASE(script_distinct_keys_and_valid_mixed_input_dispatch)
{
    constexpr unsigned flags=SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_CLEANSTACK|
        SCRIPT_VERIFY_MLDSA44|SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    for(size_t profile=0;profile<2;++profile) {
        ScriptFixture f{profile};auto tx=MakeTransactionRef(f.tx);mldsa_node::Snapshot snapshot{tx,f.coins};
        for(size_t i=0;i<2;++i) {
            BOOST_CHECK_EQUAL(HexStr(snapshot.Message(Network::REGTEST,i)),f.data["messages"][i].get_str());
            BOOST_CHECK_EQUAL(snapshot.IsApplicable(i),!f.data["witnesses"][i].empty());
            BaseSignatureChecker inherited;mldsa_node::ScriptChecker checker{snapshot,f.params,i,inherited};
            ScriptError error=SCRIPT_ERR_UNKNOWN_ERROR;
            BOOST_CHECK(VerifyScript({},f.coins.AccessCoin(tx->vin[i].prevout).out.scriptPubKey,
                &tx->vin[i].scriptWitness,flags,checker,&error));
            BOOST_CHECK_EQUAL(error,SCRIPT_ERR_OK);
        }
        if(profile==0) {
            std::swap(f.tx.vin[0].scriptWitness,f.tx.vin[1].scriptWitness);
            auto swapped=MakeTransactionRef(f.tx);mldsa_node::Snapshot bad{swapped,f.coins};
            for(size_t i=0;i<2;++i) {
                BaseSignatureChecker inherited;mldsa_node::ScriptChecker checker{bad,f.params,i,inherited};ScriptError error;
                BOOST_CHECK(!VerifyScript({},f.coins.AccessCoin(swapped->vin[i].prevout).out.scriptPubKey,
                    &swapped->vin[i].scriptWitness,flags,checker,&error));
            }
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
