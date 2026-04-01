// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>

#include <addresstype.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/pqsig/pqsig.h>
#include <key.h>
#include <key_io.h>
#include <node/psbt.h>
#include <node/types.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/pq_scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::TestLoadWallet;
using wallet::TestUnloadWallet;
using wallet::WalletContext;

constexpr uint64_t BLANK_DESCRIPTOR_WALLET_FLAGS{wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_BLANK_WALLET};
constexpr int32_t PQ_RECEIVE_RANGE_END{1};
constexpr int32_t PQ_CHANGE_RANGE_END{0};
constexpr uint64_t PQBTC_IN_PARTIAL_SIG{0x01};
constexpr std::array<unsigned char, 5> PQBTC_IDENTIFIER{{'p', 'q', 'b', 't', 'c'}};

struct LoadedPQWallet {
    std::unique_ptr<WalletContext> context;
    std::shared_ptr<CWallet> wallet;

    LoadedPQWallet() = default;
    LoadedPQWallet(LoadedPQWallet&&) = default;
    LoadedPQWallet(const LoadedPQWallet&) = delete;
    LoadedPQWallet& operator=(const LoadedPQWallet&) = delete;

    ~LoadedPQWallet()
    {
        if (wallet) TestUnloadWallet(std::move(wallet));
    }

    CWallet& operator*() const { return *wallet; }
    CWallet* operator->() const { return wallet.get(); }
};

PQPrivateDescriptorInfo ParsePQDescriptorInfo(const std::array<unsigned char, 32>& root_seed, bool internal)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(GetPQPrivateDescriptorString(root_seed, internal), provider, error, /*require_checksum=*/true);
    if (parsed.empty()) {
        throw std::runtime_error(error);
    }
    auto info = GetPQPrivateDescriptorInfo(*parsed.at(0));
    if (!info.has_value()) {
        throw std::runtime_error("missing pqpriv() descriptor info");
    }
    return *info;
}

LoadedPQWallet CreateActivePQWallet(TestChain100Setup& setup, const std::array<unsigned char, 32>& root_seed)
{
    LoadedPQWallet loaded;
    setup.m_args.ForceSetArg("-keypool", "1");
    loaded.context = std::make_unique<WalletContext>();
    loaded.context->args = &setup.m_args;
    loaded.context->chain = setup.m_node.chain.get();
    loaded.wallet = TestLoadWallet(CreateMockableWalletDatabase(), *loaded.context, BLANK_DESCRIPTOR_WALLET_FLAGS);
    loaded.wallet->m_keypool_size = 1;

    LOCK(loaded.wallet->cs_wallet);
    auto& receive_manager = Assert(loaded.wallet->AddWalletPQDescriptor(ParsePQDescriptorInfo(root_seed, /*internal=*/false), /*creation_time=*/0, /*range_start=*/0, PQ_RECEIVE_RANGE_END, /*next_index=*/0))->get();
    loaded.wallet->AddActivePQScriptPubKeyMan(receive_manager.GetID(), /*internal=*/false);
    auto& change_manager = Assert(loaded.wallet->AddWalletPQDescriptor(ParsePQDescriptorInfo(root_seed, /*internal=*/true), /*creation_time=*/0, /*range_start=*/0, PQ_CHANGE_RANGE_END, /*next_index=*/0))->get();
    loaded.wallet->AddActivePQScriptPubKeyMan(change_manager.GetID(), /*internal=*/true);
    return loaded;
}

CTxDestination MakePQDestination(const std::array<unsigned char, 32>& root_seed, bool internal, int32_t index)
{
    std::array<unsigned char, pqsig::PK_SCRIPT_SIZE> pk_script{};
    if (!pqsig::DeriveWalletPkScript(pk_script, root_seed, internal, index)) {
        throw std::runtime_error("failed to derive deterministic PQ destination");
    }
    const CScript witness_script = CScript{} << std::vector<unsigned char>(pk_script.begin(), pk_script.end()) << OP_CHECKSIG;
    return WitnessV0ScriptHash(witness_script);
}

void RescanWalletToTip(TestChain100Setup& setup, CWallet& wallet)
{
    const auto [genesis_hash, tip_hash, tip_height] = WITH_LOCK(Assert(setup.m_node.chainman)->GetMutex(), return std::make_tuple(
        setup.m_node.chainman->ActiveChain().Genesis()->GetBlockHash(),
        setup.m_node.chainman->ActiveChain().Tip()->GetBlockHash(),
        setup.m_node.chainman->ActiveChain().Height()));
    wallet::WalletRescanReserver reserver(wallet);
    BOOST_REQUIRE(reserver.reserve());
    const auto result = wallet.ScanForWalletTransactions(genesis_hash, /*start_height=*/0, /*max_height=*/tip_height, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
    BOOST_CHECK_EQUAL(result.last_scanned_block, tip_hash);
}

Txid FundWalletFromCoinbase(TestChain100Setup& setup, CWallet& wallet, const CTxDestination& dest)
{
    const auto funded_block = setup.CreateAndProcessBlock({}, GetScriptForDestination(dest));
    const Txid funding_txid = funded_block.vtx.at(0)->GetHash();
    for (int i = 0; i < COINBASE_MATURITY; ++i) {
        setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));
    }
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    RescanWalletToTip(setup, wallet);
    return funding_txid;
}

PartiallySignedTransaction CreateUnsignedPQSpendPSBT(CWallet& wallet)
{
    const CTxDestination sink = WitnessV0KeyHash(GenerateRandomKey().GetPubKey().GetID());
    const wallet::CRecipient recipient{sink, 1 * COIN, /*subtract_fee=*/false};
    wallet::CCoinControl coin_control;
    coin_control.m_feerate = CFeeRate(1000);
    auto tx_result = wallet::CreateTransaction(wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control, /*sign=*/false);
    BOOST_REQUIRE_MESSAGE(tx_result, util::ErrorString(tx_result).original);
    return PartiallySignedTransaction(CMutableTransaction(*tx_result->tx));
}

PQPkScript MakePkScript(uint8_t seed_byte)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(seed_byte);
    PQPkScript pk_script{};
    if (!pqsig::DeriveWalletPkScript(pk_script, root_seed, /*internal=*/false, /*index=*/0)) {
        throw std::runtime_error("failed to derive deterministic test pk script");
    }
    return pk_script;
}

std::vector<unsigned char> MakeSig(uint8_t fill, size_t size = pqsig::SIG_SIZE)
{
    return std::vector<unsigned char>(size, fill);
}

std::vector<unsigned char> SerializePQPropKey(uint8_t type, const std::vector<unsigned char>& identifier, uint64_t subtype, std::span<const unsigned char> trailing_key)
{
    std::vector<unsigned char> key;
    VectorWriter writer{key, 0};
    writer << CompactSizeWriter(type);
    writer << identifier;
    WriteCompactSize(writer, subtype);
    writer << trailing_key;
    return key;
}

PSBTProprietary MakePQPartialSigProp(const PQPkScript& pk_script, const std::vector<unsigned char>& sig)
{
    PSBTProprietary prop;
    prop.subtype = PQBTC_IN_PARTIAL_SIG;
    prop.identifier.assign(PQBTC_IDENTIFIER.begin(), PQBTC_IDENTIFIER.end());
    prop.key = SerializePQPropKey(PSBT_IN_PROPRIETARY, prop.identifier, prop.subtype, std::span<const unsigned char>(pk_script.begin(), pk_script.end()));
    prop.value = sig;
    return prop;
}

bool IsPQPartialSigProp(const PSBTProprietary& prop)
{
    return prop.subtype == PQBTC_IN_PARTIAL_SIG &&
           prop.identifier == std::vector<unsigned char>(PQBTC_IDENTIFIER.begin(), PQBTC_IDENTIFIER.end());
}

size_t CountPQPartialSigProps(const PSBTInput& input)
{
    size_t count{0};
    for (const auto& prop : input.m_proprietary) {
        if (IsPQPartialSigProp(prop)) ++count;
    }
    return count;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_psbt_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(pq_psbt_malformed_proprietary_partial_sigs_are_ignored)
{
    const PQPkScript pk_script = MakePkScript(0x11);
    const std::vector<unsigned char> valid_sig = MakeSig(0x44);

    struct MalformedCase {
        std::string name;
        PSBTProprietary prop;
    };

    std::vector<MalformedCase> cases;

    PSBTProprietary wrong_identifier = MakePQPartialSigProp(pk_script, valid_sig);
    wrong_identifier.identifier = {'n', 'o', 'p', 'e'};
    wrong_identifier.key = SerializePQPropKey(PSBT_IN_PROPRIETARY, wrong_identifier.identifier, wrong_identifier.subtype, std::span<const unsigned char>(pk_script.begin(), pk_script.end()));
    cases.push_back({"wrong identifier", std::move(wrong_identifier)});

    PSBTProprietary wrong_subtype = MakePQPartialSigProp(pk_script, valid_sig);
    wrong_subtype.subtype = 0x02;
    wrong_subtype.key = SerializePQPropKey(PSBT_IN_PROPRIETARY, wrong_subtype.identifier, wrong_subtype.subtype, std::span<const unsigned char>(pk_script.begin(), pk_script.end()));
    cases.push_back({"wrong subtype", std::move(wrong_subtype)});

    PSBTProprietary wrong_key_prefix = MakePQPartialSigProp(pk_script, valid_sig);
    wrong_key_prefix.key = SerializePQPropKey(PSBT_IN_PARTIAL_SIG, wrong_key_prefix.identifier, wrong_key_prefix.subtype, std::span<const unsigned char>(pk_script.begin(), pk_script.end()));
    cases.push_back({"wrong proprietary key prefix", std::move(wrong_key_prefix)});

    PSBTProprietary wrong_pk_script_length = MakePQPartialSigProp(pk_script, valid_sig);
    wrong_pk_script_length.key = SerializePQPropKey(PSBT_IN_PROPRIETARY, wrong_pk_script_length.identifier, wrong_pk_script_length.subtype, std::span<const unsigned char>(pk_script.begin(), pk_script.end() - 1));
    cases.push_back({"wrong pk_script length", std::move(wrong_pk_script_length)});

    PSBTProprietary wrong_sig_length = MakePQPartialSigProp(pk_script, MakeSig(0x44, pqsig::SIG_SIZE - 1));
    cases.push_back({"wrong signature length", std::move(wrong_sig_length)});

    for (const auto& test_case : cases) {
        BOOST_TEST_CONTEXT(test_case.name) {
            PSBTInput input;
            input.m_proprietary.insert(test_case.prop);

            SignatureData sigdata;
            input.FillSignatureData(sigdata);
            BOOST_CHECK(sigdata.pq_signatures.empty());
        }
    }
}

BOOST_AUTO_TEST_CASE(pq_psbt_from_signature_data_rewrites_stale_proprietary_fields)
{
    const PQPkScript stale_pk_script = MakePkScript(0x21);
    const PQPkScript fresh_pk_script = MakePkScript(0x22);

    PSBTInput input;
    input.m_proprietary.insert(MakePQPartialSigProp(stale_pk_script, MakeSig(0x51)));

    PSBTProprietary unrelated_prop;
    unrelated_prop.subtype = 0x07;
    unrelated_prop.identifier = {'m', 'e', 't', 'a'};
    unrelated_prop.key = SerializePQPropKey(PSBT_IN_PROPRIETARY, unrelated_prop.identifier, unrelated_prop.subtype, std::span<const unsigned char>());
    unrelated_prop.value = {0x01, 0x02, 0x03};
    input.m_proprietary.insert(unrelated_prop);

    SignatureData sigdata;
    sigdata.pq_signatures.emplace(fresh_pk_script, MakeSig(0x61));

    input.FromSignatureData(sigdata);

    BOOST_CHECK_EQUAL(CountPQPartialSigProps(input), 1U);
    BOOST_CHECK_EQUAL(input.m_proprietary.count(unrelated_prop), 1U);

    SignatureData roundtrip;
    input.FillSignatureData(roundtrip);
    BOOST_CHECK(roundtrip.pq_signatures == sigdata.pq_signatures);
}

BOOST_AUTO_TEST_CASE(pq_analyze_psbt_role_transitions_cover_updater_signer_and_finalizer)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(0x42);

    auto loaded = CreateActivePQWallet(*this, root_seed);
    const CTxDestination receive = MakePQDestination(root_seed, /*internal=*/false, /*index=*/0);
    FundWalletFromCoinbase(*this, *loaded, receive);

    PartiallySignedTransaction psbt = CreateUnsignedPQSpendPSBT(*loaded);

    node::PSBTAnalysis analysis = node::AnalyzePSBT(psbt);
    BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
    BOOST_CHECK(!analysis.inputs[0].has_utxo);
    BOOST_CHECK_EQUAL(analysis.inputs[0].next, PSBTRole::UPDATER);
    BOOST_CHECK_EQUAL(analysis.next, PSBTRole::UPDATER);

    bool complete{false};
    BOOST_REQUIRE(!loaded->FillPSBT(psbt, complete, std::nullopt, /*sign=*/false, /*bip32derivs=*/true, nullptr, /*finalize=*/false));
    BOOST_CHECK(!complete);

    analysis = node::AnalyzePSBT(psbt);
    BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
    BOOST_CHECK(analysis.inputs[0].has_utxo);
    BOOST_CHECK(!analysis.inputs[0].is_final);
    BOOST_CHECK_EQUAL(analysis.inputs[0].next, PSBTRole::SIGNER);
    BOOST_CHECK_EQUAL(analysis.next, PSBTRole::SIGNER);

    BOOST_REQUIRE(!loaded->FillPSBT(psbt, complete, std::nullopt, /*sign=*/true, /*bip32derivs=*/false, nullptr, /*finalize=*/false));
    BOOST_CHECK(!complete);

    analysis = node::AnalyzePSBT(psbt);
    BOOST_REQUIRE_EQUAL(analysis.inputs.size(), 1U);
    BOOST_CHECK(analysis.inputs[0].has_utxo);
    BOOST_CHECK(!analysis.inputs[0].is_final);
    BOOST_CHECK_EQUAL(analysis.inputs[0].next, PSBTRole::FINALIZER);
    BOOST_CHECK_EQUAL(analysis.next, PSBTRole::FINALIZER);
}

BOOST_AUTO_TEST_CASE(pq_fillpsbt_rejects_non_default_sighash)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(0x33);

    auto loaded = CreateActivePQWallet(*this, root_seed);
    const CTxDestination receive = MakePQDestination(root_seed, /*internal=*/false, /*index=*/0);
    FundWalletFromCoinbase(*this, *loaded, receive);

    PartiallySignedTransaction psbt = CreateUnsignedPQSpendPSBT(*loaded);
    bool complete{false};
    const auto err = loaded->FillPSBT(psbt, complete, SIGHASH_NONE, /*sign=*/false, /*bip32derivs=*/true, nullptr, /*finalize=*/false);

    BOOST_REQUIRE(err.has_value());
    BOOST_CHECK(*err == common::PSBTError::SIGHASH_MISMATCH);
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_SUITE_END()
