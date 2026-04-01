// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>

#include <addresstype.h>
#include <consensus/consensus.h>
#include <key.h>
#include <key_io.h>
#include <node/types.h>
#include <script/descriptor.h>
#include <script/solver.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/pq_scriptpubkeyman.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(pq_wallet_tests, TestChain100Setup)

namespace {

constexpr uint64_t BLANK_DESCRIPTOR_WALLET_FLAGS{WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET};
constexpr int32_t PQ_RECEIVE_RANGE_END{1};
constexpr int32_t PQ_CHANGE_RANGE_END{0};

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

CTxDestination DerivePQDestination(const std::array<unsigned char, 32>& root_seed, bool internal, int32_t index)
{
    std::array<unsigned char, pqsig::PK_SCRIPT_SIZE> pk_script{};
    if (!pqsig::DeriveWalletPkScript(pk_script, root_seed, internal, index)) {
        throw std::runtime_error("failed to derive deterministic PQ destination");
    }
    const CScript witness_script = CScript{} << std::vector<unsigned char>(pk_script.begin(), pk_script.end()) << OP_CHECKSIG;
    return WitnessV0ScriptHash(witness_script);
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

void RescanWalletToTip(TestChain100Setup& setup, CWallet& wallet)
{
    const auto [genesis_hash, tip_hash, tip_height] = WITH_LOCK(Assert(setup.m_node.chainman)->GetMutex(), return std::make_tuple(
        setup.m_node.chainman->ActiveChain().Genesis()->GetBlockHash(),
        setup.m_node.chainman->ActiveChain().Tip()->GetBlockHash(),
        setup.m_node.chainman->ActiveChain().Height()));
    WalletRescanReserver reserver(wallet);
    BOOST_REQUIRE(reserver.reserve());
    const auto result = wallet.ScanForWalletTransactions(genesis_hash, /*start_height=*/0, /*max_height=*/tip_height, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
    BOOST_CHECK_EQUAL(result.last_scanned_block, tip_hash);
    BOOST_REQUIRE(result.last_scanned_height.has_value());
    BOOST_CHECK_EQUAL(*result.last_scanned_height, tip_height);
}

Txid MineMatureWalletCoinbase(TestChain100Setup& setup, const CTxDestination& dest)
{
    const auto funded_block = setup.CreateAndProcessBlock({}, GetScriptForDestination(dest));
    const Txid funding_txid = funded_block.vtx.at(0)->GetHash();
    for (int i = 0; i < COINBASE_MATURITY; ++i) {
        setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));
    }
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    return funding_txid;
}

Txid FundWalletFromCoinbase(TestChain100Setup& setup, CWallet& wallet, const CTxDestination& dest)
{
    const Txid funding_txid = MineMatureWalletCoinbase(setup, dest);
    RescanWalletToTip(setup, wallet);
    return funding_txid;
}

CWalletTx& CommitAndConfirm(TestChain100Setup& setup, CWallet& wallet, const CRecipient& recipient)
{
    CTransactionRef tx;
    CCoinControl coin_control;
    coin_control.m_feerate = CFeeRate(1000);
    {
        auto res = CreateTransaction(wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
        tx = res->tx;
    }
    wallet.CommitTransaction(tx, {}, {});

    CMutableTransaction block_tx;
    {
        LOCK(wallet.cs_wallet);
        block_tx = CMutableTransaction(*wallet.mapWallet.at(tx->GetHash()).tx);
    }
    setup.CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();

    LOCK(wallet.cs_wallet);
    LOCK(Assert(setup.m_node.chainman)->GetMutex());
    wallet.SetLastBlockProcessed(wallet.GetLastBlockHeight() + 1, setup.m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    auto it = wallet.mapWallet.find(tx->GetHash());
    BOOST_REQUIRE(it != wallet.mapWallet.end());
    it->second.m_state = TxStateConfirmed{setup.m_node.chainman->ActiveChain().Tip()->GetBlockHash(), setup.m_node.chainman->ActiveChain().Height(), /*index=*/1};
    return it->second;
}

size_t CountListedCoins(const std::map<CTxDestination, std::vector<COutput>>& list)
{
    size_t count{0};
    for (const auto& [_, coins] : list) count += coins.size();
    return count;
}

std::set<COutPoint> CollectListedOutpoints(const std::map<CTxDestination, std::vector<COutput>>& list)
{
    std::set<COutPoint> outpoints;
    for (const auto& [_, coins] : list) {
        for (const auto& coin : coins) {
            outpoints.insert(coin.outpoint);
        }
    }
    return outpoints;
}

std::set<COutPoint> CollectOwnedOutpoints(const CWallet& wallet, const CWalletTx& tx)
{
    std::set<COutPoint> outpoints;
    LOCK(wallet.cs_wallet);
    for (uint32_t i = 0; i < tx.tx->vout.size(); ++i) {
        if (wallet.IsMine(tx.tx->vout[i])) {
            outpoints.emplace(tx.GetHash(), i);
        }
    }
    return outpoints;
}

std::set<std::string> CollectOwnedDestinations(const CWallet& wallet, const CWalletTx& tx)
{
    std::set<std::string> destinations;
    LOCK(wallet.cs_wallet);
    for (const auto& txout : tx.tx->vout) {
        if (!wallet.IsMine(txout)) continue;
        CTxDestination dest;
        BOOST_REQUIRE(ExtractDestination(txout.scriptPubKey, dest));
        destinations.insert(EncodeDestination(dest));
    }
    return destinations;
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_wallet_listcoins_and_output_types_cover_receive_change_and_locked_outputs)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(0x24);

    auto loaded = CreateActivePQWallet(*this, root_seed);
    const CTxDestination first_receive = *Assert(loaded->GetNewPQDestination("first receive"));
    const CTxDestination expected_change = DerivePQDestination(root_seed, /*internal=*/true, /*index=*/0);

    const Txid funding_txid = FundWalletFromCoinbase(*this, *loaded, first_receive);
    {
        LOCK(loaded->cs_wallet);
        BOOST_REQUIRE_EQUAL(loaded->mapWallet.count(funding_txid), 1U);
    }

    CWalletTx& spend_wtx = CommitAndConfirm(*this, *loaded, CRecipient{first_receive, 1 * COIN, /*subtract_fee=*/false});

    std::map<CTxDestination, std::vector<COutput>> listed;
    CoinsResult available;
    {
        LOCK(loaded->cs_wallet);
        CoinFilterParams filter;
        filter.skip_locked = false;
        listed = ListCoins(*loaded);
        available = AvailableCoins(*loaded, nullptr, std::nullopt, filter);
    }

    const std::set<COutPoint> expected_outpoints = CollectOwnedOutpoints(*loaded, spend_wtx);
    const std::set<COutPoint> listed_outpoints = CollectListedOutpoints(listed);
    const std::set<std::string> owned_destinations = CollectOwnedDestinations(*loaded, spend_wtx);

    BOOST_CHECK_EQUAL(expected_outpoints.size(), 2U);
    BOOST_CHECK_EQUAL(CountListedCoins(listed), 2U);
    BOOST_CHECK(expected_outpoints == listed_outpoints);
    BOOST_CHECK_EQUAL(available.Size(), 2U);
    BOOST_CHECK_EQUAL(available.coins[OutputType::BECH32].size(), 2U);
    BOOST_CHECK_EQUAL(available.coins[OutputType::UNKNOWN].size(), 0U);
    BOOST_CHECK(owned_destinations.contains(EncodeDestination(first_receive)));
    BOOST_CHECK(owned_destinations.contains(EncodeDestination(expected_change)));

    for (const auto& [_, coins] : listed) {
        for (const auto& coin : coins) {
            LOCK(loaded->cs_wallet);
            loaded->LockCoin(coin.outpoint, /*persist=*/false);
        }
    }

    {
        LOCK(loaded->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoins(*loaded).Size(), 0U);
        BOOST_CHECK(CollectListedOutpoints(ListCoins(*loaded)) == expected_outpoints);
    }
}

BOOST_AUTO_TEST_CASE(pq_wallet_reload_persists_next_index_and_rescan_finds_funded_outputs)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(0x42);

    auto loaded = CreateActivePQWallet(*this, root_seed);
    const CTxDestination first_receive = *Assert(loaded->GetNewPQDestination("first receive"));
    std::unique_ptr<WalletDatabase> duplicate_db = DuplicateMockDatabase(loaded->GetDatabase());
    TestUnloadWallet(std::move(loaded.wallet));

    const Txid funding_txid = MineMatureWalletCoinbase(*this, first_receive);

    LoadedPQWallet reloaded;
    reloaded.context = std::make_unique<WalletContext>();
    reloaded.context->args = &m_args;
    reloaded.context->chain = m_node.chain.get();
    reloaded.wallet = TestLoadWallet(std::move(duplicate_db), *reloaded.context, BLANK_DESCRIPTOR_WALLET_FLAGS);
    RescanWalletToTip(*this, *reloaded);

    {
        LOCK(reloaded->cs_wallet);
        BOOST_REQUIRE_EQUAL(reloaded->mapWallet.count(funding_txid), 1U);
    }

    const CTxDestination next_receive = *Assert(reloaded->GetNewPQDestination("post reload"));
    BOOST_CHECK_EQUAL(EncodeDestination(next_receive), EncodeDestination(DerivePQDestination(root_seed, /*internal=*/false, /*index=*/1)));
}

BOOST_AUTO_TEST_CASE(pq_wallet_remove_txs_clears_wallet_spend_tracking)
{
    std::array<unsigned char, 32> root_seed{};
    root_seed.fill(0x36);

    auto loaded = CreateActivePQWallet(*this, root_seed);
    const CTxDestination first_receive = *Assert(loaded->GetNewPQDestination("first receive"));
    const Txid funding_txid = FundWalletFromCoinbase(*this, *loaded, first_receive);

    const auto funding_ref = WITH_LOCK(loaded->cs_wallet, return loaded->mapWallet.at(funding_txid).tx);
    const CTxDestination sink = WitnessV0KeyHash(GenerateRandomKey().GetPubKey().GetID());
    CWalletTx& spend_wtx = CommitAndConfirm(*this, *loaded, CRecipient{sink, 1 * COIN, /*subtract_fee=*/false});
    const Txid spend_hash = spend_wtx.GetHash();

    {
        LOCK(loaded->cs_wallet);
        BOOST_CHECK(loaded->HasWalletSpend(funding_ref));
        BOOST_CHECK_EQUAL(loaded->mapWallet.count(spend_hash), 1U);

        std::vector<Txid> hashes{spend_hash};
        const auto removal = loaded->RemoveTxs(hashes);
        BOOST_REQUIRE_MESSAGE(removal, util::ErrorString(removal).original);

        BOOST_CHECK(!loaded->HasWalletSpend(funding_ref));
        BOOST_CHECK_EQUAL(loaded->mapWallet.count(spend_hash), 0U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
