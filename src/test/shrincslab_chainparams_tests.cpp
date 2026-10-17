// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <kernel/chainparams.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <memory>

BOOST_AUTO_TEST_SUITE(shrincslab_chainparams_tests)

BOOST_AUTO_TEST_CASE(dedicated_identity_and_activation)
{
    CChainParams::RegTestOptions regular_options{};
    CChainParams::RegTestOptions lab_options{};
    lab_options.shrincs_labnet = true;

    const std::unique_ptr<const CChainParams> regular{CChainParams::RegTest(regular_options)};
    const std::unique_ptr<const CChainParams> lab{CChainParams::RegTest(lab_options)};

    BOOST_CHECK(!regular->GetConsensus().shrincs_v0);
    BOOST_CHECK(lab->GetConsensus().shrincs_v0);
    BOOST_CHECK_NE(regular->GenesisBlock().GetHash(), lab->GenesisBlock().GetHash());
    BOOST_CHECK_EQUAL(lab->GenesisBlock().GetHash(), uint256{"122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69"});
    BOOST_CHECK_EQUAL(lab->GenesisBlock().hashMerkleRoot, uint256{"2dec88624f3bbd6308ed55b83d9cb01933bbc76759498e52d21130c4e6ccd672"});
    BOOST_CHECK_EQUAL(lab->GetDefaultPort(), 29333);
    BOOST_CHECK_EQUAL(lab->Bech32HRP(), "pqsl");
    BOOST_CHECK(lab->DNSSeeds().empty());
    BOOST_CHECK(lab->FixedSeeds().empty());
    BOOST_CHECK(lab->GetAvailableSnapshotHeights().empty());
    BOOST_CHECK(!lab->IsMockableChain());
    BOOST_CHECK(regular->IsMockableChain());

    const std::array<unsigned char, 4> expected_magic{0x91, 0xe1, 0xca, 0xc8};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        lab->MessageStart().begin(), lab->MessageStart().end(),
        expected_magic.begin(), expected_magic.end());
    const std::optional<ChainType> network{GetNetworkForMagic(lab->MessageStart())};
    BOOST_REQUIRE(network.has_value());
    BOOST_CHECK(*network == ChainType::REGTEST);
}

BOOST_AUTO_TEST_SUITE_END()
