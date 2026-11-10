// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.

#include <addresstype.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <crypto/mldsa44/resource_limits.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <tuple>
#include <vector>

namespace {
static_assert(pqbtc::mldsa44::MAX_BLOCK_VERIFICATIONS ==
              MAX_BLOCK_SIGOPS_COST / pqbtc::mldsa44::VERIFICATION_SIGOPS_COST);
static_assert(pqbtc::mldsa44::MAX_STANDARD_TX_VERIFICATIONS ==
              MAX_STANDARD_TX_SIGOPS_COST / pqbtc::mldsa44::VERIFICATION_SIGOPS_COST);
constexpr unsigned WITNESS_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
constexpr unsigned ACTIVE_FLAGS{WITNESS_FLAGS | SCRIPT_VERIFY_MLDSA44};

CScript Program(opcodetype version = OP_2, size_t size = 32)
{
    return CScript{} << version << std::vector<unsigned char>(size, 1);
}

// Use real UTXO lookup and the cost function consumed by mempool/mining/blocks.
struct ResourceTransaction {
    CCoinsView base;
    CCoinsViewCache coins{&base};
    CMutableTransaction tx;

    explicit ResourceTransaction(size_t count, const CScript& prevout = Program())
    {
        tx.vout.emplace_back(1, Program());
        for (size_t i = 0; i < count; ++i) {
            const COutPoint outpoint{Txid::FromUint256(uint256{1}), static_cast<uint32_t>(i)};
            coins.AddCoin(outpoint, Coin{CTxOut{2, prevout}, 1, false}, false);
            tx.vin.emplace_back(outpoint);
        }
    }

    int64_t Cost(unsigned flags = ACTIVE_FLAGS) const
    {
        return GetTransactionSigOpCost(CTransaction{tx}, coins, flags);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(mldsa44_resource_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(native_verification_is_charged_only_when_enabled)
{
    ResourceTransaction fixture{1};
    BOOST_CHECK_EQUAL(fixture.Cost(), 625);
    for (const unsigned flags : {0U, static_cast<unsigned>(SCRIPT_VERIFY_P2SH),
                                WITNESS_FLAGS, static_cast<unsigned>(STANDARD_SCRIPT_VERIFY_FLAGS),
                                static_cast<unsigned>(SCRIPT_VERIFY_MLDSA44)}) {
        BOOST_CHECK_EQUAL(fixture.Cost(flags), 0);
    }
    BOOST_CHECK_EQUAL(fixture.Cost(STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_MLDSA44), 625);
}

BOOST_AUTO_TEST_CASE(native_cost_uses_prevout_shape_not_untrusted_witness)
{
    ResourceTransaction fixture{1};
    // Invalid or absent witness must not make an attempted native input free.
    for (const std::vector<std::vector<unsigned char>>& stack : {
             std::vector<std::vector<unsigned char>>{},
             std::vector<std::vector<unsigned char>>{{}},
             std::vector<std::vector<unsigned char>>{{1}, {2}},
             std::vector<std::vector<unsigned char>>{
                 std::vector<unsigned char>(2420, 1), std::vector<unsigned char>(1312, 1)}}) {
        fixture.tx.vin[0].scriptWitness.stack = stack;
        BOOST_CHECK_EQUAL(fixture.Cost(), 625);
    }
    fixture.tx.vin[0].scriptSig = CScript{} << OP_0;
    BOOST_CHECK_EQUAL(fixture.Cost(), 625);
    BOOST_CHECK_EQUAL(CountWitnessSigOps({}, Program(), nullptr, ACTIVE_FLAGS), 625U);
}

BOOST_AUTO_TEST_CASE(other_witness_shapes_keep_existing_costs)
{
    for (const auto& [version, size, expected] : std::array{
             std::tuple{OP_0, size_t{20}, int64_t{1}},
             std::tuple{OP_0, size_t{32}, int64_t{0}},
             std::tuple{OP_1, size_t{32}, int64_t{0}},
             std::tuple{OP_2, size_t{20}, int64_t{0}},
             std::tuple{OP_2, size_t{31}, int64_t{0}},
             std::tuple{OP_2, size_t{33}, int64_t{0}},
             std::tuple{OP_3, size_t{32}, int64_t{0}},
             std::tuple{OP_16, size_t{32}, int64_t{0}}}) {
        ResourceTransaction fixture{1, Program(version, size)};
        BOOST_CHECK_EQUAL(fixture.Cost(), expected);
    }
    ResourceTransaction legacy{1, CScript{} << OP_CHECKSIG};
    BOOST_CHECK_EQUAL(legacy.Cost(), 0);
    legacy.tx.vout.emplace_back(1, CScript{} << OP_CHECKSIG);
    BOOST_CHECK_EQUAL(legacy.Cost(), 4);
}

BOOST_AUTO_TEST_CASE(nested_v2_is_not_a_native_verification)
{
    const CScript redeem{Program()};
    ResourceTransaction fixture{1, GetScriptForDestination(ScriptHash(redeem))};
    fixture.tx.vin[0].scriptSig = CScript{} << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK_EQUAL(fixture.Cost(), 0);
    fixture.tx.vin[0].scriptSig << OP_DUP; // malformed nested scriptSig
    BOOST_CHECK_EQUAL(fixture.Cost(), 0);
}

BOOST_AUTO_TEST_CASE(transaction_and_block_budget_boundaries)
{
    ResourceTransaction standard_limit{25}, standard_over{26};
    BOOST_CHECK_EQUAL(standard_limit.Cost(), 15625);
    BOOST_CHECK(standard_limit.Cost() <= MAX_STANDARD_TX_SIGOPS_COST);
    BOOST_CHECK_EQUAL(standard_over.Cost(), 16250);
    BOOST_CHECK(standard_over.Cost() > MAX_STANDARD_TX_SIGOPS_COST);
    ResourceTransaction block_limit{128}, block_over{129};
    BOOST_CHECK_EQUAL(block_limit.Cost(), 80000);
    BOOST_CHECK(block_limit.Cost() <= MAX_BLOCK_SIGOPS_COST);
    BOOST_CHECK_EQUAL(block_over.Cost(), 80625);
    BOOST_CHECK(block_over.Cost() > MAX_BLOCK_SIGOPS_COST);
    // These are accounting boundaries; RPC acceptance needs separate real-node tests.
}

BOOST_AUTO_TEST_CASE(coinbase_does_not_verify_a_prevout)
{
    ResourceTransaction fixture{0};
    fixture.tx.vin.resize(1);
    fixture.tx.vin[0].prevout.SetNull();
    fixture.tx.vin[0].scriptWitness.stack = {{1}, {2}};
    BOOST_REQUIRE(CTransaction{fixture.tx}.IsCoinBase());
    BOOST_CHECK_EQUAL(fixture.Cost(), 0);
    fixture.tx.vout.emplace_back(1, CScript{} << OP_CHECKSIG);
    BOOST_CHECK_EQUAL(fixture.Cost(), 4);
}

BOOST_AUTO_TEST_SUITE_END()
