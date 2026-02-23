// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <test/data/pqsig/kat_v1.json.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

#include <univalue.h>

BOOST_AUTO_TEST_SUITE(pqsig_tests)

namespace {

const UniValue& GetKatVectors()
{
    static UniValue vectors{UniValue::VARR};
    static bool loaded{false};
    if (!loaded) {
        UniValue root;
        BOOST_REQUIRE(root.read(json_tests::kat_v1));
        if (root.isArray()) {
            vectors = root.get_array();
        } else if (root.isObject()) {
            vectors = root.get_obj().find_value("vectors");
            BOOST_REQUIRE(vectors.isArray());
        } else {
            BOOST_FAIL("KAT root must be JSON object or array");
        }
        loaded = true;
    }
    return vectors;
}

} // namespace

BOOST_AUTO_TEST_CASE(pqsig_kat_vectors)
{
    const UniValue& vectors = GetKatVectors();
    BOOST_REQUIRE(vectors.isArray());

    for (unsigned int i = 0; i < vectors.get_array().size(); ++i) {
        const UniValue obj = vectors.get_array()[i].get_obj();
        const std::vector<uint8_t> msg = ParseHex(obj.find_value("msg32").get_str());
        const std::vector<uint8_t> sk = ParseHex(obj.find_value("sk_seed").get_str());
        const std::vector<uint8_t> pk = ParseHex(obj.find_value("pk_script33").get_str());
        std::vector<uint8_t> sig = ParseHex(obj.find_value("sig4480").get_str());

        BOOST_REQUIRE_EQUAL(msg.size(), pqsig::MSG32_SIZE);
        BOOST_REQUIRE_EQUAL(pk.size(), pqsig::PK_SCRIPT_SIZE);
        BOOST_REQUIRE_EQUAL(sig.size(), pqsig::SIG_SIZE);

        BOOST_CHECK(pqsig::PQSigVerify(sig, msg, pk));

        std::vector<uint8_t> regenerated(pqsig::SIG_SIZE);
        BOOST_CHECK(pqsig::PQSigSign(regenerated, msg, sk, pk));
        BOOST_CHECK_EQUAL_COLLECTIONS(regenerated.begin(), regenerated.end(), sig.begin(), sig.end());

        sig[0] ^= 0x01;
        BOOST_CHECK(!pqsig::PQSigVerify(sig, msg, pk));
    }
}

BOOST_AUTO_TEST_CASE(pqsig_envelope_metrics)
{
    const UniValue& vectors = GetKatVectors();
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE(!vectors.get_array().empty());

    const UniValue obj = vectors.get_array()[0].get_obj();
    const std::vector<uint8_t> msg = ParseHex(obj.find_value("msg32").get_str());
    const std::vector<uint8_t> sk = ParseHex(obj.find_value("sk_seed").get_str());
    const std::vector<uint8_t> pk = ParseHex(obj.find_value("pk_script33").get_str());

    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    BOOST_CHECK(pqsig::PQSigSign(sig, msg, sk, pk));
    const pqsig::PQSigMetrics sign_metrics = pqsig::GetLastPQSigMetrics();
    BOOST_CHECK_EQUAL(sign_metrics.hash_calls, 6027717U);
    BOOST_CHECK_EQUAL(sign_metrics.compression_calls, 6869634U);
    BOOST_CHECK_EQUAL(sign_metrics.outer_search_iters, 244170U);

    BOOST_CHECK(pqsig::PQSigVerify(sig, msg, pk));
    const pqsig::PQSigMetrics verify_metrics = pqsig::GetLastPQSigMetrics();
    BOOST_CHECK_EQUAL(verify_metrics.compression_calls, 1292U);
}

BOOST_AUTO_TEST_CASE(pqsig_rejects_malformed_inputs)
{
    const UniValue& vectors = GetKatVectors();
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE(!vectors.get_array().empty());

    const UniValue obj = vectors.get_array()[0].get_obj();
    const std::vector<uint8_t> msg = ParseHex(obj.find_value("msg32").get_str());
    const std::vector<uint8_t> sk = ParseHex(obj.find_value("sk_seed").get_str());
    std::vector<uint8_t> pk = ParseHex(obj.find_value("pk_script33").get_str());

    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    BOOST_CHECK(pqsig::PQSigSign(sig, msg, sk, pk));

    std::vector<uint8_t> short_sig(pqsig::SIG_SIZE - 1);
    BOOST_CHECK(!pqsig::PQSigVerify(short_sig, msg, pk));

    pk[0] = 0x7f;
    BOOST_CHECK(!pqsig::PQSigVerify(sig, msg, pk));
}

BOOST_AUTO_TEST_SUITE_END()
