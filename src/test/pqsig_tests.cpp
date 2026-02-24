// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <crypto/pqsig/params.h>
#include <test/data/pqsig/invalid_vectors.json.h>
#include <test/data/pqsig/kat_v1.json.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
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

const UniValue& GetInvalidVectors()
{
    static UniValue vectors{UniValue::VARR};
    static bool loaded{false};
    if (!loaded) {
        UniValue root;
        BOOST_REQUIRE(root.read(json_tests::invalid_vectors));
        vectors = root.get_obj().find_value("vectors");
        BOOST_REQUIRE(vectors.isArray());
        loaded = true;
    }
    return vectors;
}

const UniValue& FindKatVectorByName(const std::string& name)
{
    const UniValue& vectors = GetKatVectors();
    for (unsigned int i = 0; i < vectors.get_array().size(); ++i) {
        const UniValue& entry = vectors.get_array()[i];
        const UniValue obj = entry.get_obj();
        if (obj.find_value("name").get_str() == name) {
            return entry;
        }
    }
    throw std::runtime_error("missing KAT vector");
}

uint8_t ParseHexByte(const std::string& hex)
{
    const std::vector<uint8_t> parsed = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    return parsed[0];
}

void ApplyMutation(
    std::vector<uint8_t>& msg,
    std::vector<uint8_t>& pk,
    std::vector<uint8_t>& sig,
    const UniValue& mutation_obj)
{
    const std::string field = mutation_obj.find_value("field").get_str();
    const size_t offset = mutation_obj.find_value("offset").getInt<int>();
    const std::string op = mutation_obj.find_value("op").get_str();
    const uint8_t value = ParseHexByte(mutation_obj.find_value("value").get_str());

    std::vector<uint8_t>* target = nullptr;
    if (field == "msg32") {
        target = &msg;
    } else if (field == "pk_script33") {
        target = &pk;
    } else if (field == "sig4480") {
        target = &sig;
    } else {
        BOOST_FAIL("unknown mutation field");
    }

    BOOST_REQUIRE(offset < target->size());
    if (op == "set") {
        (*target)[offset] = value;
    } else if (op == "xor") {
        (*target)[offset] ^= value;
    } else {
        BOOST_FAIL("unknown mutation op");
    }
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
    const std::vector<uint8_t> pk = ParseHex(obj.find_value("pk_script33").get_str());

    std::vector<uint8_t> sig(pqsig::SIG_SIZE);
    BOOST_CHECK(pqsig::PQSigSign(sig, msg, sk, pk));

    std::vector<uint8_t> short_sig(pqsig::SIG_SIZE - 1);
    BOOST_CHECK(!pqsig::PQSigVerify(short_sig, msg, pk));

    const std::vector<uint8_t> short_msg(pqsig::MSG32_SIZE - 1, 0x00);
    BOOST_CHECK(!pqsig::PQSigVerify(sig, short_msg, pk));

    const std::vector<uint8_t> short_pk(pqsig::PK_SCRIPT_SIZE - 1, 0x00);
    BOOST_CHECK(!pqsig::PQSigVerify(sig, msg, short_pk));

    std::vector<uint8_t> bad_pk = pk;
    bad_pk[0] = 0x7f;
    BOOST_CHECK(!pqsig::PQSigVerify(sig, msg, bad_pk));

}

BOOST_AUTO_TEST_CASE(pqsig_invalid_corpus_vectors)
{
    const UniValue& invalid_vectors = GetInvalidVectors();
    BOOST_REQUIRE(invalid_vectors.isArray());

    for (unsigned int i = 0; i < invalid_vectors.get_array().size(); ++i) {
        const UniValue invalid_obj = invalid_vectors.get_array()[i].get_obj();
        const std::string base_name = invalid_obj.find_value("base").get_str();
        const UniValue base_obj = FindKatVectorByName(base_name).get_obj();

        std::vector<uint8_t> msg = ParseHex(base_obj.find_value("msg32").get_str());
        std::vector<uint8_t> pk = ParseHex(base_obj.find_value("pk_script33").get_str());
        std::vector<uint8_t> sig = ParseHex(base_obj.find_value("sig4480").get_str());

        const UniValue& mutations = invalid_obj.find_value("mutations");
        BOOST_REQUIRE(mutations.isArray());
        for (unsigned int j = 0; j < mutations.get_array().size(); ++j) {
            ApplyMutation(msg, pk, sig, mutations.get_array()[j].get_obj());
        }

        BOOST_CHECK_MESSAGE(
            !pqsig::PQSigVerify(sig, msg, pk),
            "invalid corpus vector unexpectedly verified");
    }
}

BOOST_AUTO_TEST_CASE(pqsig_signer_counter_bounds)
{
    const UniValue& vectors = GetKatVectors();
    BOOST_REQUIRE(vectors.isArray());
    BOOST_REQUIRE(!vectors.get_array().empty());

    const UniValue obj = vectors.get_array()[0].get_obj();
    const std::vector<uint8_t> msg = ParseHex(obj.find_value("msg32").get_str());
    const std::vector<uint8_t> sk = ParseHex(obj.find_value("sk_seed").get_str());
    const std::vector<uint8_t> pk = ParseHex(obj.find_value("pk_script33").get_str());
    std::vector<uint8_t> sig(pqsig::SIG_SIZE);

    BOOST_CHECK(!pqsig::PQSigSign(sig, msg, sk, pk, 0));
    BOOST_CHECK(!pqsig::PQSigSign(sig, msg, sk, pk, pqsig::params::SIGN_COUNTER_MAX + 1));
}

BOOST_AUTO_TEST_SUITE_END()
