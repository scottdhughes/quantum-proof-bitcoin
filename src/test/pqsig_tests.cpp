// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <crypto/pqsig/pqsig_internal.h>
#include <crypto/pqsig/params.h>
#include <test/data/pqsig/invalid_vectors.json.h>
#include <test/data/pqsig/kat_v1.json.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
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

struct PQSigCase
{
    std::vector<uint8_t> msg;
    std::vector<uint8_t> sk;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sig;
};

PQSigCase LoadKatCase(const UniValue& obj)
{
    PQSigCase testcase{
        ParseHex(obj.find_value("msg32").get_str()),
        ParseHex(obj.find_value("sk_seed").get_str()),
        ParseHex(obj.find_value("pk_script33").get_str()),
        ParseHex(obj.find_value("sig4480").get_str()),
    };

    BOOST_REQUIRE_EQUAL(testcase.msg.size(), pqsig::MSG32_SIZE);
    BOOST_REQUIRE_EQUAL(testcase.sk.size(), pqsig::MSG32_SIZE);
    BOOST_REQUIRE_EQUAL(testcase.pk.size(), pqsig::PK_SCRIPT_SIZE);
    BOOST_REQUIRE_EQUAL(testcase.sig.size(), pqsig::SIG_SIZE);
    return testcase;
}

void XorByte(std::vector<uint8_t>& bytes, const size_t offset, const uint8_t value = 0x01)
{
    BOOST_REQUIRE(offset < bytes.size());
    BOOST_REQUIRE(value != 0);
    bytes[offset] ^= value;
}

std::vector<size_t> StructuredMessageOffsets()
{
    return {0, pqsig::MSG32_SIZE / 2, pqsig::MSG32_SIZE - 1};
}

std::vector<size_t> StructuredPkOffsets()
{
    return {
        0,
        1,
        1 + (pqsig::params::N / 2),
        1 + pqsig::params::N,
        pqsig::PK_SCRIPT_SIZE - 1,
    };
}

std::vector<size_t> StructuredSigOffsets()
{
    std::vector<size_t> offsets{
        0,
        pqsig::params::SIG_R_SIZE - 1,
        pqsig::params::PORS_REVEAL_OFFSET,
        pqsig::params::PORS_REVEAL_OFFSET + (pqsig::params::PORS_REVEAL_SIZE / 2),
        pqsig::params::PORS_REVEAL_OFFSET + pqsig::params::PORS_REVEAL_SIZE - 1,
        pqsig::params::PORS_AUTH_OFFSET,
        pqsig::params::PORS_AUTH_OFFSET + (pqsig::params::PORS_AUTH_PAD_SIZE / 2),
        pqsig::params::PORS_AUTH_OFFSET + pqsig::params::PORS_AUTH_PAD_SIZE - 1,
        pqsig::params::HT_OFFSET,
        pqsig::params::HT_OFFSET + pqsig::params::HT_AUTH_SIZE - 1,
        pqsig::params::HT_OFFSET + pqsig::params::HT_LAYER_SIZE + pqsig::params::HT_AUTH_SIZE,
    };

    for (size_t layer = 0; layer < pqsig::params::D; ++layer) {
        const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
        const size_t count_offset = layer_offset + pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
        for (size_t i = 0; i < pqsig::params::HT_COUNTER_SIZE; ++i) {
            offsets.push_back(count_offset + i);
        }
    }

    return offsets;
}

std::vector<size_t> LeadingTrailingOffsets(const size_t start, const size_t size, const size_t window)
{
    const size_t span = std::min(window, size);
    std::vector<size_t> offsets;
    offsets.reserve(span * 2);

    for (size_t i = 0; i < span; ++i) {
        offsets.push_back(start + i);
    }
    for (size_t i = size - span; i < size; ++i) {
        offsets.push_back(start + i);
    }

    std::sort(offsets.begin(), offsets.end());
    offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());
    return offsets;
}

std::vector<size_t> TargetedHypertreeAuthOffsets()
{
    std::vector<size_t> offsets;
    for (size_t layer = 0; layer < pqsig::params::D; ++layer) {
        const size_t layer_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE;
        const std::vector<size_t> window = LeadingTrailingOffsets(layer_offset, pqsig::params::HT_AUTH_SIZE, 8);
        offsets.insert(offsets.end(), window.begin(), window.end());
    }
    return offsets;
}

std::vector<size_t> TargetedHypertreeWotsOffsets()
{
    std::vector<size_t> offsets;
    for (size_t layer = 0; layer < pqsig::params::D; ++layer) {
        const size_t wots_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE + pqsig::params::HT_AUTH_SIZE;
        const std::vector<size_t> window = LeadingTrailingOffsets(wots_offset, pqsig::params::HT_WOTS_SIZE, 8);
        offsets.insert(offsets.end(), window.begin(), window.end());
    }
    return offsets;
}

std::vector<size_t> TargetedHypertreeCountOffsets()
{
    std::vector<size_t> offsets;
    for (size_t layer = 0; layer < pqsig::params::D; ++layer) {
        const size_t count_offset = pqsig::params::HT_OFFSET + layer * pqsig::params::HT_LAYER_SIZE +
            pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE;
        for (size_t i = 0; i < pqsig::params::HT_COUNTER_SIZE; ++i) {
            offsets.push_back(count_offset + i);
        }
    }
    return offsets;
}

std::string JoinOffsets(const std::vector<size_t>& offsets)
{
    if (offsets.empty()) return "none";

    std::string out;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (!out.empty()) out += ", ";
        out += strprintf("%u", static_cast<unsigned int>(offsets[i]));
    }
    return out;
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

BOOST_AUTO_TEST_CASE(pqsig_invalid_corpus_minimum_coverage)
{
    const UniValue& invalid_vectors = GetInvalidVectors();
    BOOST_REQUIRE(invalid_vectors.isArray());
    BOOST_REQUIRE_GE(invalid_vectors.get_array().size(), 10U);

    bool has_msg32{false};
    bool has_pk_alg_id{false};
    bool has_pk_seed{false};
    bool has_pk_root{false};
    bool has_sig_r{false};
    bool has_sig_pors_reveal{false};
    bool has_sig_pors_auth{false};
    bool has_sig_layer_auth{false};
    bool has_sig_layer_wots{false};
    bool has_sig_layer_count{false};

    for (unsigned int i = 0; i < invalid_vectors.get_array().size(); ++i) {
        const UniValue invalid_obj = invalid_vectors.get_array()[i].get_obj();
        const UniValue& mutations = invalid_obj.find_value("mutations");
        BOOST_REQUIRE(mutations.isArray());

        for (unsigned int j = 0; j < mutations.get_array().size(); ++j) {
            const UniValue mutation = mutations.get_array()[j].get_obj();
            const std::string field = mutation.find_value("field").get_str();
            const size_t offset = mutation.find_value("offset").getInt<int>();

            if (field == "msg32") {
                has_msg32 = true;
                continue;
            }
            if (field == "pk_script33") {
                if (offset == 0) {
                    has_pk_alg_id = true;
                } else if (offset < 1 + pqsig::params::N) {
                    has_pk_seed = true;
                } else {
                    has_pk_root = true;
                }
                continue;
            }
            if (field != "sig4480") {
                BOOST_FAIL("unexpected invalid corpus field");
            }

            if (offset < pqsig::params::SIG_R_SIZE) {
                has_sig_r = true;
                continue;
            }
            if (offset < pqsig::params::PORS_AUTH_OFFSET) {
                has_sig_pors_reveal = true;
                continue;
            }
            if (offset < pqsig::params::HT_OFFSET) {
                has_sig_pors_auth = true;
                continue;
            }

            const size_t layer_offset = (offset - pqsig::params::HT_OFFSET) % pqsig::params::HT_LAYER_SIZE;
            if (layer_offset < pqsig::params::HT_AUTH_SIZE) {
                has_sig_layer_auth = true;
            } else if (layer_offset < pqsig::params::HT_AUTH_SIZE + pqsig::params::HT_WOTS_SIZE) {
                has_sig_layer_wots = true;
            } else {
                has_sig_layer_count = true;
            }
        }
    }

    BOOST_CHECK(has_msg32);
    BOOST_CHECK(has_pk_alg_id);
    BOOST_CHECK(has_pk_seed);
    BOOST_CHECK(has_pk_root);
    BOOST_CHECK(has_sig_r);
    BOOST_CHECK(has_sig_pors_reveal);
    BOOST_CHECK(has_sig_pors_auth);
    BOOST_CHECK(has_sig_layer_auth);
    BOOST_CHECK(has_sig_layer_wots);
    BOOST_CHECK(has_sig_layer_count);
}

BOOST_AUTO_TEST_CASE(pqsig_selected_structural_mutations_fail)
{
    const PQSigCase testcase = LoadKatCase(FindKatVectorByName("kat_01").get_obj());
    BOOST_REQUIRE(pqsig::PQSigVerify(testcase.sig, testcase.msg, testcase.pk));

    for (const size_t offset : StructuredMessageOffsets()) {
        std::vector<uint8_t> mutated_msg = testcase.msg;
        XorByte(mutated_msg, offset);
        BOOST_CHECK_MESSAGE(
            !pqsig::PQSigVerify(testcase.sig, mutated_msg, testcase.pk),
            strprintf("message mutation offset %u unexpectedly verified", static_cast<unsigned int>(offset)));
    }

    for (const size_t offset : StructuredPkOffsets()) {
        std::vector<uint8_t> mutated_pk = testcase.pk;
        XorByte(mutated_pk, offset);
        BOOST_CHECK_MESSAGE(
            !pqsig::PQSigVerify(testcase.sig, testcase.msg, mutated_pk),
            strprintf("pk mutation offset %u unexpectedly verified", static_cast<unsigned int>(offset)));
    }

    for (const size_t offset : StructuredSigOffsets()) {
        std::vector<uint8_t> mutated_sig = testcase.sig;
        XorByte(mutated_sig, offset);
        BOOST_CHECK_MESSAGE(
            !pqsig::PQSigVerify(mutated_sig, testcase.msg, testcase.pk),
            strprintf("signature mutation offset %u unexpectedly verified", static_cast<unsigned int>(offset)));
    }
}

BOOST_AUTO_TEST_CASE(pqsig_targeted_hypertree_region_mutation_sweep)
{
    const PQSigCase testcase = LoadKatCase(FindKatVectorByName("kat_01").get_obj());
    BOOST_REQUIRE(pqsig::PQSigVerify(testcase.sig, testcase.msg, testcase.pk));

    std::vector<size_t> accepted_auth_offsets;
    for (const size_t offset : TargetedHypertreeAuthOffsets()) {
        std::vector<uint8_t> mutated_sig = testcase.sig;
        XorByte(mutated_sig, offset);
        if (pqsig::PQSigVerify(mutated_sig, testcase.msg, testcase.pk)) {
            accepted_auth_offsets.push_back(offset);
        }
    }

    std::vector<size_t> accepted_wots_offsets;
    for (const size_t offset : TargetedHypertreeWotsOffsets()) {
        std::vector<uint8_t> mutated_sig = testcase.sig;
        XorByte(mutated_sig, offset);
        if (pqsig::PQSigVerify(mutated_sig, testcase.msg, testcase.pk)) {
            accepted_wots_offsets.push_back(offset);
        }
    }

    std::vector<size_t> accepted_count_offsets;
    for (const size_t offset : TargetedHypertreeCountOffsets()) {
        std::vector<uint8_t> mutated_sig = testcase.sig;
        XorByte(mutated_sig, offset);
        if (pqsig::PQSigVerify(mutated_sig, testcase.msg, testcase.pk)) {
            accepted_count_offsets.push_back(offset);
        }
    }

    constexpr size_t EXPECTED_ISSUE_48_OFFSET =
        pqsig::params::HT_OFFSET + 2 * pqsig::params::HT_LAYER_SIZE + pqsig::params::HT_AUTH_SIZE;
    const std::vector<size_t> targeted_wots_offsets = TargetedHypertreeWotsOffsets();

    BOOST_CHECK_MESSAGE(
        std::find(targeted_wots_offsets.begin(), targeted_wots_offsets.end(), EXPECTED_ISSUE_48_OFFSET) != targeted_wots_offsets.end(),
        strprintf("targeted WOTS sweep omitted known issue-48 offset %u", static_cast<unsigned int>(EXPECTED_ISSUE_48_OFFSET)));

    BOOST_TEST_MESSAGE(strprintf("targeted auth accepted offsets: %s", JoinOffsets(accepted_auth_offsets)));
    BOOST_TEST_MESSAGE(strprintf("targeted wots accepted offsets: %s", JoinOffsets(accepted_wots_offsets)));
    BOOST_TEST_MESSAGE(strprintf("targeted count accepted offsets: %s", JoinOffsets(accepted_count_offsets)));

    BOOST_CHECK_MESSAGE(
        accepted_auth_offsets.empty(),
        strprintf("auth-path mutation offsets unexpectedly verified: %s", JoinOffsets(accepted_auth_offsets)));
    BOOST_CHECK_MESSAGE(
        accepted_count_offsets.empty(),
        strprintf("count-field mutation offsets unexpectedly verified: %s", JoinOffsets(accepted_count_offsets)));
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

    std::vector<uint8_t> short_sk(pqsig::MSG32_SIZE - 1, 0x42);
    BOOST_CHECK(!pqsig::PQSigSign(sig, msg, short_sk, pk));
    BOOST_CHECK(!pqsig::PQSigSign(sig, msg, sk, pk, 0));
    BOOST_CHECK(!pqsig::PQSigSign(sig, msg, sk, pk, pqsig::params::SIGN_COUNTER_MAX + 1));
}

BOOST_AUTO_TEST_SUITE_END()
