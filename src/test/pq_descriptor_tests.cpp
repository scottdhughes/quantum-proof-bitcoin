// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pqsig/pqsig.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(pq_descriptor_tests)

namespace {

std::string WithChecksum(const std::string& desc)
{
    return desc + "#" + GetDescriptorChecksum(desc);
}

CScript MakePqWitnessScript(const std::vector<unsigned char>& pk_script)
{
    return CScript() << pk_script << OP_CHECKSIG;
}

void CheckUnparsable(const std::string& desc, const std::string& expected_error)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(desc, provider, error);
    BOOST_CHECK(parsed.empty());
    BOOST_CHECK_EQUAL(error, expected_error);
}

} // namespace

BOOST_AUTO_TEST_CASE(roundtrip_expand_and_infer)
{
    std::vector<unsigned char> pk_script(pqsig::PK_SCRIPT_SIZE, 0x11);
    pk_script[0] = pqsig::ALG_ID_RC2;
    const std::string desc_body = "pq(" + HexStr(pk_script) + ")";
    const std::string desc = WithChecksum(desc_body);

    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(desc, provider, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    BOOST_CHECK_EQUAL(parsed[0]->ToString(), desc);
    BOOST_CHECK(parsed[0]->IsSolvable());
    BOOST_CHECK(!parsed[0]->IsRange());
    BOOST_CHECK_EQUAL(parsed[0]->GetOutputType(), OutputType::BECH32);
    BOOST_CHECK_EQUAL(parsed[0]->ScriptSize(), 34);
    BOOST_CHECK_EQUAL(parsed[0]->MaxSatisfactionElems(), 2);

    std::string priv_desc;
    BOOST_CHECK(!parsed[0]->ToPrivateString(provider, priv_desc));

    FlatSigningProvider expand_out;
    std::vector<CScript> output_scripts;
    BOOST_REQUIRE(parsed[0]->Expand(0, DUMMY_SIGNING_PROVIDER, output_scripts, expand_out));
    BOOST_REQUIRE_EQUAL(output_scripts.size(), 1U);

    const CScript witness_script = MakePqWitnessScript(pk_script);
    const CScript script_pubkey = GetScriptForDestination(WitnessV0ScriptHash(witness_script));
    BOOST_CHECK_EQUAL(HexStr(output_scripts[0]), HexStr(script_pubkey));
    BOOST_CHECK(expand_out.scripts.contains(CScriptID(witness_script)));
    BOOST_CHECK_EQUAL(HexStr(expand_out.scripts.at(CScriptID(witness_script))), HexStr(witness_script));
    BOOST_CHECK_EQUAL(parsed[0]->MaxSatisfactionWeight(false), GetSizeOfCompactSize(pqsig::SIG_SIZE) + pqsig::SIG_SIZE + GetSizeOfCompactSize(witness_script.size()) + witness_script.size());

    FlatSigningProvider infer_provider;
    infer_provider.scripts.emplace(CScriptID(witness_script), witness_script);
    auto inferred = InferDescriptor(script_pubkey, infer_provider);
    BOOST_REQUIRE(inferred);
    BOOST_CHECK_EQUAL(inferred->ToString(), desc);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_inputs)
{
    const std::string valid_hex = std::string("01") + std::string((pqsig::PK_SCRIPT_SIZE - 1) * 2, '1');
    const std::string bad_alg_hex = std::string(pqsig::PK_SCRIPT_SIZE * 2, '2');

    CheckUnparsable("pq(zz)", "pq(): PK_script must be valid hex");
    CheckUnparsable("pq(01)", strprintf("pq(): PK_script must be exactly %u bytes", static_cast<unsigned>(pqsig::PK_SCRIPT_SIZE)));
    CheckUnparsable("pq(" + bad_alg_hex + ")", strprintf("pq(): PK_script must use ALG_ID=0x%02x", pqsig::ALG_ID_RC2));
    CheckUnparsable("wsh(pq(" + valid_hex + "))", "Can only have pq() at top level");
}

BOOST_AUTO_TEST_SUITE_END()
