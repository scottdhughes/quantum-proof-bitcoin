#!/usr/bin/env python3
'''Apply the PQBTC SHRINCS-v0 regtest-devnet integration in a real checkout.

This script is intentionally deterministic and idempotent. It:
- vendors the exact pinned libshrincs WOTS+C seam with git-blob verification;
- moves the project-owned complete verifier into the node crypto library;
- activates the dedicated witness-v2 path only when the regtest consensus
  parameter is true;
- removes the external-checkout/test-only build gate;
- adds interpreter-level signed KAT coverage.

It does not activate SHRINCS on mainnet, testnet, testnet4, or signet.
'''

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PIN = "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5"
RAW = f"https://raw.githubusercontent.com/remix7531/libshrincs/{PIN}"


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text()
    count = text.count(old)
    if count == 0:
        if new in text:
            return
        raise RuntimeError(f"{path}: expected replacement anchor not found")
    if count != 1:
        raise RuntimeError(f"{path}: replacement anchor occurred {count} times")
    target.write_text(text.replace(old, new, 1))


def remove_once(path: str, block: str) -> None:
    replace_once(path, block, "")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def vendor(remote_path: str, local_path: str, expected_blob: str) -> None:
    with urllib.request.urlopen(f"{RAW}/{remote_path}", timeout=60) as response:
        data = response.read()
    actual = git_blob_sha(data)
    if actual != expected_blob:
        raise RuntimeError(
            f"{remote_path}: git blob mismatch: expected {expected_blob}, got {actual}"
        )
    target = ROOT / local_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


# 1. Project-owned full verifier: move from research harness into the node tree.
for name in ("full_verify.c", "stateful_verify.c", "stateless_verify.c"):
    source = ROOT / "contrib" / "shrincs-ref" / name
    if not source.exists():
        raise RuntimeError(f"missing project verifier source: {source}")
    destination = ROOT / "src" / "crypto" / "shrincs" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)

write(
    "src/crypto/shrincs/verify.h",
    r'''// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_SHRINCS_VERIFY_H
#define BITCOIN_CRYPTO_SHRINCS_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify one signature under the frozen PQBTC-SHRINCS-v0 profile.
 *
 * Returns 1 on success and 0 on every malformed, unsupported, or invalid input.
 * The accepted public-key size is exactly 48 bytes. Accepted signatures are
 * the canonical current-profile stateful lengths 538 + 16*d for 1 <= d <= 255
 * or the exact 5,776-byte stateless recovery encoding.
 */
int pqbtc_shrincs_verify(const uint8_t* public_key,
                         size_t public_key_len,
                         const uint8_t* signature,
                         size_t signature_len,
                         const uint8_t* message,
                         size_t message_len,
                         const uint8_t* context,
                         size_t context_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_CRYPTO_SHRINCS_VERIFY_H
''',
)

# 2. Vendor exactly the libshrincs component seam proved against our vectors.
vendor("src/sha256.c", "src/crypto/shrincs/third_party/libshrincs/src/sha256.c",
       "4df4d8a9cb394fcd2c6aa96bba2f0af8afb0bdb4")
vendor("src/thash.c", "src/crypto/shrincs/third_party/libshrincs/src/thash.c",
       "0bb56260f496882473f04b9322a5d2ec72e5e3ee")
vendor("src/util.c", "src/crypto/shrincs/third_party/libshrincs/src/util.c",
       "a67255bc7955783d1927ad710ce7a2a7aa5c8b84")
vendor("src/wots.c", "src/crypto/shrincs/third_party/libshrincs/src/wots.c",
       "10fd0c6f418fc09227bbd58185aac594e3b8be83")
vendor("include/sha256.h", "src/crypto/shrincs/third_party/libshrincs/include/sha256.h",
       "4b060ef4cf46c4bc1e9cbc8588c26c4c8cbe880c")
vendor("include/thash.h", "src/crypto/shrincs/third_party/libshrincs/include/thash.h",
       "6f92ec435549d2c767d45aa469ce114947a8eb05")
vendor("include/util.h", "src/crypto/shrincs/third_party/libshrincs/include/util.h",
       "312630418f859ad31b7372b4bec394f166e5fd22")
vendor("include/wots.h", "src/crypto/shrincs/third_party/libshrincs/include/wots.h",
       "5da295aa2246a0dd4424207cce1f287a0631b9b1")
vendor("LICENSE", "src/crypto/shrincs/third_party/libshrincs/LICENSE",
       "66b873f6b77c1782f9e58f94e2364f22e8974105")

write(
    "src/crypto/shrincs/third_party/libshrincs/README.pqbtc.md",
    f'''# Vendored libshrincs component seam

Upstream: `https://github.com/remix7531/libshrincs`

Pinned commit: `{PIN}`

This directory contains only the portable WOTS+C/SHA-256 component seam used
by the PQBTC-SHRINCS-v0 verifier:

- `src/sha256.c`
- `src/thash.c`
- `src/util.c`
- `src/wots.c`
- their four public headers
- upstream MIT license

The full current-profile stateful and stateless verifiers are project-owned
sources in `src/crypto/shrincs/`. This vendoring does not claim that upstream
`libshrincs` is a complete SHRINCS implementation.
''',
)

# 3. Build the verifier into bitcoin_crypto, and the transaction envelope into consensus.
replace_once(
    "src/crypto/CMakeLists.txt",
    "  pqsig/pqsig.cpp\n  ../support/cleanse.cpp\n",
    '''  pqsig/pqsig.cpp
  shrincs/full_verify.c
  shrincs/stateful_verify.c
  shrincs/stateless_verify.c
  shrincs/third_party/libshrincs/src/sha256.c
  shrincs/third_party/libshrincs/src/thash.c
  shrincs/third_party/libshrincs/src/util.c
  shrincs/third_party/libshrincs/src/wots.c
  ../support/cleanse.cpp
''',
)
replace_once(
    "src/crypto/CMakeLists.txt",
    '''target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)

''',
    '''target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)

target_include_directories(bitcoin_crypto
  BEFORE PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/shrincs/third_party/libshrincs/include
)

''',
)
replace_once(
    "src/CMakeLists.txt",
    "  script/interpreter.cpp\n  script/script.cpp\n",
    "  script/interpreter.cpp\n  script/shrincs_tx_v0.cpp\n  script/script.cpp\n",
)

# 4. Regtest-only consensus activation. Other networks retain the default false.
replace_once(
    "src/consensus/params.h",
    '''    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;
''',
    '''    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    /**
     * Enable the frozen PQBTC-SHRINCS-v0 witness-v2 spend semantics.
     *
     * This is true only for the private regtest/devnet profile. Mainnet,
     * testnet, testnet4, and signet remain false.
     */
    bool shrincs_v0{false};
''',
)
replace_once(
    "src/kernel/chainparams.cpp",
    '''        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
''',
    '''        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.shrincs_v0 = true;
        consensus.nSubsidyHalvingInterval = 150;
''',
)

# 5. Freeze the regtest chain identifier already used by the authenticated KAT.
replace_once(
    "src/script/shrincs_tx_v0.h",
    '''inline constexpr std::string_view SIGNING_CONTEXT{"PQBTC/SHRINCS/TXSIG/v0"};

''',
    '''inline constexpr std::string_view SIGNING_CONTEXT{"PQBTC/SHRINCS/TXSIG/v0"};
inline constexpr std::string_view REGTEST_CHAIN_ID_LABEL{"PQBTC-SHRINCS-TX-V0-TEST-CHAIN"};

''',
)
replace_once(
    "src/script/shrincs_tx_v0.h",
    '''/** Tagged commitment to one exact 48-byte current-draft SHRINCS public key. */
std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key);
''',
    '''/** Fixed chain identifier for the private regtest/devnet activation. */
uint256 RegtestChainId();

/** Tagged commitment to one exact 48-byte current-draft SHRINCS public key. */
std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key);
''',
)
replace_once(
    "src/script/shrincs_tx_v0.cpp",
    '''std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key)
{
''',
    '''uint256 RegtestChainId()
{
    HashWriter writer;
    writer.write(std::as_bytes(std::span<const char>{
        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));
    return writer.GetSHA256();
}

std::optional<uint256> OutputCommitment(std::span<const unsigned char> public_key)
{
''',
)

# 6. Add a dedicated checker method and script flag. No ECDSA/Schnorr/rc2 fallback.
replace_once(
    "src/script/interpreter.h",
    '''    // Internal replacement-path enablement for the first positive PQ-native
    // witness-v1 replacement-script-hash seam.
    SCRIPT_VERIFY_PQ_REPLACEMENT_V1_SCRIPTHASH = (1U << 22),

    // Constants to point to the highest flag in use. Add new flags above this line.
''',
    '''    // Internal replacement-path enablement for the first positive PQ-native
    // witness-v1 replacement-script-hash seam.
    SCRIPT_VERIFY_PQ_REPLACEMENT_V1_SCRIPTHASH = (1U << 22),

    // Enable the dedicated PQBTC-SHRINCS-v0 native witness-v2 spend path.
    SCRIPT_VERIFY_SHRINCS_V0 = (1U << 23),

    // Constants to point to the highest flag in use. Add new flags above this line.
''',
)
replace_once(
    "src/script/interpreter.h",
    '''    virtual bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const
    {
        return false;
    }

    virtual bool CheckLockTime''',
    '''    virtual bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const
    {
        return false;
    }

    virtual bool CheckSHRINCSSignature(std::span<const unsigned char> sig,
                                      std::span<const unsigned char> pubkey,
                                      ScriptError* serror = nullptr) const
    {
        return false;
    }

    virtual bool CheckLockTime''',
)
replace_once(
    "src/script/interpreter.h",
    '''    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override;
    bool CheckLockTime''',
    '''    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override;
    bool CheckSHRINCSSignature(std::span<const unsigned char> sig,
                              std::span<const unsigned char> pubkey,
                              ScriptError* serror = nullptr) const override;
    bool CheckLockTime''',
)
replace_once(
    "src/script/interpreter.h",
    '''    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override
    {
        return m_checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror);
    }

    bool CheckLockTime''',
    '''    bool CheckSchnorrSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override
    {
        return m_checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror);
    }

    bool CheckSHRINCSSignature(std::span<const unsigned char> sig,
                              std::span<const unsigned char> pubkey,
                              ScriptError* serror = nullptr) const override
    {
        return m_checker.CheckSHRINCSSignature(sig, pubkey, serror);
    }

    bool CheckLockTime''',
)

replace_once(
    "src/script/interpreter.cpp",
    '''#include <crypto/pqsig/pqsig.h>
#include <crypto/ripemd160.h>
''',
    '''#include <crypto/pqsig/pqsig.h>
#include <crypto/ripemd160.h>
#include <crypto/shrincs/verify.h>
''',
)
replace_once(
    "src/script/interpreter.cpp",
    '''#include <pubkey.h>
#include <script/script.h>
''',
    '''#include <pubkey.h>
#include <script/script.h>
#include <script/shrincs_tx_v0.h>
''',
)
replace_once(
    "src/script/interpreter.cpp",
    '''template <class T>
bool GenericTransactionSignatureChecker<T>::CheckLockTime(const CScriptNum& nLockTime) const
{
''',
    '''template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSHRINCSSignature(
    std::span<const unsigned char> sig,
    std::span<const unsigned char> pubkey,
    ScriptError* serror) const
{
    if (pubkey.size() != shrincs_tx_v0::PUBLIC_KEY_BYTES) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    if (!shrincs_tx_v0::ClassifySignature(sig.size())) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    if (txdata == nullptr || !txdata->m_spent_outputs_ready) {
        return HandleMissingData(m_mdb);
    }

    const std::optional<uint256> sighash{shrincs_tx_v0::SignatureHash(
        *txTo,
        std::span<const CTxOut>{txdata->m_spent_outputs.data(), txdata->m_spent_outputs.size()},
        nIn,
        shrincs_tx_v0::RegtestChainId())};
    if (!sighash) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    const std::string_view context{shrincs_tx_v0::SIGNING_CONTEXT};
    if (pqbtc_shrincs_verify(
            pubkey.data(),
            pubkey.size(),
            sig.data(),
            sig.size(),
            sighash->begin(),
            sighash->size(),
            reinterpret_cast<const uint8_t*>(context.data()),
            context.size()) != 1) {
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }
    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckLockTime(const CScriptNum& nLockTime) const
{
''',
)

replace_once(
    "src/script/interpreter.cpp",
    '''    } else if (!is_p2sh && CScript::IsPayToAnchor(witversion, program)) {
        return true;
''',
    '''    } else if (witversion == shrincs_tx_v0::PROPOSED_WITNESS_VERSION &&
               program.size() == shrincs_tx_v0::PROGRAM_BYTES &&
               !is_p2sh &&
               (flags & SCRIPT_VERIFY_SHRINCS_V0)) {
        const std::optional<shrincs_tx_v0::ParsedWitness> parsed{
            shrincs_tx_v0::ParseWitness(witness, program)};
        if (!parsed) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        if (!checker.CheckSHRINCSSignature(parsed->signature, parsed->public_key, serror)) {
            return false;
        }
        return set_success(serror);
    } else if (!is_p2sh && CScript::IsPayToAnchor(witversion, program)) {
        return true;
''',
)

# 7. Block and mempool activation use the chain parameter, not global standard flags.
replace_once(
    "src/validation.cpp",
    '''    constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // Check input scripts and signatures.
''',
    '''    unsigned int scriptVerifyFlags{STANDARD_SCRIPT_VERIFY_FLAGS};
    if (m_active_chainstate.m_chainman.GetConsensus().shrincs_v0) {
        scriptVerifyFlags |= SCRIPT_VERIFY_SHRINCS_V0;
    }

    // Check input scripts and signatures.
''',
)
replace_once(
    "src/validation.cpp",
    '''    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_TAPROOT)) {
        flags |= SCRIPT_VERIFY_PQ_REPLACEMENT_V1_SCRIPTHASH;
    }

    return flags;
''',
    '''    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_TAPROOT)) {
        flags |= SCRIPT_VERIFY_PQ_REPLACEMENT_V1_SCRIPTHASH;
    }

    if (consensusparams.shrincs_v0) {
        flags |= SCRIPT_VERIFY_SHRINCS_V0;
    }

    return flags;
''',
)

# 8. Remove the external-checkout/test-only build gate and always run signed KATs.
replace_once(
    "src/test/CMakeLists.txt",
    '''option(PQBTC_ENABLE_LEGACY_UNIT_TESTS "Build legacy pre-PQ unit suites in addition to PQ-first suites" OFF)
option(PQBTC_ENABLE_SHRINCS_SIGNED_SEAM_TESTS "Build the research-only native SHRINCS transaction signed-seam suite" OFF)
set(PQBTC_LIBSHRINCS_SOURCE_DIR "" CACHE PATH "Path to the pinned libshrincs checkout for signed-seam tests")
''',
    '''option(PQBTC_ENABLE_LEGACY_UNIT_TESTS "Build legacy pre-PQ unit suites in addition to PQ-first suites" OFF)
''',
)
replace_once(
    "src/test/CMakeLists.txt",
    '''  shrincs_tx_v0_tests.cpp
  peerman_tests.cpp
''',
    '''  shrincs_tx_v0_tests.cpp
  shrincs_tx_v0_signed_seam_tests.cpp
  peerman_tests.cpp
''',
)
replace_once(
    "src/test/CMakeLists.txt",
    '''    shrincs_tx_v0_tests.cpp
    script_tests.cpp
''',
    '''    shrincs_tx_v0_tests.cpp
    shrincs_tx_v0_signed_seam_tests.cpp
    script_tests.cpp
''',
)
remove_once(
    "src/test/CMakeLists.txt",
    '''if(PQBTC_ENABLE_SHRINCS_SIGNED_SEAM_TESTS)
  list(APPEND TEST_PQBTC_SOURCES shrincs_tx_v0_signed_seam_tests.cpp)
endif()

''',
)
remove_once(
    "src/test/CMakeLists.txt",
    '''# The candidate SHRINCS transaction component is deliberately compiled only
# into the test binary. It is not linked into bitcoin_consensus, bitcoin_node,
# the wallet, RPC, policy, mining, or release executables.
target_sources(test_pqbtc
  PRIVATE
    ../script/shrincs_tx_v0.cpp
)

''',
)
start = '''if(PQBTC_ENABLE_SHRINCS_SIGNED_SEAM_TESTS)
  set(SHRINCS_SIGNED_SEAM_EXTERNAL_SOURCES
'''
end = '''  target_include_directories(test_pqbtc PRIVATE ${PQBTC_LIBSHRINCS_SOURCE_DIR}/include)
endif()

'''
test_cmake = (ROOT / "src/test/CMakeLists.txt").read_text()
if start in test_cmake:
    begin = test_cmake.index(start)
    finish = test_cmake.index(end, begin) + len(end)
    test_cmake = test_cmake[:begin] + test_cmake[finish:]
    (ROOT / "src/test/CMakeLists.txt").write_text(test_cmake)
elif "PQBTC_LIBSHRINCS_SOURCE_DIR" in test_cmake:
    raise RuntimeError("src/test/CMakeLists.txt: external SHRINCS block changed unexpectedly")

replace_once(
    "src/test/CMakeLists.txt",
    '''  bitcoin_node
  bitcoin_consensus
  minisketch
''',
    '''  bitcoin_node
  bitcoin_consensus
  bitcoin_crypto
  minisketch
''',
)

# 9. Interpreter-level KAT proves the activated witness path, not merely direct ABI calls.
replace_once(
    "src/test/shrincs_tx_v0_signed_seam_tests.cpp",
    '''#include <primitives/transaction.h>
#include <script/script.h>
''',
    '''#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
''',
)
replace_once(
    "src/test/shrincs_tx_v0_signed_seam_tests.cpp",
    '''BOOST_AUTO_TEST_SUITE_END()''',
    r'''BOOST_AUTO_TEST_CASE(regtest_witness_v2_executes_full_verifier)
{
    const SignedVectors signed_vectors{LoadSignedVectors()};
    const EnvelopeCase envelope{BuildEnvelopeCase(signed_vectors.public_key)};

    auto run = [&](const std::vector<unsigned char>& signature,
                   const std::vector<unsigned char>& public_key,
                   unsigned int flags,
                   ScriptError* error) {
        CMutableTransaction mutable_tx{envelope.tx};
        mutable_tx.vin[0].scriptWitness.stack = {signature, public_key};
        const CTransaction tx{mutable_tx};

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{envelope.spent_outputs}, /*force=*/true);
        TransactionSignatureChecker checker{
            &tx,
            /*nInIn=*/0,
            envelope.spent_outputs[0].nValue,
            txdata,
            MissingDataBehavior::ASSERT_FAIL};

        return VerifyScript(
            tx.vin[0].scriptSig,
            envelope.spent_outputs[0].scriptPubKey,
            &tx.vin[0].scriptWitness,
            flags,
            checker,
            error);
    };

    constexpr unsigned int active_flags{
        SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SHRINCS_V0};

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_CHECK(run(
        signed_vectors.stateful_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(run(
        signed_vectors.stateless_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    std::vector<unsigned char> mutated_signature{signed_vectors.stateful_signature};
    mutated_signature[mutated_signature.size() / 2] ^= 1;
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!run(
        mutated_signature,
        signed_vectors.public_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_EVAL_FALSE);

    std::vector<unsigned char> wrong_key{signed_vectors.public_key};
    wrong_key[0] ^= 1;
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!run(
        signed_vectors.stateful_signature,
        wrong_key,
        active_flags,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    // Without the regtest activation flag, witness v2 retains ordinary
    // future-version behavior. This prevents accidental inherited-network
    // activation by the verifier merely being present in the binary.
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(run(
        signed_vectors.stateful_signature,
        signed_vectors.public_key,
        SCRIPT_VERIFY_WITNESS,
        &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()''',
)

# 10. Keep an executable declaration of what is and is not activated.
write(
    "docs/PQBTC_SHRINCS_REGTEST_DEVNET.md",
    r'''# PQBTC SHRINCS-v0 regtest devnet

This branch removes the artificial test-only build gates and makes the frozen
SHRINCS-v0 verifier part of the node. The spend path is active **only** when the
chain's consensus parameters set `shrincs_v0=true`; currently that is private
`-regtest` only.

## Spend format

```text
scriptPubKey:
    OP_2 PUSH32 TaggedHash("PQBTC/SHRINCS/OUTPUT/v0", public_key_48)

witness:
    canonical_signature
    public_key_48
```

The accepted signatures are the frozen current-profile encodings:

- stateful: `538 + 16*d` bytes for `1 <= d <= 255`;
- stateless recovery: exactly `5,776` bytes.

The transaction digest is fixed `SIGHASH_ALL`, commits to every input prevout,
amount, script, and sequence, every output, the selected input, and the private
regtest chain identifier. There is no ECDSA, Schnorr, rc2, ML-DSA, or
unknown-algorithm fallback.

## Build and mine

```bash
cmake -S . -B build -G Ninja \
  -DBUILD_TESTS=ON \
  -DENABLE_WALLET=ON \
  -DENABLE_IPC=OFF
cmake --build build --parallel 2

build/bin/pqbtcd -regtest -daemon
build/bin/pqbtc-cli -regtest createwallet devnet
ADDR=$(build/bin/pqbtc-cli -regtest getnewaddress)
build/bin/pqbtc-cli -regtest generatetoaddress 101 "$ADDR"
```

The signed interpreter KAT is:

```bash
build/bin/test_pqbtc \
  --run_test=shrincs_tx_v0_signed_seam_tests \
  --catch_system_error=no
```

Coins mined on regtest have no value and the network can be reset at any time.
Mainnet, testnet, testnet4, and signet do not activate this witness version.
''',
)

# Idempotence marker.
write(
    "src/crypto/shrincs/REGTEST_DEVNET_INTEGRATION",
    "PQBTC-SHRINCS-v0 regtest-devnet integration\n",
)

print("Applied PQBTC SHRINCS-v0 regtest-devnet integration.")
