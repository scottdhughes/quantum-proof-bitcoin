#!/usr/bin/env python3
"""Materialize the dedicated zero-value PQBTC SHRINCS labnet profile.

This script is intentionally idempotent.  It converts the existing regtest-only
SHRINCS development seam into an explicitly selected ``-shrincslab`` profile
with its own genesis, P2P magic, port, address namespace, deployment files, and
native tests.  Ordinary regtest returns to its inherited semantics and does not
activate SHRINCS.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import struct

ROOT = Path(__file__).resolve().parents[2]

TIMESTAMP = b"PQBTC SHRINCS Labnet 17/Aug/2026: hash-based post-quantum authorization"
GENESIS_TIME = 1_786_924_800
GENESIS_NONCE = 2
GENESIS_BITS = 0x207FFFFF
GENESIS_HASH = "122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69"
GENESIS_MERKLE = "2dec88624f3bbd6308ed55b83d9cb01933bbc76759498e52d21130c4e6ccd672"
MESSAGE_MAGIC = bytes.fromhex("91e1cac8")
P2P_PORT = 29333
RPC_PORT = 29332
BECH32_HRP = "pqsl"


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(value: int) -> bytes:
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def verify_genesis_constants() -> None:
    script_sig = (
        bytes([4])
        + bytes.fromhex("ffff001d")
        + bytes([1, 4])
        + bytes([len(TIMESTAMP)])
        + TIMESTAMP
    )
    transaction = (
        struct.pack("<I", 1)
        + b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + compact_size(len(script_sig))
        + script_sig
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x01"
        + struct.pack("<Q", 50 * 100_000_000)
        + b"\x01\x6a"
        + struct.pack("<I", 0)
    )
    merkle_raw = dsha256(transaction)
    header = (
        struct.pack("<I", 1)
        + b"\x00" * 32
        + merkle_raw
        + struct.pack("<III", GENESIS_TIME, GENESIS_BITS, GENESIS_NONCE)
    )
    assert merkle_raw[::-1].hex() == GENESIS_MERKLE
    assert dsha256(header)[::-1].hex() == GENESIS_HASH
    exponent = GENESIS_BITS >> 24
    mantissa = GENESIS_BITS & 0x007FFFFF
    target = mantissa << (8 * (exponent - 3))
    assert int.from_bytes(dsha256(header), "little") <= target


def replace_once(path: str, old: str, new: str) -> bool:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text:
        return False
    if old not in text:
        raise RuntimeError(f"anchor not found in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def replace_all(path: str, old: str, new: str, minimum: int = 1) -> bool:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0 and new in text:
        return False
    if count < minimum:
        raise RuntimeError(f"expected at least {minimum} anchors in {path}, found {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")
    return True


def write(path: str, content: str, executable: bool = False) -> bool:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    old = target.read_text(encoding="utf-8") if target.exists() else None
    changed = old != content
    if changed:
        target.write_text(content, encoding="utf-8")
    if executable:
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return changed


def patch_chain_selection() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["chainparamsbase"] = replace_once(
        "src/chainparamsbase.cpp",
        '    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "\n'
        '                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);\n',
        '    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "\n'
        '                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);\n'
        '    argsman.AddArg("-shrincslab", "Select the dedicated zero-value PQBTC SHRINCS labnet identity (requires -regtest).", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);\n',
    )
    changes["kernel_options"] = replace_once(
        "src/kernel/chainparams.h",
        "        bool fastprune{false};\n        bool enforce_bip94{false};\n",
        "        bool fastprune{false};\n        bool enforce_bip94{false};\n        bool shrincs_labnet{false};\n",
    )
    changes["read_option"] = replace_once(
        "src/chainparams.cpp",
        '    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;\n',
        '    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;\n'
        '    options.shrincs_labnet = args.GetBoolArg("-shrincslab", false);\n',
    )
    changes["reject_wrong_chain"] = replace_once(
        "src/chainparams.cpp",
        "std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)\n{\n    switch (chain) {\n",
        "std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)\n{\n"
        "    if (args.GetBoolArg(\"-shrincslab\", false) && chain != ChainType::REGTEST) {\n"
        "        throw std::runtime_error(\"-shrincslab requires -regtest or -chain=regtest\");\n"
        "    }\n"
        "    switch (chain) {\n",
    )
    return changes


def patch_kernel_chainparams() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    helper_anchor = '''static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}
'''
    helper = helper_anchor + '''
/** Dedicated, zero-value PQBTC SHRINCS labnet genesis. */
static CBlock CreateShrincsLabGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* timestamp = "PQBTC SHRINCS Labnet 17/Aug/2026: hash-based post-quantum authorization";
    const CScript unspendable_output = CScript() << OP_RETURN;
    return CreateGenesisBlock(timestamp, unspendable_output, nTime, nNonce, nBits, nVersion, genesisReward);
}
'''
    changes["genesis_helper"] = replace_once("src/kernel/chainparams.cpp", helper_anchor, helper)
    changes["activation"] = replace_once(
        "src/kernel/chainparams.cpp",
        "        consensus.shrincs_v0 = true;\n",
        "        consensus.shrincs_v0 = opts.shrincs_labnet;\n",
    )
    old_identity = '''        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
'''
    new_identity = '''        if (opts.shrincs_labnet) {
            // First four bytes of SHA256d("PQBTC-SHRINCSLAB-v0-message-start|165").
            pchMessageStart = {0x91, 0xe1, 0xca, 0xc8};
            nDefaultPort = 29333;
        } else {
            pchMessageStart = {0xfa, 0xbf, 0xb5, 0xda};
            nDefaultPort = 18444;
        }
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;
'''
    changes["network_identity"] = replace_once("src/kernel/chainparams.cpp", old_identity, new_identity)
    old_genesis = '''        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"});
        assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});
'''
    new_genesis = '''        if (opts.shrincs_labnet) {
            genesis = CreateShrincsLabGenesisBlock(1786924800, 2, 0x207fffff, 1, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == uint256{"122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69"});
            assert(genesis.hashMerkleRoot == uint256{"2dec88624f3bbd6308ed55b83d9cb01933bbc76759498e52d21130c4e6ccd672"});
        } else {
            genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
            assert(consensus.hashGenesisBlock == uint256{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"});
            assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});
        }
'''
    changes["genesis"] = replace_once("src/kernel/chainparams.cpp", old_genesis, new_genesis)
    changes["seeds"] = replace_once(
        "src/kernel/chainparams.cpp",
        '        vFixedSeeds.clear(); //!< Regtest mode doesn\'t have any fixed seeds.\n'
        '        vSeeds.clear();\n'
        '        vSeeds.emplace_back("dummySeed.invalid.");\n',
        '        vFixedSeeds.clear();\n'
        '        vSeeds.clear();\n'
        '        if (!opts.shrincs_labnet) vSeeds.emplace_back("dummySeed.invalid.");\n',
    )
    changes["mockability"] = replace_once(
        "src/kernel/chainparams.cpp",
        "        fDefaultConsistencyChecks = true;\n        m_is_mockable_chain = true;\n",
        "        fDefaultConsistencyChecks = true;\n        m_is_mockable_chain = !opts.shrincs_labnet;\n",
    )
    changes["snapshots"] = replace_once(
        "src/kernel/chainparams.cpp",
        "        chainTxData = ChainTxData{\n            .nTime = 0,\n            .tx_count = 0,\n            .dTxRate = 0.001,\n        };\n",
        "        if (opts.shrincs_labnet) m_assumeutxo_data.clear();\n\n"
        "        chainTxData = ChainTxData{\n            .nTime = 0,\n            .tx_count = 0,\n            .dTxRate = opts.shrincs_labnet ? 0.0 : 0.001,\n        };\n",
    )
    old_prefixes = '''        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
'''
    new_prefixes = '''        if (opts.shrincs_labnet) {
            base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65);
            base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 127);
            base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 193);
            base58Prefixes[EXT_PUBLIC_KEY] = {0xa4, 0x5d, 0xa6, 0x7c};
            base58Prefixes[EXT_SECRET_KEY] = {0x73, 0xbc, 0xcb, 0x89};
            bech32_hrp = "pqsl";
        } else {
            base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
            base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
            base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,239);
            base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
            base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
            bech32_hrp = "bcrt";
        }
'''
    changes["address_namespace"] = replace_once("src/kernel/chainparams.cpp", old_prefixes, new_prefixes)
    changes["magic_lookup"] = replace_once(
        "src/kernel/chainparams.cpp",
        "    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();\n"
        "    const auto signet_msg = CChainParams::SigNet({})->MessageStart();\n",
        "    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();\n"
        "    CChainParams::RegTestOptions shrincs_lab_options{};\n"
        "    shrincs_lab_options.shrincs_labnet = true;\n"
        "    const auto shrincs_lab_msg = CChainParams::RegTest(shrincs_lab_options)->MessageStart();\n"
        "    const auto signet_msg = CChainParams::SigNet({})->MessageStart();\n",
    )
    changes["magic_result"] = replace_once(
        "src/kernel/chainparams.cpp",
        "    } else if (std::ranges::equal(message, regtest_msg)) {\n        return ChainType::REGTEST;\n    } else if (std::ranges::equal(message, signet_msg)) {\n",
        "    } else if (std::ranges::equal(message, regtest_msg)) {\n        return ChainType::REGTEST;\n"
        "    } else if (std::ranges::equal(message, shrincs_lab_msg)) {\n        return ChainType::REGTEST;\n"
        "    } else if (std::ranges::equal(message, signet_msg)) {\n",
    )
    return changes


def patch_shrincs_naming() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["header"] = replace_once(
        "src/script/shrincs_tx_v0.h",
        "/** Fixed chain identifier for the private regtest/devnet activation. */\nuint256 RegtestChainId();\n",
        "/** Frozen chain identifier retained for signed-vector compatibility. */\nuint256 RegtestChainId();\n\n"
        "/** Chain identifier used by the explicitly selected SHRINCS labnet. */\nuint256 ShrincsLabChainId();\n",
    )
    changes["source"] = replace_once(
        "src/script/shrincs_tx_v0.cpp",
        "uint256 RegtestChainId()\n{\n    HashWriter writer;\n    writer.write(std::as_bytes(std::span<const char>{\n        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));\n    return writer.GetSHA256();\n}\n",
        "uint256 RegtestChainId()\n{\n    HashWriter writer;\n    writer.write(std::as_bytes(std::span<const char>{\n        REGTEST_CHAIN_ID_LABEL.data(), REGTEST_CHAIN_ID_LABEL.size()}));\n    return writer.GetSHA256();\n}\n\n"
        "uint256 ShrincsLabChainId()\n{\n    return RegtestChainId();\n}\n",
    )
    changes["interpreter"] = replace_once(
        "src/script/interpreter.cpp",
        "        shrincs_tx_v0::RegtestChainId())};\n",
        "        shrincs_tx_v0::ShrincsLabChainId())};\n",
    )
    return changes


def patch_controller_and_tests() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    path = "contrib/shrincs-labnet/labnet.py"
    changes["controller_marker"] = replace_once(path, 'MARKER_NAME = ".pqbtc-shrincs-labnet"\n', 'MARKER_NAME = ".pqbtc-shrincslab"\nNETWORK_HRP = "pqsl"\n')
    changes["controller_ports0"] = replace_once(path, "return NodeLayout(self, index=0, p2p_port=19444, rpc_port=19443)", "return NodeLayout(self, index=0, p2p_port=29333, rpc_port=29332)")
    changes["controller_ports1"] = replace_once(path, "return NodeLayout(self, index=1, p2p_port=19445, rpc_port=19453)", "return NodeLayout(self, index=1, p2p_port=29343, rpc_port=29342)")
    changes["controller_config"] = replace_once(path, '                "regtest=1",\n                "server=1",\n', '                "regtest=1",\n                "shrincslab=1",\n                "server=1",\n')
    changes["controller_cli"] = replace_once(path, '            "-regtest",\n            f"-datadir={self.paths.datadir}",\n', '            "-regtest",\n            "-shrincslab",\n            f"-datadir={self.paths.datadir}",\n')
    changes["controller_daemon"] = replace_once(path, '                        self.layout.daemon,\n                        "-regtest",\n                        f"-datadir={node.paths.datadir}",\n', '                        self.layout.daemon,\n                        "-regtest",\n                        "-shrincslab",\n                        f"-datadir={node.paths.datadir}",\n')
    changes["controller_profile1"] = replace_all(path, "pqbtc-shrincs-v0-private-regtest-labnet", "pqbtc-shrincs-v0-public-zero-value-labnet", minimum=2)
    changes["controller_import"] = replace_once(path, "        from test_framework.address import address_to_scriptpubkey, program_to_witness\n", "        from test_framework.address import address_to_scriptpubkey\n        from test_framework.segwit_addr import encode_segwit_address\n")
    changes["controller_address"] = replace_once(path, "        shrincs_address = program_to_witness(2, program, main=False)\n", "        shrincs_address = encode_segwit_address(NETWORK_HRP, 2, program)\n")
    changes["test_hrp"] = replace_once(
        "test/functional/test_framework/address.py",
        "    if hrp not in ['bc', 'tb', 'bcrt', 'pq', 'rq', 'tq']:\n",
        "    if hrp not in ['bc', 'tb', 'bcrt', 'pq', 'rq', 'tq', 'pqsl']:\n",
    )
    changes["functional_args"] = replace_once(
        "test/functional/feature_shrincs_regtest.py",
        '        self.extra_args = [["-acceptnonstdtxn=1"]]\n',
        '        self.extra_args = [["-shrincslab", "-acceptnonstdtxn=1"]]\n',
    )
    changes["functional_doc"] = replace_once(
        "test/functional/feature_shrincs_regtest.py",
        '"""Mine and spend actual PQBTC-SHRINCS-v0 outputs on private regtest."""\n',
        '"""Mine and spend actual PQBTC-SHRINCS-v0 outputs on the dedicated SHRINCS labnet."""\n',
    )
    changes["controller_test_ports"] = replace_all(
        "contrib/shrincs-labnet/test_labnet.py",
        '            "port=19444",\n            "rpcport=19443",\n',
        '            "port=29333",\n            "rpcport=29332",\n',
    )
    changes["controller_test_selector"] = replace_once(
        "contrib/shrincs-labnet/test_labnet.py",
        '        self.assertIn("regtest=1\\n", global_settings)\n',
        '        self.assertIn("regtest=1\\n", global_settings)\n        self.assertIn("shrincslab=1\\n", global_settings)\n',
    )
    changes["architecture_guard"] = replace_once(
        "ci/test/test_shrincs_tx_cpp_component.py",
        '''        activation = "consensus.shrincs_v0 = true;"
        self.assertEqual(chainparams.count(activation), 1)
        regtest_start = chainparams.index("class CRegTestParams")
        activation_position = chainparams.index(activation)
        self.assertGreater(activation_position, regtest_start)
        self.assertIn(
            "m_chain_type = ChainType::REGTEST;",
            chainparams[regtest_start:activation_position],
        )
''',
        '''        activation = "consensus.shrincs_v0 = opts.shrincs_labnet;"
        self.assertEqual(chainparams.count(activation), 1)
        regtest_start = chainparams.index("class CRegTestParams")
        activation_position = chainparams.index(activation)
        self.assertGreater(activation_position, regtest_start)
        self.assertIn("bool shrincs_labnet{false};", (REPO_ROOT / "src" / "kernel" / "chainparams.h").read_text(encoding="utf-8"))
        self.assertIn("m_chain_type = ChainType::REGTEST;", chainparams[regtest_start:activation_position])
        self.assertIn('bech32_hrp = "pqsl";', chainparams)
        self.assertIn("0x91, 0xe1, 0xca, 0xc8", chainparams)
''',
    )
    return changes


def chainparams_test_source() -> str:
    return '''// Copyright (c) 2026 The PQBTC Core developers
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
'''


def patch_native_tests() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["new_test"] = write("src/test/shrincslab_chainparams_tests.cpp", chainparams_test_source())
    changes["cmake"] = replace_all(
        "src/test/CMakeLists.txt",
        "  shrincs_tx_v0_signed_seam_tests.cpp\n",
        "  shrincs_tx_v0_signed_seam_tests.cpp\n  shrincslab_chainparams_tests.cpp\n",
        minimum=2,
    )
    return changes


def write_manifest_and_docs() -> dict[str, bool]:
    manifest = {
        "schema_version": 2,
        "profile": "pqbtc-shrincs-v0-public-zero-value-labnet",
        "zero_value_only": True,
        "selector": ["-regtest", "-shrincslab"],
        "network": {
            "internal_chain_type": "regtest",
            "genesis_hash": GENESIS_HASH,
            "genesis_merkle_root": GENESIS_MERKLE,
            "genesis_time": GENESIS_TIME,
            "genesis_nonce": GENESIS_NONCE,
            "genesis_bits": "207fffff",
            "message_magic": MESSAGE_MAGIC.hex(),
            "default_p2p_port": P2P_PORT,
            "recommended_rpc_port": RPC_PORT,
            "bech32_hrp": BECH32_HRP,
            "public_discovery": False,
            "dns_seeds": [],
            "fixed_seeds": [],
        },
        "consensus_activation": {
            "mainnet": False,
            "testnet": False,
            "testnet4": False,
            "signet": False,
            "ordinary_regtest": False,
            "shrincslab": True,
        },
        "proof_of_work": {
            "algorithm": "sha256d",
            "pow_limit": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "no_retargeting": True,
            "allow_min_difficulty": True,
            "economic_security": False,
        },
        "shrincs": {
            "upstream_repository": "SHRINCS/shrincs-bip",
            "upstream_commit": "acc6bda51dc3b94848d118967247ad0f3cd7a80e",
            "public_key_bytes": 48,
            "stateful_signature_min": 554,
            "stateful_signature_max": 4618,
            "stateless_signature_bytes": 5776,
            "context": "PQBTC/SHRINCS/TXSIG/v0",
        },
        "production_ready": False,
    }
    changes = {
        "manifest": write(
            "contrib/shrincs-labnet/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
    }
    docs = f'''# PQBTC SHRINCS public zero-value labnet

This profile is the first network-distinct PQBTC chain that exercises the frozen
SHRINCS-v0 transaction authorization path.  It is selected with:

```bash
pqbtcd -regtest -shrincslab
```

It deliberately reuses mature **regtest machinery** (instant mining and no
retargeting) while replacing every network-facing identity that could collide
with Bitcoin regtest:

| Field | SHRINCS labnet |
|---|---|
| Genesis | `{GENESIS_HASH}` |
| Merkle root | `{GENESIS_MERKLE}` |
| Message magic | `{MESSAGE_MAGIC.hex()}` |
| Default P2P port | `{P2P_PORT}` |
| Recommended RPC port | `{RPC_PORT}` |
| Bech32 HRP | `{BECH32_HRP}` |
| DNS/fixed seeds | none |

Ordinary `-regtest` does **not** activate SHRINCS on this branch.  Mainnet,
testnet3, testnet4, and signet remain unchanged.

## Start a two-node network and mine

```bash
python3 contrib/shrincs-labnet/labnet.py quickstart --fresh --mode both
python3 contrib/shrincs-labnet/labnet.py mine 10
python3 contrib/shrincs-labnet/labnet.py status
```

The quickstart builds the node, starts two peers, mines mature funds, creates a
crash-safe stateful signer, rejects a mutated signature, broadcasts one
stateful and one stateless SHRINCS spend, and mines both.

## Public node

Use `contrib/shrincs-labnet/shrincslab.conf.example` as a starting point.  Expose
only P2P port `{P2P_PORT}`.  Keep RPC firewalled and use cookie authentication.
Until seed operators exist, peers join with `-addnode=<host>:{P2P_PORT}`.

The supplied Docker Compose file starts a seed, miner, and observer on one
machine for deployment rehearsal.  It does not create economic security.

## Security scope

At compact target `0x207fffff`, a block requires about two SHA-256d attempts on
average.  This is ideal for testing and worthless as adversarial hash security.
Coins on this network must never be sold, custodied as value, or represented as
production-ready.  The current SHRINCS draft and signer remain research code.
'''
    changes["docs"] = write("docs/PQBTC_SHRINCS_PUBLIC_LABNET.md", docs)
    config = f'''# PQBTC SHRINCS public zero-value labnet
regtest=1
shrincslab=1
server=1
listen=1
port={P2P_PORT}
rpcport={RPC_PORT}

# Public P2P, private RPC.
bind=0.0.0.0:{P2P_PORT}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# No discovery exists yet. Add known peers explicitly.
discover=0
dnsseed=0
fixedseeds=0
listenonion=0
upnp=0
natpmp=0

acceptnonstdtxn=1
txindex=1
fallbackfee=0.00010000
persistmempool=1
'''
    changes["config"] = write("contrib/shrincs-labnet/shrincslab.conf.example", config)
    dockerfile = '''FROM ubuntu:24.04 AS builder
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    build-essential cmake ninja-build libboost-dev libevent-dev libsqlite3-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja \
    -DBUILD_GUI=OFF -DBUILD_GUI_TESTS=OFF -DBUILD_BENCH=OFF \
    -DBUILD_FUZZ_BINARY=OFF -DBUILD_KERNEL_LIB=OFF -DENABLE_WALLET=ON \
    -DENABLE_IPC=OFF -DENABLE_EXTERNAL_SIGNER=OFF -DWITH_ZMQ=OFF \
    -DWITH_USDT=OFF -DBUILD_TESTS=OFF \
    && cmake --build build --parallel 2 --target pqbtcd pqbtc-cli

FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    libevent-2.1-7t64 libevent-pthreads-2.1-7t64 libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/bin/pqbtcd /usr/local/bin/pqbtcd
COPY --from=builder /src/build/bin/pqbtc-cli /usr/local/bin/pqbtc-cli
RUN useradd --create-home --uid 10001 pqbtc && mkdir /data && chown pqbtc:pqbtc /data
USER pqbtc
VOLUME ["/data"]
EXPOSE 29333
ENTRYPOINT ["pqbtcd", "-regtest", "-shrincslab", "-datadir=/data", "-printtoconsole"]
'''
    changes["dockerfile"] = write("contrib/shrincs-labnet/Dockerfile.shrincslab", dockerfile)
    compose = '''services:
  seed:
    build:
      context: ../..
      dockerfile: contrib/shrincs-labnet/Dockerfile.shrincslab
    command:
      - -server=1
      - -listen=1
      - -port=29333
      - -rpcbind=127.0.0.1
      - -rpcport=29332
      - -discover=0
      - -dnsseed=0
      - -fixedseeds=0
      - -acceptnonstdtxn=1
    ports:
      - "29333:29333"
    volumes:
      - shrincslab-seed:/data

  miner:
    build:
      context: ../..
      dockerfile: contrib/shrincs-labnet/Dockerfile.shrincslab
    command:
      - -server=1
      - -listen=1
      - -port=29333
      - -rpcbind=127.0.0.1
      - -rpcport=29332
      - -addnode=seed:29333
      - -discover=0
      - -dnsseed=0
      - -fixedseeds=0
      - -acceptnonstdtxn=1
    depends_on: [seed]
    volumes:
      - shrincslab-miner:/data

  observer:
    build:
      context: ../..
      dockerfile: contrib/shrincs-labnet/Dockerfile.shrincslab
    command:
      - -server=1
      - -listen=1
      - -port=29333
      - -rpcbind=127.0.0.1
      - -rpcport=29332
      - -addnode=seed:29333
      - -discover=0
      - -dnsseed=0
      - -fixedseeds=0
      - -acceptnonstdtxn=1
    depends_on: [seed]
    volumes:
      - shrincslab-observer:/data

volumes:
  shrincslab-seed:
  shrincslab-miner:
  shrincslab-observer:
'''
    changes["compose"] = write("contrib/shrincs-labnet/docker-compose.shrincslab.yml", compose)
    return changes


def main() -> int:
    verify_genesis_constants()
    changes = {
        "chain_selection": patch_chain_selection(),
        "kernel_chainparams": patch_kernel_chainparams(),
        "shrincs_naming": patch_shrincs_naming(),
        "controller_and_tests": patch_controller_and_tests(),
        "native_tests": patch_native_tests(),
        "manifest_and_docs": write_manifest_and_docs(),
    }
    print(json.dumps({"result": "PASS", "changes": changes}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
