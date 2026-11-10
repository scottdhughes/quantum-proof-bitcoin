// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <cassert>
#include <stdexcept>

void SetupChainParamsBaseOptions(ArgsManager& argsman)
{
    argsman.AddArg("-mldsa44demo", "Use the isolated valueless CONTRACT-1 regtest (requires explicit experimental build and -regtest; never production)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-mldsa44test", "Use the isolated valueless CONTRACT-1 public TEST profile (command-line only; requires -chain=test and experimental build; never production)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-chain=<chain>", "Use the chain <chain> (default: main). Allowed values: " LIST_CHAIN_NAMES, ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testactivationheight=name@height.", "Set the activation height of 'name' (segwit, bip34, dersig, cltv, csv). (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-testnet", "Use the testnet3 chain. Equivalent to -chain=test. Support for testnet3 is deprecated and will be removed in an upcoming release. Consider moving to testnet4 now by using -testnet4.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet4", "Use the testnet4 chain. Equivalent to -chain=testnet4.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-vbparams=deployment:start:end[:min_activation_height]", "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signet", "Use the signet chain. Equivalent to -chain=signet. Note that the network is defined by the -signetchallenge parameter", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetchallenge", "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetseednode", "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

/**
 * Port numbers for incoming Tor connections (8334, 18334, 38334, 48334, 18445) have
 * been chosen arbitrarily to keep ranges of used ports tight.
 */
bool IsMLDSA44Demo(const ArgsManager& args, ChainType chain)
{
    // The namespace is selected before SelectConfigNetwork. Never let a later
    // section-specific value select a different consensus identity.
    if (args.IsArgSetInConfig("-mldsa44demo")) throw std::invalid_argument("-mldsa44demo is command-line only; not permitted in config/settings");
    if (!args.GetBoolArg("-mldsa44demo", false)) return false;
    if (args.GetBoolArg("-mldsa44test", false)) throw std::invalid_argument("ML-DSA demo and public test modes conflict");
    if (chain != ChainType::REGTEST) throw std::invalid_argument("-mldsa44demo requires -regtest");
#ifndef ENABLE_EXPERIMENTAL_MLDSA44
    throw std::invalid_argument("-mldsa44demo requires ENABLE_EXPERIMENTAL_MLDSA44");
#else
    return true;
#endif
}

bool IsMLDSA44Test(const ArgsManager& args, ChainType chain)
{
    if (args.IsArgSetInConfig("-mldsa44test")) throw std::invalid_argument("-mldsa44test is command-line only; not permitted in config/settings");
    if (!args.GetBoolArg("-mldsa44test", false)) return false;
    if (chain != ChainType::TESTNET || args.GetArg("-chain") != "test" || args.IsArgSetInConfig("-chain")) {
        throw std::invalid_argument("-mldsa44test requires explicit command-line -chain=test");
    }
    if (args.GetBoolArg("-mldsa44demo", false) || args.GetBoolArg("-regtest", false) ||
        args.GetBoolArg("-testnet", false) || args.GetBoolArg("-testnet4", false) || args.GetBoolArg("-signet", false) ||
        args.IsArgSet("-testactivationheight") || args.IsArgSet("-vbparams") || args.IsArgSet("-signetchallenge") ||
        args.IsArgSet("-signetseednode")) {
        throw std::invalid_argument("-mldsa44test does not allow conflicting network/deployment options");
    }
#ifndef ENABLE_EXPERIMENTAL_MLDSA44
    throw std::invalid_argument("-mldsa44test requires ENABLE_EXPERIMENTAL_MLDSA44");
#else
    return true;
#endif
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain, bool mldsa44_demo, bool mldsa44_test)
{
    if (mldsa44_demo && mldsa44_test) throw std::invalid_argument("ML-DSA demo and public test modes conflict");
    if (mldsa44_test) {
        if (chain != ChainType::TESTNET) throw std::invalid_argument("ML-DSA public test requires test");
        return std::make_unique<CBaseChainParams>("mldsa44-test-v1", 23832);
    }
    if (mldsa44_demo) {
        if (chain != ChainType::REGTEST) throw std::invalid_argument("ML-DSA demo requires regtest");
        return std::make_unique<CBaseChainParams>("mldsa44-regtest-v1", 24832);
    }
    switch (chain) {
    case ChainType::MAIN:
        return std::make_unique<CBaseChainParams>("", 8332);
    case ChainType::TESTNET:
        return std::make_unique<CBaseChainParams>("testnet3", 18332);
    case ChainType::TESTNET4:
        return std::make_unique<CBaseChainParams>("testnet4", 48332);
    case ChainType::SIGNET:
        return std::make_unique<CBaseChainParams>("signet", 38332);
    case ChainType::REGTEST:
        return std::make_unique<CBaseChainParams>("regtest", 18443);
    }
    assert(false);
}

void SelectBaseParams(const ChainType chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain, IsMLDSA44Demo(gArgs, chain), IsMLDSA44Test(gArgs, chain));
    gArgs.SelectConfigNetwork(ChainTypeToString(chain));
}
