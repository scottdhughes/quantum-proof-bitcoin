#!/usr/bin/env python3
"""Give the SHRINCS labnet its own base RPC and filesystem identity.

The labnet deliberately reuses the mature regtest consensus machinery, but it
must never reuse the default ``regtest/`` data directory.  This materializer
selects ``shrincslab/`` and RPC port 29332 whenever ``-regtest -shrincslab`` is
active, while preserving ordinary regtest defaults.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: str, old: str, new: str) -> bool:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text:
        return False
    if old not in text:
        raise RuntimeError(f"anchor not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def patch_base_params() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["header_create"] = replace_once(
        "src/chainparamsbase.h",
        "std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain);\n",
        "std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain, bool shrincs_labnet = false);\n",
    )
    changes["header_select"] = replace_once(
        "src/chainparamsbase.h",
        "void SelectBaseParams(const ChainType chain);\n",
        "void SelectBaseParams(const ChainType chain, bool shrincs_labnet = false);\n",
    )
    changes["source_create"] = replace_once(
        "src/chainparamsbase.cpp",
        "std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain)\n",
        "std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain, const bool shrincs_labnet)\n",
    )
    changes["source_regtest"] = replace_once(
        "src/chainparamsbase.cpp",
        "    case ChainType::REGTEST:\n        return std::make_unique<CBaseChainParams>(\"regtest\", 18443);\n",
        "    case ChainType::REGTEST:\n"
        "        if (shrincs_labnet) return std::make_unique<CBaseChainParams>(\"shrincslab\", 29332);\n"
        "        return std::make_unique<CBaseChainParams>(\"regtest\", 18443);\n",
    )
    changes["source_select"] = replace_once(
        "src/chainparamsbase.cpp",
        "void SelectBaseParams(const ChainType chain)\n{\n"
        "    globalChainBaseParams = CreateBaseChainParams(chain);\n"
        "    gArgs.SelectConfigNetwork(ChainTypeToString(chain));\n"
        "}\n",
        "void SelectBaseParams(const ChainType chain, const bool shrincs_labnet)\n{\n"
        "    globalChainBaseParams = CreateBaseChainParams(chain, shrincs_labnet);\n"
        "    gArgs.SelectConfigNetwork(shrincs_labnet ? \"shrincslab\" : ChainTypeToString(chain));\n"
        "}\n",
    )
    changes["select_params"] = replace_once(
        "src/chainparams.cpp",
        "void SelectParams(const ChainType chain)\n{\n"
        "    SelectBaseParams(chain);\n"
        "    globalChainParams = CreateChainParams(gArgs, chain);\n"
        "}\n",
        "void SelectParams(const ChainType chain)\n{\n"
        "    const bool shrincs_labnet{chain == ChainType::REGTEST && gArgs.GetBoolArg(\"-shrincslab\", false)};\n"
        "    SelectBaseParams(chain, shrincs_labnet);\n"
        "    globalChainParams = CreateChainParams(gArgs, chain);\n"
        "}\n",
    )
    return changes


def patch_native_test() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["include"] = replace_once(
        "src/test/shrincslab_chainparams_tests.cpp",
        "#include <kernel/chainparams.h>\n",
        "#include <chainparamsbase.h>\n#include <kernel/chainparams.h>\n",
    )
    changes["assertions"] = replace_once(
        "src/test/shrincslab_chainparams_tests.cpp",
        "    BOOST_CHECK_EQUAL(lab->GetDefaultPort(), 29333);\n"
        "    BOOST_CHECK_EQUAL(lab->Bech32HRP(), \"pqsl\");\n",
        "    BOOST_CHECK_EQUAL(lab->GetDefaultPort(), 29333);\n"
        "    BOOST_CHECK_EQUAL(lab->Bech32HRP(), \"pqsl\");\n\n"
        "    const std::unique_ptr<CBaseChainParams> regular_base{CreateBaseChainParams(ChainType::REGTEST)};\n"
        "    const std::unique_ptr<CBaseChainParams> lab_base{CreateBaseChainParams(ChainType::REGTEST, true)};\n"
        "    BOOST_CHECK_EQUAL(regular_base->DataDir(), \"regtest\");\n"
        "    BOOST_CHECK_EQUAL(regular_base->RPCPort(), 18443);\n"
        "    BOOST_CHECK_EQUAL(lab_base->DataDir(), \"shrincslab\");\n"
        "    BOOST_CHECK_EQUAL(lab_base->RPCPort(), 29332);\n",
    )
    return changes


def patch_manifest_and_docs() -> dict[str, bool]:
    manifest_path = ROOT / "contrib/shrincs-labnet/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    network = manifest.setdefault("network", {})
    before = (network.get("default_data_dir"), network.get("recommended_rpc_port"))
    network["default_data_dir"] = "shrincslab"
    network["recommended_rpc_port"] = 29332
    changed_manifest = before != ("shrincslab", 29332)
    if changed_manifest:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    docs_path = ROOT / "docs/PQBTC_SHRINCS_PUBLIC_LABNET.md"
    docs = docs_path.read_text(encoding="utf-8")
    section = '''
## Filesystem and RPC isolation

`-regtest -shrincslab` selects base data directory `shrincslab/` and default
RPC port `29332`. Ordinary regtest continues to use `regtest/` and `18443`.
This prevents the two chains from sharing block databases, wallets, cookies,
settings, or RPC endpoints when an operator does not pass an explicit datadir.
'''
    changed_docs = section not in docs
    if changed_docs:
        docs_path.write_text(docs.rstrip() + "\n" + section, encoding="utf-8")
    return {"manifest": changed_manifest, "docs": changed_docs}


def main() -> int:
    result = {
        "result": "PASS",
        "changes": {
            "base_params": patch_base_params(),
            "native_test": patch_native_test(),
            "manifest_and_docs": patch_manifest_and_docs(),
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
