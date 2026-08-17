#!/usr/bin/env python3
"""Bind PQBTC-SHRINCS-v0 to the dedicated labnet identity.

The public zero-value labnet must be incompatible with the earlier private
regtest fixture at every relevant boundary: genesis, P2P handshake,
transaction-signature domain, RPC port, and filesystem namespace.  This
materializer is idempotent and runs after
``apply_shrincslab_public_profile.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENESIS_HASH = "122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69"
CHAIN_DOMAIN_LABEL = f"PQBTC-SHRINCSLAB-v0|genesis={GENESIS_HASH}"
CHAIN_DOMAIN_HASH = hashlib.sha256(CHAIN_DOMAIN_LABEL.encode("ascii")).hexdigest()
EXPECTED_CHAIN_DOMAIN_HASH = "db0e425cda8dcebc9e64203d2a5dfde2e954954f3dc95b8b9807590103d07652"


def replace_once(path: str, old: str, new: str) -> bool:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text:
        return False
    if old not in text:
        raise RuntimeError(f"anchor not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def patch_cpp_domain() -> dict[str, bool]:
    changes: dict[str, bool] = {}

    header = ROOT / "src/script/shrincs_tx_v0.h"
    header_text = header.read_text(encoding="utf-8")
    old_label = 'inline constexpr std::string_view REGTEST_CHAIN_ID_LABEL{"PQBTC-SHRINCS-TX-V0-TEST-CHAIN"};\n'
    new_label = (
        old_label
        + 'inline constexpr std::string_view SHRINCS_LAB_CHAIN_ID_LABEL{\n'
        + f'    "{CHAIN_DOMAIN_LABEL}"}};\n'
    )
    if "SHRINCS_LAB_CHAIN_ID_LABEL" not in header_text:
        if old_label not in header_text:
            raise RuntimeError("SHRINCS chain-domain label anchor not found in header")
        header_text = header_text.replace(old_label, new_label, 1)
        changes["label"] = True
    else:
        changes["label"] = False

    old_declaration = "/** Chain identifier used by the explicitly selected SHRINCS labnet. */\nuint256 ShrincsLabChainId();\n"
    new_declaration = "/** Genesis-bound chain identifier used by the SHRINCS labnet. */\nuint256 ShrincsLabChainId();\n"
    if new_declaration not in header_text:
        if old_declaration not in header_text:
            raise RuntimeError("SHRINCS labnet chain-id declaration anchor not found")
        header_text = header_text.replace(old_declaration, new_declaration, 1)
        changes["header"] = True
    else:
        changes["header"] = False
    if changes["label"] or changes["header"]:
        header.write_text(header_text, encoding="utf-8")

    source = ROOT / "src/script/shrincs_tx_v0.cpp"
    source_text = source.read_text(encoding="utf-8")
    old_function = '''uint256 ShrincsLabChainId()
{
    return RegtestChainId();
}
'''
    new_function = '''uint256 ShrincsLabChainId()
{
    HashWriter writer;
    writer.write(std::as_bytes(std::span<const char>{
        SHRINCS_LAB_CHAIN_ID_LABEL.data(), SHRINCS_LAB_CHAIN_ID_LABEL.size()}));
    return writer.GetSHA256();
}
'''
    if new_function not in source_text:
        if old_function not in source_text:
            raise RuntimeError("SHRINCS labnet chain-id function anchor not found")
        source.write_text(source_text.replace(old_function, new_function, 1), encoding="utf-8")
        changes["function"] = True
    else:
        changes["function"] = False
    return changes


def patch_base_identity() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["base_params"] = replace_once(
        "src/chainparamsbase.cpp",
        "    case ChainType::REGTEST:\n        return std::make_unique<CBaseChainParams>(\"regtest\", 18443);\n",
        "    case ChainType::REGTEST:\n"
        "        if (gArgs.GetBoolArg(\"-shrincslab\", false)) {\n"
        "            return std::make_unique<CBaseChainParams>(\"shrincslab\", 29332);\n"
        "        }\n"
        "        return std::make_unique<CBaseChainParams>(\"regtest\", 18443);\n",
    )
    changes["config_namespace"] = replace_once(
        "src/chainparamsbase.cpp",
        "void SelectBaseParams(const ChainType chain)\n{\n"
        "    globalChainBaseParams = CreateBaseChainParams(chain);\n"
        "    gArgs.SelectConfigNetwork(ChainTypeToString(chain));\n"
        "}\n",
        "void SelectBaseParams(const ChainType chain)\n{\n"
        "    globalChainBaseParams = CreateBaseChainParams(chain);\n"
        "    const bool shrincs_labnet{chain == ChainType::REGTEST && gArgs.GetBoolArg(\"-shrincslab\", false)};\n"
        "    gArgs.SelectConfigNetwork(shrincs_labnet ? \"shrincslab\" : ChainTypeToString(chain));\n"
        "}\n",
    )
    ci_path = ROOT / "ci/test/test_shrincs_tx_cpp_component.py"
    ci_text = ci_path.read_text(encoding="utf-8")
    marker = '        self.assertIn(\'bech32_hrp = "pqsl";\', chainparams)\n'
    addition = (
        marker
        + '        base_params = (REPO_ROOT / "src" / "chainparamsbase.cpp").read_text(encoding="utf-8")\n'
        + '        self.assertIn(\'CBaseChainParams>("shrincslab", 29332)\', base_params)\n'
        + '        self.assertIn(\'SelectConfigNetwork(shrincs_labnet ? "shrincslab"\', base_params)\n'
    )
    if addition in ci_text:
        changes["architecture_guard"] = False
    elif marker in ci_text:
        ci_path.write_text(ci_text.replace(marker, addition, 1), encoding="utf-8")
        changes["architecture_guard"] = True
    else:
        raise RuntimeError("architecture-guard base-identity anchor not found")
    return changes


def patch_python_model() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    changes["constant"] = replace_once(
        "contrib/shrincs-tx/tx_model.py",
        'TEST_CHAIN_ID = hashlib.sha256(b"PQBTC-SHRINCS-TX-V0-TEST-CHAIN").digest()\n',
        f'SHRINCS_LAB_GENESIS = "{GENESIS_HASH}"\n'
        f'SHRINCS_LAB_CHAIN_DOMAIN = b"{CHAIN_DOMAIN_LABEL}"\n'
        'TEST_CHAIN_ID = hashlib.sha256(SHRINCS_LAB_CHAIN_DOMAIN).digest()\n',
    )
    changes["comment"] = replace_once(
        "contrib/shrincs-tx/tx_model.py",
        "    `chain_id` is a 32-byte network-specific constant to be frozen with the\n"
        "    network genesis. No production chain ID is selected by this model.\n",
        "    `chain_id` is the 32-byte domain identifier frozen to the dedicated\n"
        "    zero-value SHRINCS labnet genesis.\n",
    )
    return changes


def patch_native_test_domains() -> dict[str, bool]:
    changes: dict[str, bool] = {}
    for path in (
        "src/test/shrincs_tx_v0_tests.cpp",
        "src/test/shrincs_tx_v0_signed_seam_tests.cpp",
    ):
        changes[path] = replace_once(
            path,
            '    result.chain_id = HashText("PQBTC-SHRINCS-TX-V0-TEST-CHAIN");\n',
            "    result.chain_id = shrincs_tx_v0::ShrincsLabChainId();\n",
        )
    return changes


def patch_manifest_and_docs() -> dict[str, bool]:
    manifest_path = ROOT / "contrib/shrincs-labnet/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    previous_domain = manifest.get("shrincs", {}).get("chain_domain")
    manifest.setdefault("shrincs", {})["chain_domain"] = {
        "label": CHAIN_DOMAIN_LABEL,
        "sha256": CHAIN_DOMAIN_HASH,
        "bound_genesis": GENESIS_HASH,
        "replay_compatible_with_private_regtest_fixture": False,
    }
    network = manifest.setdefault("network", {})
    previous_base = (network.get("default_data_dir"), network.get("recommended_rpc_port"))
    network["default_data_dir"] = "shrincslab"
    network["recommended_rpc_port"] = 29332
    manifest_changed = (
        previous_domain != manifest["shrincs"]["chain_domain"]
        or previous_base != ("shrincslab", 29332)
    )
    if manifest_changed:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    docs_path = ROOT / "docs/PQBTC_SHRINCS_PUBLIC_LABNET.md"
    docs = docs_path.read_text(encoding="utf-8")
    domain_section = f'''\n## Genesis-bound signature domain\n\nEvery SHRINCS transaction signature commits to:\n\n```text\n{CHAIN_DOMAIN_LABEL}\nSHA256 = {CHAIN_DOMAIN_HASH}\n```\n\nThis is intentionally incompatible with the earlier private-regtest fixture.\nA signature from that fixture cannot authorize an otherwise identical labnet\ntransaction, and changing the labnet genesis requires a new signature domain.\n'''
    base_section = '''\n## Filesystem and RPC isolation\n\n`-regtest -shrincslab` selects base data directory `shrincslab/`, config\nnamespace `[shrincslab]`, and default RPC port `29332`. Ordinary regtest keeps\n`regtest/`, `[regtest]`, and `18443`. The two chains therefore cannot share\nblock databases, wallets, cookies, settings, or RPC endpoints by default.\n'''
    docs_changed = False
    for section in (domain_section, base_section):
        if section not in docs:
            docs = docs.rstrip() + "\n" + section
            docs_changed = True
    if docs_changed:
        docs_path.write_text(docs, encoding="utf-8")

    return {"manifest": manifest_changed, "docs": docs_changed}


def main() -> int:
    if CHAIN_DOMAIN_HASH != EXPECTED_CHAIN_DOMAIN_HASH:
        raise RuntimeError("genesis-bound chain-domain hash drifted")
    result = {
        "result": "PASS",
        "genesis": GENESIS_HASH,
        "chain_domain_label": CHAIN_DOMAIN_LABEL,
        "chain_domain_sha256": CHAIN_DOMAIN_HASH,
        "changes": {
            "cpp": patch_cpp_domain(),
            "base_identity": patch_base_identity(),
            "python_model": patch_python_model(),
            "native_tests": patch_native_test_domains(),
            "manifest_and_docs": patch_manifest_and_docs(),
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
