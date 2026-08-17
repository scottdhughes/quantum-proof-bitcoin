#!/usr/bin/env python3
"""Bind PQBTC-SHRINCS-v0 signatures to the dedicated labnet genesis.

The earlier private-regtest fixture used a generic test-chain label.  A public
network must not preserve that compatibility domain: otherwise a signature
created for the private fixture could be replayed on the network-distinct
labnet whenever the transaction surfaces otherwise coincide.

This materializer is idempotent and runs after
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
    source = ROOT / "src/script/shrincs_tx_v0.cpp"
    text = source.read_text(encoding="utf-8")
    changes: dict[str, bool] = {}

    old_label = 'inline constexpr std::string_view REGTEST_CHAIN_ID_LABEL{"PQBTC-SHRINCS-TX-V0-TEST-CHAIN"};\n'
    new_label = (
        old_label
        + 'inline constexpr std::string_view SHRINCS_LAB_CHAIN_ID_LABEL{\n'
        + f'    "{CHAIN_DOMAIN_LABEL}"}};\n'
    )
    if "SHRINCS_LAB_CHAIN_ID_LABEL" not in text:
        if old_label not in text:
            raise RuntimeError("SHRINCS chain-domain label anchor not found")
        text = text.replace(old_label, new_label, 1)
        changes["label"] = True
    else:
        changes["label"] = False

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
    if new_function not in text:
        if old_function not in text:
            raise RuntimeError("SHRINCS labnet chain-id function anchor not found")
        text = text.replace(old_function, new_function, 1)
        changes["function"] = True
    else:
        changes["function"] = False

    if changes["label"] or changes["function"]:
        source.write_text(text, encoding="utf-8")

    changes["header"] = replace_once(
        "src/script/shrincs_tx_v0.h",
        "/** Chain identifier used by the explicitly selected SHRINCS labnet. */\nuint256 ShrincsLabChainId();\n",
        "/** Genesis-bound chain identifier used by the SHRINCS labnet. */\nuint256 ShrincsLabChainId();\n",
    )
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
    previous = manifest.get("shrincs", {}).get("chain_domain")
    manifest.setdefault("shrincs", {})["chain_domain"] = {
        "label": CHAIN_DOMAIN_LABEL,
        "sha256": CHAIN_DOMAIN_HASH,
        "bound_genesis": GENESIS_HASH,
        "replay_compatible_with_private_regtest_fixture": False,
    }
    manifest_changed = previous != manifest["shrincs"]["chain_domain"]
    if manifest_changed:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    docs_path = ROOT / "docs/PQBTC_SHRINCS_PUBLIC_LABNET.md"
    docs = docs_path.read_text(encoding="utf-8")
    section = f'''\n## Genesis-bound signature domain\n\nEvery SHRINCS transaction signature commits to:\n\n```text\n{CHAIN_DOMAIN_LABEL}\nSHA256 = {CHAIN_DOMAIN_HASH}\n```\n\nThis is intentionally incompatible with the earlier private-regtest fixture.\nA signature from that fixture cannot authorize an otherwise identical labnet\ntransaction, and changing the labnet genesis requires a new signature domain.\n'''
    docs_changed = section not in docs
    if docs_changed:
        docs_path.write_text(docs.rstrip() + "\n" + section, encoding="utf-8")

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
            "python_model": patch_python_model(),
            "native_tests": patch_native_test_domains(),
            "manifest_and_docs": patch_manifest_and_docs(),
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
