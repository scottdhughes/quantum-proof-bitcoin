"""Register the mined SHRINCS functional gate and normalize labnet metadata."""

from __future__ import annotations

import json
from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "ci" / "test" / "functional_suite_inventory.json"
PQ_TESTS = ROOT / "ci" / "test" / "pq_functional_tests.txt"
LINT_IGNORES = ROOT / "test" / "lint" / "lint_ignore_dirs.py"
GITIGNORE = ROOT / ".gitignore"
LABNET_CONTROLLER = ROOT / "contrib" / "shrincs-labnet" / "labnet.py"
LABNET_TESTS = ROOT / "contrib" / "shrincs-labnet" / "test_labnet.py"
FUNCTIONAL_TEST = "feature_shrincs_regtest.py"
ENTRY = {
    "name": FUNCTIONAL_TEST,
    "policy_class": "pq_required",
    "owner": "@scottdhughes",
    "tracking_issue": "#239",
    "notes": (
        "Owned PQBTC-SHRINCS-v0 regtest gate: funds genuine witness-v2 outputs, "
        "produces both stateful and stateless current-profile signatures with the "
        "exact pinned executable model, proves one-bit mutations are rejected, "
        "broadcasts both valid spends through node validation, and mines them."
    ),
}
EXECUTABLES = (
    LABNET_CONTROLLER,
    LABNET_TESTS,
    ROOT / "test" / "functional" / FUNCTIONAL_TEST,
)
VENDORED_LINT_SUBTREE = "src/crypto/shrincs/third_party/libshrincs/"
LABNET_STATE_IGNORE = "/.shrincs-labnet/"

OLD_CONFIG_TEXT = '''    def config_text(self) -> str:
        return "\\n".join(
            [
                "regtest=1",
                "server=1",
                "listen=1",
                f"port={self.p2p_port}",
                f"rpcport={self.rpc_port}",
                "rpcbind=127.0.0.1",
                "rpcallowip=127.0.0.1",
                "discover=0",
                "dnsseed=0",
                "fixedseeds=0",
                "listenonion=0",
                "upnp=0",
                "natpmp=0",
                "txindex=1",
                "acceptnonstdtxn=1",
                "fallbackfee=0.00010000",
                "persistmempool=1",
                "printtoconsole=0",
                "",
            ]
        )
'''

NEW_CONFIG_TEXT = '''    def config_text(self) -> str:
        return "\\n".join(
            [
                "regtest=1",
                "server=1",
                "listen=1",
                "discover=0",
                "dnsseed=0",
                "fixedseeds=0",
                "listenonion=0",
                "upnp=0",
                "natpmp=0",
                "txindex=1",
                "acceptnonstdtxn=1",
                "fallbackfee=0.00010000",
                "persistmempool=1",
                "printtoconsole=0",
                "",
                "[regtest]",
                f"port={self.p2p_port}",
                f"rpcport={self.rpc_port}",
                "rpcbind=127.0.0.1",
                "rpcallowip=127.0.0.1",
                "",
            ]
        )
'''

NODE_CONFIG_TEST = '''

class NodeConfigTests(unittest.TestCase):
    def test_network_bindings_live_under_regtest_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layout = labnet.Layout(root / "state", root / "build")
            text = layout.node0.config_text()

        global_settings, regtest_settings = text.split("[regtest]\\n", 1)
        self.assertIn("regtest=1\\n", global_settings)
        for setting in (
            "port=19444",
            "rpcport=19443",
            "rpcbind=127.0.0.1",
            "rpcallowip=127.0.0.1",
        ):
            with self.subTest(setting=setting):
                self.assertNotIn(setting, global_settings)
                self.assertIn(setting, regtest_settings)
'''


def write_if_changed(path: Path, content: str) -> bool:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def register_inventory() -> tuple[list[dict[str, object]], bool]:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if not isinstance(inventory, list):
        raise RuntimeError("functional inventory must be a JSON array")

    matches = [index for index, item in enumerate(inventory) if item.get("name") == FUNCTIONAL_TEST]
    if len(matches) > 1:
        raise RuntimeError(f"duplicate functional inventory entries for {FUNCTIONAL_TEST}")
    if matches:
        inventory[matches[0]] = ENTRY
    else:
        position = next(
            (
                index
                for index, item in enumerate(inventory)
                if str(item.get("name", "")) > FUNCTIONAL_TEST
            ),
            len(inventory),
        )
        inventory.insert(position, ENTRY)

    changed = write_if_changed(
        INVENTORY,
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
    )
    return inventory, changed


def regenerate_pq_gate_list(inventory: list[dict[str, object]]) -> bool:
    names = [
        str(entry["name"])
        for entry in inventory
        if entry.get("policy_class") == "pq_required"
    ]
    return write_if_changed(PQ_TESTS, "\n".join(names) + "\n")


def register_vendored_lint_subtree() -> bool:
    text = LINT_IGNORES.read_text(encoding="utf-8")
    line = f'    "{VENDORED_LINT_SUBTREE}",\n'
    if line in text:
        return False
    anchor = '    "src/leveldb/",\n'
    if anchor not in text:
        raise RuntimeError("shared lint exclusion anchor not found")
    return write_if_changed(LINT_IGNORES, text.replace(anchor, line + anchor, 1))


def register_local_state_ignore() -> bool:
    text = GITIGNORE.read_text(encoding="utf-8")
    if LABNET_STATE_IGNORE in text.splitlines():
        return False
    if not text.endswith("\n"):
        text += "\n"
    return write_if_changed(
        GITIGNORE,
        text + "\n# Private zero-value SHRINCS labnet state and secret-key database.\n"
        + LABNET_STATE_IGNORE
        + "\n",
    )


def normalize_regtest_config_section() -> bool:
    changed = False
    controller = LABNET_CONTROLLER.read_text(encoding="utf-8")
    if OLD_CONFIG_TEXT in controller:
        controller = controller.replace(OLD_CONFIG_TEXT, NEW_CONFIG_TEXT, 1)
        changed = write_if_changed(LABNET_CONTROLLER, controller) or changed
    elif NEW_CONFIG_TEXT not in controller:
        raise RuntimeError("labnet node-config anchor not found")

    tests = LABNET_TESTS.read_text(encoding="utf-8")
    if "class NodeConfigTests" not in tests:
        anchor = "\n\nclass SignerStoreTests(unittest.TestCase):"
        if anchor not in tests:
            raise RuntimeError("labnet test insertion anchor not found")
        tests = tests.replace(
            anchor,
            NODE_CONFIG_TEST + anchor,
            1,
        )
        changed = write_if_changed(LABNET_TESTS, tests) or changed
    return changed


def normalize_executable_modes() -> bool:
    changed = False
    for path in EXECUTABLES:
        if not path.is_file():
            raise RuntimeError(f"missing executable script: {path.relative_to(ROOT)}")
        old_mode = path.stat().st_mode
        new_mode = old_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        if new_mode != old_mode:
            path.chmod(new_mode)
            changed = True
    return changed


def main() -> int:
    inventory, inventory_changed = register_inventory()
    changes = {
        "inventory": inventory_changed,
        "pq_gate_list": regenerate_pq_gate_list(inventory),
        "vendored_lint_exclusion": register_vendored_lint_subtree(),
        "gitignore": register_local_state_ignore(),
        "regtest_config_section": normalize_regtest_config_section(),
        "executable_modes": normalize_executable_modes(),
    }
    print(json.dumps({"result": "PASS", "changes": changes}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
