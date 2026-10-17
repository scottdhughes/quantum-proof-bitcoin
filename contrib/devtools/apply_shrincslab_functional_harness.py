#!/usr/bin/env python3
"""Point the SHRINCS functional test at the isolated labnet cookie/log path.

The test intentionally keeps ``self.chain == 'regtest'`` while creating its
configuration so the mature framework continues to emit ``regtest=1`` and a
``[regtest]`` section with deterministic test ports.  Only the instantiated
``TestNode.chain`` value is overridden to ``shrincslab``; that value controls
where the framework reads the RPC cookie and debug log after the node selects
its dedicated base data directory.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "test/functional/feature_shrincs_regtest.py"


def main() -> int:
    text = TARGET.read_text(encoding="utf-8")
    old = '        self.extra_args = [["-shrincslab", "-acceptnonstdtxn=1"]]\n'
    new = (
        old
        + '        # The config remains regtest-shaped, but the node stores cookies, logs,\n'
        + '        # wallets, and chainstate below the isolated shrincslab/ directory.\n'
        + '        self.extra_init = [{"chain": "shrincslab"}]\n'
    )
    if new in text:
        print("SHRINCS functional harness already targets shrincslab/.")
        return 0
    if old not in text:
        raise SystemExit("SHRINCS functional-test parameter anchor not found")
    TARGET.write_text(text.replace(old, new, 1), encoding="utf-8")
    print("Adapted SHRINCS functional harness to shrincslab/ cookie and log paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
