#!/usr/bin/env python3
"""Verify deterministic PQBTC artifacts are reproducible and unchanged."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENESIS_PATH = ROOT / "contrib" / "genesis" / "generated_constants.json"
KAT_PATH = ROOT / "src" / "test" / "data" / "pqsig" / "kat_v1.json"


def load_module(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def canonical_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def check_genesis() -> str:
    committed = json.loads(GENESIS_PATH.read_text(encoding="utf-8"))
    generator = load_module(ROOT / "contrib" / "genesis" / "generate_constants.py", "pqb_genesis")
    regenerated = generator.generate(committed["seed"])

    if regenerated != committed:
        raise RuntimeError("genesis constants drift detected: regenerate contrib/genesis/generated_constants.json")
    return canonical_digest(committed)


def check_kat() -> str:
    sys.path.insert(0, str(ROOT / "contrib" / "pqsig-ref"))
    gen_kat = load_module(ROOT / "contrib" / "pqsig-ref" / "gen_kat.py", "pqb_gen_kat")
    committed = json.loads(KAT_PATH.read_text(encoding="utf-8"))

    regenerated = {
        "profile": "pqsig-rc2-2^40-4480",
        "vectors": [
            gen_kat.make_vector("kat_01", "1f" * 32, "42" * 32),
            gen_kat.make_vector("kat_02", "2a" * 32, "11" * 32),
            gen_kat.make_vector("kat_03", "3b" * 32, "00" * 31 + "7f"),
        ],
    }

    if regenerated != committed:
        raise RuntimeError("PQSig KAT drift detected: regenerate src/test/data/pqsig/kat_v1.json")
    return canonical_digest(committed)


def main() -> int:
    try:
        genesis_digest = check_genesis()
        kat_digest = check_kat()
    except Exception as exc:  # noqa: BLE001
        print(f"check_deterministic_artifacts.py: {exc}", file=sys.stderr)
        return 1

    print("Deterministic artifacts verified")
    print(f"  genesis_sha256={genesis_digest}")
    print(f"  pqsig_kat_sha256={kat_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
