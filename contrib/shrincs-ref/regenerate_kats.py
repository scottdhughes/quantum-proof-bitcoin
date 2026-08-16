"""Regenerate and byte-compare the committed full-profile SHRINCS KATs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
DEFAULT_VECTOR_DIR = REPO_ROOT / "contrib" / "shrincs-ref" / "vectors"


class RegenerationError(ValueError):
    """Raised when deterministic KAT regeneration disagrees with the commit."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegenerationError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def serialize_vectors(
    profile: str,
    manifest: dict[str, Any],
    vectors: list[dict[str, Any]],
) -> bytes:
    return (
        json.dumps(
            {
                "profile": profile,
                "draft_commit": manifest["upstream"]["draft_specification"]["commit"],
                "libshrincs_commit": manifest["upstream"]["libshrincs_wotsc"]["commit"],
                "vectors": vectors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--vector-dir", type=Path, default=DEFAULT_VECTOR_DIR)
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--libshrincs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    stateful = load_module(
        REPO_ROOT / "contrib" / "shrincs-ref" / "check_stateful_fxmss.py",
        "pqbtc_regenerate_stateful",
    )
    stateless = load_module(
        REPO_ROOT / "contrib" / "shrincs-ref" / "check_stateless.py",
        "pqbtc_regenerate_stateless",
    )
    kat_loader = load_module(
        REPO_ROOT / "contrib" / "shrincs-ref" / "kat_loader.py",
        "pqbtc_regenerate_kat_loader",
    )

    manifest = stateful.load_manifest(args.manifest)
    stateful.validate_pins(manifest, args.shrincs_bip, args.libshrincs)
    reference = stateful.load_module(
        args.shrincs_bip / "impl" / "shrincs.py",
        "pqbtc_regenerate_pinned_draft",
    )

    generated = {
        "stateful": serialize_vectors(
            "pqbtc-shrincs-current-draft-stateful-kat-v0",
            manifest,
            stateful.create_vectors(reference),
        ),
        "stateless": serialize_vectors(
            stateless.VECTOR_PROFILE,
            manifest,
            stateless.create_vectors(reference),
        ),
    }

    kat_manifest = kat_loader.load_manifest(args.vector_dir / "manifest.json")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"corpora": {}, "result": "PASS"}
    for name, raw in generated.items():
        committed_raw, committed_data = kat_loader.load_corpus(
            name,
            args.vector_dir,
            kat_manifest,
        )
        require(raw == committed_raw, f"regenerated {name} KAT bytes differ from the commitment")
        output_path = args.output_dir / f"{name}-vectors.json"
        output_path.write_bytes(raw)
        result["corpora"][name] = {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "vectors": len(committed_data["vectors"]),
        }

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "SHRINCS KAT regeneration: PASS "
            f"(stateful={result['corpora']['stateful']['vectors']}, "
            f"stateless={result['corpora']['stateless']['vectors']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
