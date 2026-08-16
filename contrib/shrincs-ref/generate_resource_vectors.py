"""Generate adversarial resource vectors for the pinned SHRINCS draft."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
PROFILE = "pqbtc-shrincs-current-draft-resource-v0"


class ResourceVectorError(ValueError):
    """Raised when the pinned reference cannot produce a resource vector."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ResourceVectorError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def kdf(label: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def encode_vector(
    name: str,
    mode: str,
    message: bytes,
    context: bytes,
    public_key: bytes,
    signature: bytes,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "mode": mode,
        "message": message.hex(),
        "context": context.hex(),
        "public_key": public_key.hex(),
        "signature": signature.hex(),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    result.update(extra)
    return result


def create_stateful_maximum(reference: ModuleType) -> dict[str, Any]:
    structure = bytes([reference.FXMSS_SHAPE_UNBALANCED, 255])
    state = 254
    seed = kdf(b"pqbtc-shrincs-resource/stateful-max/seed", 48)
    sk_seed = seed[0:16]
    sk_prf = seed[16:32]
    pk_seed = seed[32:48]
    stateless_root = kdf(b"pqbtc-shrincs-resource/stateful-max/stateless-root", 16)
    stateful_root = reference.fxmss_node(
        sk_seed,
        0,
        reference.FXMSS_HEIGHT,
        pk_seed,
        structure,
        bytearray(22),
    )
    secret_key = sk_seed + sk_prf + pk_seed + stateless_root + structure + stateful_root
    public_key = pk_seed + stateless_root + stateful_root
    message = kdf(b"pqbtc-shrincs-resource/stateful-max/message", 4096)
    context = kdf(b"pqbtc-shrincs-resource/stateful-max/context", 255)

    position = reference.shrincs_sf_leaf_select(structure, state)
    require(position is not None, "maximum-depth stateful leaf unavailable")
    leaf_index, leaf_height = position
    leaf_depth = reference.FXMSS_HEIGHT - leaf_height
    require(leaf_depth == 255, "maximum-depth stateful vector did not select depth 255")

    signature = reference.shrincs_sign(message, context, secret_key, state, None)
    require(signature is not None, "maximum-depth stateful signing failed")
    require(len(signature) == 4618, "maximum-depth stateful signature length drifted")
    require(
        reference.shrincs_verify(message, signature, context, public_key),
        "reference rejected maximum-depth stateful signature",
    )
    return encode_vector(
        "stateful_max_depth_message_context",
        "stateful",
        message,
        context,
        public_key,
        signature,
        structure=structure.hex(),
        state=state,
        leaf_index=leaf_index,
        leaf_depth=leaf_depth,
    )


def create_stateless_maximum_message(reference: ModuleType) -> dict[str, Any]:
    seed = kdf(b"pqbtc-shrincs-resource/stateless-max-message/seed", 48)
    sk_seed = seed[0:16]
    sk_prf = seed[16:32]
    pk_seed = seed[32:48]
    stateful_root = kdf(b"pqbtc-shrincs-resource/stateless-max-message/stateful-root", 16)

    address = bytearray(22)
    address[0] = reference.SPHX_LAYER_COUNT - 1
    stateless_root = reference.xmss_node(
        sk_seed,
        0,
        reference.SPHX_XMSS_HEIGHT,
        pk_seed,
        address,
    )
    structure = bytes([reference.FXMSS_SHAPE_UNBALANCED, 0])
    secret_key = sk_seed + sk_prf + pk_seed + stateless_root + structure + stateful_root
    public_key = pk_seed + stateless_root + stateful_root
    message = kdf(b"pqbtc-shrincs-resource/stateless-max-message/message", 4096)
    context = kdf(b"pqbtc-shrincs-resource/stateless-max-message/context", 255)
    opt_rand = kdf(b"pqbtc-shrincs-resource/stateless-max-message/randomizer", 16)

    signature = reference.shrincs_sign(message, context, secret_key, None, opt_rand)
    require(signature is not None, "maximum-message stateless signing failed")
    require(len(signature) == 5776, "stateless signature length drifted")
    require(
        reference.shrincs_verify(message, signature, context, public_key),
        "reference rejected maximum-message stateless signature",
    )
    return encode_vector(
        "stateless_max_message_context",
        "stateless",
        message,
        context,
        public_key,
        signature,
        opt_rand=opt_rand.hex(),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    expected_commit = manifest["upstream"]["draft_specification"]["commit"]
    require(git_head(args.shrincs_bip) == expected_commit, "draft checkout does not match manifest")
    reference = load_module(
        args.shrincs_bip / "impl" / "shrincs.py",
        "shrincs_resource_reference",
    )

    vectors = [create_stateful_maximum(reference), create_stateless_maximum_message(reference)]
    data = {
        "profile": PROFILE,
        "draft_commit": expected_commit,
        "vectors": vectors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = {
        "result": "PASS",
        "vectors": len(vectors),
        "stateful_signature_bytes": len(bytes.fromhex(vectors[0]["signature"])),
        "stateless_signature_bytes": len(bytes.fromhex(vectors[1]["signature"])),
        "message_bytes": 4096,
        "context_bytes": 255,
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
