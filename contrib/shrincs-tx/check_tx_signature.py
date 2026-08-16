"""Exercise the PQBTC SHRINCS transaction digest through two verifier lines."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "contrib" / "shrincs-tx" / "tx_model.py"
DRAFT_COMMIT = "acc6bda51dc3b94848d118967247ad0f3cd7a80e"
PROFILE = "pqbtc-shrincs-tx-v0-signed-seam"


class TxSeamError(ValueError):
    """Raised when the signed transaction seam disagrees or loses binding."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TxSeamError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(
        spec is not None and spec.loader is not None,
        f"cannot load module from {path}",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def git_head(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def kdf(label: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def c_buffer(data: bytes):
    if not data:
        return None
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def load_c_verifier(path: Path):
    library = ctypes.CDLL(str(path.resolve()))
    verify = library.pqbtc_shrincs_verify
    verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    verify.restype = ctypes.c_int
    return verify


def verify_with_c(
    verify,
    public_key: bytes,
    signature: bytes,
    message: bytes,
    context: bytes,
) -> bool:
    return (
        verify(
            c_buffer(public_key),
            len(public_key),
            c_buffer(signature),
            len(signature),
            c_buffer(message),
            len(message),
            c_buffer(context),
            len(context),
        )
        == 1
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    require(git_head(args.shrincs_bip) == DRAFT_COMMIT, "draft checkout pin drifted")
    model = load_module(MODEL_PATH, "pqbtc_shrincs_tx_model")
    reference = load_module(args.shrincs_bip / "impl" / "shrincs.py", "shrincs_tx_reference")
    verify = load_c_verifier(args.library)

    seed = kdf(b"pqbtc-shrincs-tx-v0/seam/seed", 48)
    structure = bytes([reference.FXMSS_SHAPE_UNBALANCED, 4])
    secret_key, public_key = reference.shrincs_keygen(seed, structure)
    require(
        len(public_key) == model.PUBLIC_KEY_BYTES,
        "reference public-key length drifted",
    )

    tx = model.build_design_transaction(public_key)
    digest = model.transaction_sighash(tx, 0, model.TEST_CHAIN_ID)
    signature = reference.shrincs_sign(
        digest,
        model.SHRINCS_CONTEXT,
        secret_key,
        0,
        None,
    )
    require(signature is not None, "reference failed to produce stateful transaction signature")
    require(
        model.classify_signature(signature) == "stateful",
        "transaction seam did not use stateful mode",
    )
    require(
        reference.shrincs_verify(digest, signature, model.SHRINCS_CONTEXT, public_key),
        "reference rejected transaction signature",
    )
    require(
        verify_with_c(verify, public_key, signature, digest, model.SHRINCS_CONTEXT),
        "independent C verifier rejected transaction signature",
    )

    program = model.output_commitment(public_key)
    parsed_signature, parsed_key, mode = model.parse_witness([signature, public_key], program)
    require(
        parsed_signature == signature
        and parsed_key == public_key
        and mode == "stateful",
        "witness parse drifted",
    )

    rejected: list[str] = []
    for name, mutated_tx in model.transaction_surface_mutations(tx).items():
        mutated_digest = model.transaction_sighash(mutated_tx, 0, model.TEST_CHAIN_ID)
        require(mutated_digest != digest, f"{name} mutation did not change transaction digest")
        require(
            not reference.shrincs_verify(
                mutated_digest,
                signature,
                model.SHRINCS_CONTEXT,
                public_key,
            ),
            f"reference accepted signature after {name} mutation",
        )
        require(
            not verify_with_c(
                verify,
                public_key,
                signature,
                mutated_digest,
                model.SHRINCS_CONTEXT,
            ),
            f"independent verifier accepted signature after {name} mutation",
        )
        rejected.append(name)

    alternate_input_digest = model.transaction_sighash(tx, 1, model.TEST_CHAIN_ID)
    require(alternate_input_digest != digest, "input index did not change digest")
    require(
        not reference.shrincs_verify(
            alternate_input_digest,
            signature,
            model.SHRINCS_CONTEXT,
            public_key,
        ),
        "reference verified for a different input index",
    )
    require(
        not verify_with_c(
            verify,
            public_key,
            signature,
            alternate_input_digest,
            model.SHRINCS_CONTEXT,
        ),
        "signature verified for a different input index",
    )
    rejected.append("input_index")

    changed_chain = bytearray(model.TEST_CHAIN_ID)
    changed_chain[0] ^= 1
    changed_chain_digest = model.transaction_sighash(tx, 0, bytes(changed_chain))
    require(changed_chain_digest != digest, "chain-id mutation did not change digest")
    require(
        not reference.shrincs_verify(
            changed_chain_digest,
            signature,
            model.SHRINCS_CONTEXT,
            public_key,
        ),
        "reference verified under a different chain ID",
    )
    require(
        not verify_with_c(
            verify,
            public_key,
            signature,
            changed_chain_digest,
            model.SHRINCS_CONTEXT,
        ),
        "signature verified under a different chain ID",
    )
    rejected.append("chain_id")

    wrong_context = model.SHRINCS_CONTEXT + b"x"
    require(
        not reference.shrincs_verify(digest, signature, wrong_context, public_key),
        "reference verified under a different SHRINCS context",
    )
    require(
        not verify_with_c(verify, public_key, signature, digest, wrong_context),
        "signature verified under a different SHRINCS context",
    )
    rejected.append("shrincs_context")

    mutated_signature = bytearray(signature)
    mutated_signature[len(mutated_signature) // 2] ^= 1
    require(
        not reference.shrincs_verify(
            digest,
            bytes(mutated_signature),
            model.SHRINCS_CONTEXT,
            public_key,
        ),
        "reference accepted a signature-bit mutation",
    )
    require(
        not verify_with_c(
            verify,
            public_key,
            bytes(mutated_signature),
            digest,
            model.SHRINCS_CONTEXT,
        ),
        "independent verifier accepted a signature-bit mutation",
    )
    rejected.append("signature_bit")

    mutated_key = bytearray(public_key)
    mutated_key[0] ^= 1
    try:
        model.parse_witness([signature, bytes(mutated_key)], program)
    except model.TxModelError:
        pass
    else:
        raise TxSeamError("witness parser accepted a public-key commitment mutation")
    rejected.append("public_key_commitment")

    mutated_program = model.output_commitment(bytes(mutated_key))
    parsed_mutated_signature, parsed_mutated_key, _ = model.parse_witness(
        [signature, bytes(mutated_key)],
        mutated_program,
    )
    require(parsed_mutated_signature == signature, "mutated-key witness signature drifted")
    require(parsed_mutated_key == bytes(mutated_key), "mutated-key witness public key drifted")
    require(
        not reference.shrincs_verify(
            digest,
            signature,
            model.SHRINCS_CONTEXT,
            bytes(mutated_key),
        ),
        "reference accepted the signature under a different committed public key",
    )
    require(
        not verify_with_c(
            verify,
            bytes(mutated_key),
            signature,
            digest,
            model.SHRINCS_CONTEXT,
        ),
        "independent verifier accepted the signature under a different committed public key",
    )
    rejected.append("public_key_crypto")

    result: dict[str, Any] = {
        "profile": PROFILE,
        "result": "PASS",
        "draft_commit": DRAFT_COMMIT,
        "chain_id": model.TEST_CHAIN_ID.hex(),
        "context": model.SHRINCS_CONTEXT.hex(),
        "public_key": public_key.hex(),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "output_commitment": program.hex(),
        "signature": signature.hex(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "signature_bytes": len(signature),
        "signature_mode": mode,
        "transaction_digest": digest.hex(),
        "stripped_transaction": tx.serialize_stripped().hex(),
        "rejected_mutations": rejected,
        "rejected_mutation_count": len(rejected),
        "weight_one_input_two_outputs": model.transaction_weight_one_input_two_outputs(
            len(signature)
        ),
        "verifier_compressions_upper_bound": model.transaction_verifier_compressions(
            len(signature)
        ),
        "signature_bytes_exceed_verifier_compressions": (
            model.signature_bytes_exceed_verifier_compressions()
        ),
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(
            json.dumps(
                {
                    "profile": PROFILE,
                    "result": "PASS",
                    "signature_bytes": len(signature),
                    "rejected_mutation_count": len(rejected),
                    "signature_bytes_exceed_verifier_compressions": (
                        model.signature_bytes_exceed_verifier_compressions()
                    ),
                },
                sort_keys=True,
            )
        )
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
