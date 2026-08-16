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


def require_valid(
    reference: ModuleType,
    verify,
    public_key: bytes,
    signature: bytes,
    message: bytes,
    context: bytes,
    label: str,
) -> None:
    require(
        reference.shrincs_verify(message, signature, context, public_key),
        f"reference rejected {label}",
    )
    require(
        verify_with_c(verify, public_key, signature, message, context),
        f"independent C verifier rejected {label}",
    )


def require_rejected(
    reference: ModuleType,
    verify,
    public_key: bytes,
    signatures: dict[str, bytes],
    message: bytes,
    context: bytes,
    label: str,
    rejected: list[str],
) -> None:
    for mode, signature in signatures.items():
        require(
            not reference.shrincs_verify(message, signature, context, public_key),
            f"reference accepted {mode} signature after {label} mutation",
        )
        require(
            not verify_with_c(verify, public_key, signature, message, context),
            f"independent verifier accepted {mode} signature after {label} mutation",
        )
        rejected.append(f"{label}:{mode}")


def signature_record(model: ModuleType, signature: bytes) -> dict[str, Any]:
    return {
        "signature": signature.hex(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "signature_bytes": len(signature),
        "transaction_weight_one_input_two_outputs": (
            model.transaction_weight_one_input_two_outputs(len(signature))
        ),
        "verifier_compressions_upper_bound": model.transaction_verifier_compressions(
            len(signature)
        ),
    }


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
    stateful_signature = reference.shrincs_sign(
        digest,
        model.SHRINCS_CONTEXT,
        secret_key,
        0,
        None,
    )
    stateless_signature = reference.shrincs_sign(
        digest,
        model.SHRINCS_CONTEXT,
        secret_key,
        None,
        kdf(b"pqbtc-shrincs-tx-v0/seam/stateless-randomizer", 16),
    )
    require(stateful_signature is not None, "reference failed to produce stateful signature")
    require(stateless_signature is not None, "reference failed to produce stateless signature")
    signatures = {
        "stateful": stateful_signature,
        "stateless": stateless_signature,
    }

    program = model.output_commitment(public_key)
    for mode, signature in signatures.items():
        require(model.classify_signature(signature) == mode, f"{mode} classification drifted")
        require_valid(
            reference,
            verify,
            public_key,
            signature,
            digest,
            model.SHRINCS_CONTEXT,
            f"valid {mode} transaction signature",
        )
        parsed_signature, parsed_key, parsed_mode = model.parse_witness(
            [signature, public_key],
            program,
        )
        require(parsed_signature == signature, f"{mode} witness signature drifted")
        require(parsed_key == public_key, f"{mode} witness public key drifted")
        require(parsed_mode == mode, f"{mode} witness mode drifted")

    rejected: list[str] = []
    for name, mutated_tx in model.transaction_surface_mutations(tx).items():
        mutated_digest = model.transaction_sighash(mutated_tx, 0, model.TEST_CHAIN_ID)
        require(mutated_digest != digest, f"{name} mutation did not change transaction digest")
        require_rejected(
            reference,
            verify,
            public_key,
            signatures,
            mutated_digest,
            model.SHRINCS_CONTEXT,
            name,
            rejected,
        )

    alternate_input_digest = model.transaction_sighash(tx, 1, model.TEST_CHAIN_ID)
    require(alternate_input_digest != digest, "input index did not change digest")
    require_rejected(
        reference,
        verify,
        public_key,
        signatures,
        alternate_input_digest,
        model.SHRINCS_CONTEXT,
        "input_index",
        rejected,
    )

    changed_chain = bytearray(model.TEST_CHAIN_ID)
    changed_chain[0] ^= 1
    changed_chain_digest = model.transaction_sighash(tx, 0, bytes(changed_chain))
    require(changed_chain_digest != digest, "chain-id mutation did not change digest")
    require_rejected(
        reference,
        verify,
        public_key,
        signatures,
        changed_chain_digest,
        model.SHRINCS_CONTEXT,
        "chain_id",
        rejected,
    )

    require_rejected(
        reference,
        verify,
        public_key,
        signatures,
        digest,
        model.SHRINCS_CONTEXT + b"x",
        "shrincs_context",
        rejected,
    )

    for mode, signature in signatures.items():
        mutated_signature = bytearray(signature)
        mutated_signature[len(mutated_signature) // 2] ^= 1
        require(
            not reference.shrincs_verify(
                digest,
                bytes(mutated_signature),
                model.SHRINCS_CONTEXT,
                public_key,
            ),
            f"reference accepted {mode} signature-bit mutation",
        )
        require(
            not verify_with_c(
                verify,
                public_key,
                bytes(mutated_signature),
                digest,
                model.SHRINCS_CONTEXT,
            ),
            f"independent verifier accepted {mode} signature-bit mutation",
        )
        rejected.append(f"signature_bit:{mode}")

    mutated_key = bytearray(public_key)
    mutated_key[0] ^= 1
    for mode, signature in signatures.items():
        try:
            model.parse_witness([signature, bytes(mutated_key)], program)
        except model.TxModelError:
            pass
        else:
            raise TxSeamError(
                f"witness parser accepted {mode} public-key commitment mutation"
            )
        rejected.append(f"public_key_commitment:{mode}")

    mutated_program = model.output_commitment(bytes(mutated_key))
    for mode, signature in signatures.items():
        parsed_signature, parsed_key, parsed_mode = model.parse_witness(
            [signature, bytes(mutated_key)],
            mutated_program,
        )
        require(parsed_signature == signature, f"{mode} mutated-key signature drifted")
        require(parsed_key == bytes(mutated_key), f"{mode} mutated-key public key drifted")
        require(parsed_mode == mode, f"{mode} mutated-key mode drifted")
        require(
            not reference.shrincs_verify(
                digest,
                signature,
                model.SHRINCS_CONTEXT,
                bytes(mutated_key),
            ),
            f"reference accepted {mode} signature under a different committed key",
        )
        require(
            not verify_with_c(
                verify,
                bytes(mutated_key),
                signature,
                digest,
                model.SHRINCS_CONTEXT,
            ),
            f"independent verifier accepted {mode} signature under a different committed key",
        )
        rejected.append(f"public_key_crypto:{mode}")

    require(len(rejected) == 56, "signed-seam rejection coverage drifted")
    result: dict[str, Any] = {
        "profile": PROFILE,
        "result": "PASS",
        "draft_commit": DRAFT_COMMIT,
        "chain_id": model.TEST_CHAIN_ID.hex(),
        "context": model.SHRINCS_CONTEXT.hex(),
        "public_key": public_key.hex(),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "output_commitment": program.hex(),
        "transaction_digest": digest.hex(),
        "stripped_transaction": tx.serialize_stripped().hex(),
        "signatures": {
            mode: signature_record(model, signature)
            for mode, signature in signatures.items()
        },
        "rejected_cases": rejected,
        "rejected_case_count": len(rejected),
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
                    "stateful_signature_bytes": len(stateful_signature),
                    "stateless_signature_bytes": len(stateless_signature),
                    "rejected_case_count": len(rejected),
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
