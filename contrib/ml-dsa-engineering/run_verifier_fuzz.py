#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import argparse
import base64
import binascii
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

import run_wrapper_tests as wrapper


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FUZZ_SOURCE = HERE / "pqbtc_mldsa44_verify_fuzz.c"
CORPUS_MANIFEST = HERE / "verifier_fuzz_corpus.json"
WYCHEPROOF_DIR = HERE / "fuzz_sources" / "wycheproof"
WYCHEPROOF_SOURCE = WYCHEPROOF_DIR / "SOURCE.json"
WYCHEPROOF_LICENSE = WYCHEPROOF_DIR / "LICENSE"
WYCHEPROOF_VECTORS = WYCHEPROOF_DIR / "mldsa_44_verify_test.json"
PROMOTED_DIR = HERE / "fuzz_sources" / "promoted"
PROMOTED_SOURCE = PROMOTED_DIR / "SOURCE.json"

FRAME_HEADER = struct.Struct("<BBHHHH")
FRAME_VERSION = 1
NULL_SIGNATURE = 0x01
NULL_PUBLIC_KEY = 0x02
NULL_CONTEXT = 0x04
NULL_MESSAGE = 0x08
NULL_MASK = 0x0F
MAX_SIGNATURE_BYTES = 2421
MAX_PUBLIC_KEY_BYTES = 1313
MAX_CONTEXT_BYTES = 256
MAX_MESSAGE_BYTES = 4096
MAX_FRAME_BYTES = (
    FRAME_HEADER.size
    + MAX_SIGNATURE_BYTES
    + MAX_PUBLIC_KEY_BYTES
    + MAX_CONTEXT_BYTES
    + MAX_MESSAGE_BYTES
)

CTILDE_BYTES = 32
Z_BYTES = 2304
HINT_OFFSET = CTILDE_BYTES + Z_BYTES
HINT_INDICES = 80
HINT_COUNTERS = 4

OK = 0
ERR_INVALID_ARGUMENT = -1
ERR_VERIFY = -9
RESULT_NAMES = {
    OK: "ok",
    ERR_INVALID_ARGUMENT: "invalid_argument",
    ERR_VERIFY: "verify_rejection",
}
PROMOTED_SOURCE_IDENTITY = {
    "repository": "https://github.com/scottdhughes/quantum-proof-bitcoin",
    "repository_commit": "6d237f467f3a55d5cc48ca584a060251bdbf97dc",
    "workflow": ".github/workflows/ml-dsa-44-review-reproduction.yml",
    "workflow_run_id": 29971871087,
    "workflow_run_attempt": 1,
    "job_id": 89095408293,
    "artifact_id": 8550615906,
    "artifact_name": (
        "ml-dsa-44-review-evidence-"
        "6d237f467f3a55d5cc48ca584a060251bdbf97dc"
    ),
    "artifact_digest": (
        "sha256:5566d45b97bdca1bdf7050d68d85a840"
        "7048526bcbf042aac9450dbeadd14288"
    ),
    "artifact_size_bytes": 1676931,
    "artifact_created_at": "2026-07-23T02:08:43Z",
    "artifact_expires_at": "2026-10-21T01:28:10Z",
    "evidence_manifest_sha256": (
        "7230ab2f48a125df4a82ee4efe976c5929d279e7e8cf3bb8abd0aad5394fd6fe"
    ),
    "retained_source_run_id": 29863344728,
    "retained_source_run_attempt": 1,
    "retained_source_head_sha": "37b1330a717acd39be4465a9110119b3db1eee89",
    "retained_source_artifact": (
        "ml-dsa-44-review-evidence-"
        "37b1330a717acd39be4465a9110119b3db1eee89"
    ),
    "campaign_seed": 4202067318,
    "campaign_seconds": 1800,
    "promoted_at": "2026-07-23",
}
PROMOTED_SELECTION = {
    "rule": (
        "SHA256(frame) absent from both the baseline unique frames "
        "and the imported retained frames"
    ),
    "candidate_minimized_cases": 141,
    "candidate_minimized_bytes": 493706,
    "candidate_minimized_aggregate_sha256": (
        "96b2fe1c21cbdfebb00c429bd26040cc09d2abb622ecee766954c32b6f61575b"
    ),
    "baseline_generated_cases": 207,
    "baseline_unique_frames": 202,
    "imported_retained_unique_frames": 72,
    "candidate_baseline_overlap": 50,
    "candidate_retained_overlap": 53,
    "baseline_retained_overlap": 0,
    "selected_cases": 38,
    "selected_bytes": 120844,
    "expected_counts": {
        "invalid_argument": 13,
        "verify_rejection": 25,
    },
    "inventory_sha256_format": (
        "lowercase digest followed by LF, lexicographically sorted"
    ),
    "candidate_sha256_inventory_sha256": (
        "c6320986ab7d421b615db05bb35e56793b855f0b01d41cb200a67485a7c2208d"
    ),
    "baseline_sha256_inventory_sha256": (
        "eb11480400e8ef376e4612ac584fa7eeda80f02f270590ceac5e62e60c25e72a"
    ),
    "retained_sha256_inventory_sha256": (
        "27768fcaf1337f1658325e0824c52ce246600459ef18c809f23822a6ae5b4b24"
    ),
    "selected_sha256_inventory_sha256": (
        "0c5b39103c4b18df8ad0e10a2f973fd226053e6d609480bef41b0108f6bdbfd5"
    ),
    "metadata_sha256_format": (
        "for each SHA256-sorted case: sha256 NUL decimal_size NUL "
        "expected_result NUL artifact_member LF"
    ),
    "metadata_sha256": (
        "3e9e972fdba69f3fc2c77df31f4e43b4797eb4f32537e3d72d2387f4c17975df"
    ),
    "frames_sha256_format": (
        "for each SHA256-sorted case: uint32_le(size) followed by frame bytes"
    ),
    "frames_sha256": (
        "a63099a9e7cbfadb72a1487509288e613d91b3b8dcd0c62cc013810c08fc27b0"
    ),
}
SANITIZERS = {
    "address-undefined": "fuzzer,address,undefined",
    "memory": "fuzzer,memory",
}
CAMPAIGN_SCHEMA_VERSION = 1
MAX_RETAINED_CORPUS_FILES = 4096
MAX_RETAINED_CORPUS_BYTES = 32 * 1024 * 1024
CAMPAIGN_TIMEOUT_ALLOWANCE_SECONDS = 30
CORPUS_MINIMIZATION_TIMEOUT_SECONDS = 150
CRASH_MINIMIZATION_TIMEOUT_SECONDS = 75


class FuzzHarnessError(RuntimeError):
    pass


@dataclass(frozen=True)
class CorpusCase:
    name: str
    source: str
    frame: bytes
    expected: int


@dataclass(frozen=True)
class DecodedFrame:
    null_flags: int
    signature: bytes
    public_key: bytes
    context: bytes
    message: bytes


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_file(path: Path, expected_size: int, expected_sha256: str) -> None:
    if path.stat().st_size != expected_size:
        raise FuzzHarnessError(f"unexpected size for {path.relative_to(REPO_ROOT)}")
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise FuzzHarnessError(
            f"unexpected SHA256 for {path.relative_to(REPO_ROOT)}: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def validate_wycheproof_source() -> dict:
    expected_files = ["LICENSE", "SOURCE.json", "mldsa_44_verify_test.json"]
    actual_files = sorted(path.name for path in WYCHEPROOF_DIR.iterdir() if path.is_file())
    if actual_files != expected_files:
        raise FuzzHarnessError("Wycheproof source capsule file set differs from SOURCE.json")

    source = json.loads(WYCHEPROOF_SOURCE.read_text(encoding="utf8"))
    if source.get("schema_version") != 1:
        raise FuzzHarnessError("unsupported Wycheproof source manifest schema")
    if source["source"] != {
        "repository": "https://github.com/C2SP/wycheproof",
        "commit": "fc24cd5b787d8e496bff31b0468af693a652b0f2",
        "license": "Apache-2.0",
        "imported": "2026-07-20",
    }:
        raise FuzzHarnessError("unexpected Wycheproof source identity")

    license_record = source["license_file"]
    require_file(
        WYCHEPROOF_LICENSE,
        license_record["size"],
        license_record["sha256"],
    )
    vector_record = source["vector_file"]
    require_file(
        WYCHEPROOF_VECTORS,
        vector_record["size"],
        vector_record["sha256"],
    )

    vectors = json.loads(WYCHEPROOF_VECTORS.read_text(encoding="utf8"))
    if (
        vectors.get("algorithm") != vector_record["algorithm"]
        or str(vectors.get("generatorVersion")) != vector_record["generator_version"]
        or vectors.get("numberOfTests") != vector_record["number_of_tests"]
    ):
        raise FuzzHarnessError("Wycheproof vector metadata differs from SOURCE.json")
    tests = [test for group in vectors["testGroups"] for test in group["tests"]]
    if len(tests) != vector_record["number_of_tests"]:
        raise FuzzHarnessError("Wycheproof test count does not match numberOfTests")
    test_ids = [test["tcId"] for test in tests]
    if len(set(test_ids)) != len(test_ids):
        raise FuzzHarnessError("Wycheproof test IDs are not unique")
    if any(test["result"] not in {"valid", "invalid"} for test in tests):
        raise FuzzHarnessError("unsupported Wycheproof expected result")
    return vectors


def reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FuzzHarnessError(f"duplicate JSON key in promoted source: {key}")
        result[key] = value
    return result


def reject_nonfinite_json_constant(value):
    raise FuzzHarnessError(f"non-finite JSON value in promoted source: {value}")


def exact_json_value(actual, expected) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            exact_json_value(actual[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            exact_json_value(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def load_promoted_source_manifest(source_path: Path = PROMOTED_SOURCE) -> dict:
    source_path = source_path.absolute()
    source_dir = source_path.parent
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise FuzzHarnessError("promoted source directory must be a regular directory")
    try:
        entries = sorted(source_dir.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise FuzzHarnessError(
            f"cannot inspect promoted source directory: {error}"
        ) from error
    if [path.name for path in entries] != ["SOURCE.json"]:
        raise FuzzHarnessError(
            "promoted source capsule file set differs from SOURCE.json"
        )
    if source_path.name != "SOURCE.json" or any(
        path.is_symlink() or not path.is_file() for path in entries
    ):
        raise FuzzHarnessError("promoted source capsule contains a non-regular entry")

    try:
        manifest = json.loads(
            source_path.read_text(encoding="utf8"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_nonfinite_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FuzzHarnessError(
            f"cannot parse promoted source capsule: {error}"
        ) from error
    if type(manifest) is not dict or set(manifest) != {
        "schema_version",
        "frame_version",
        "source",
        "selection",
        "derivation",
        "cases",
    }:
        raise FuzzHarnessError("unexpected promoted source manifest fields")
    if (
        type(manifest["schema_version"]) is not int
        or type(manifest["frame_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["frame_version"] != FRAME_VERSION
    ):
        raise FuzzHarnessError("unsupported promoted source manifest schema")
    if not exact_json_value(manifest["source"], PROMOTED_SOURCE_IDENTITY):
        raise FuzzHarnessError("unexpected promoted source identity")
    if not exact_json_value(manifest["selection"], PROMOTED_SELECTION):
        raise FuzzHarnessError("unexpected promoted source selection metadata")
    return manifest


def validate_digest_inventory(
    values, label: str, expected_count: int, expected_sha256: str
) -> set[str]:
    if type(values) is not list or len(values) != expected_count:
        raise FuzzHarnessError(f"unexpected {label} inventory count")
    if any(
        type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in values
    ):
        raise FuzzHarnessError(f"invalid {label} inventory digest")
    if values != sorted(set(values)):
        raise FuzzHarnessError(f"{label} inventory is not unique and sorted")
    digest = hashlib.sha256("".join(f"{value}\n" for value in values).encode())
    if digest.hexdigest() != expected_sha256:
        raise FuzzHarnessError(f"{label} inventory aggregate differs")
    return set(values)


def validate_promoted_source(source_path: Path = PROMOTED_SOURCE) -> list[CorpusCase]:
    manifest = load_promoted_source_manifest(source_path)
    derivation = manifest["derivation"]
    if type(derivation) is not dict or set(derivation) != {
        "hash_algorithm",
        "inventory_format",
        "set_rule",
        "candidate_minimized_sha256",
        "baseline_unique_sha256",
        "imported_retained_sha256",
    }:
        raise FuzzHarnessError("unexpected promoted source derivation fields")
    expected_derivation_strings = {
        "hash_algorithm": "SHA-256",
        "inventory_format": PROMOTED_SELECTION["inventory_sha256_format"],
        "set_rule": (
            "selected case SHA256 set equals candidate minimized SHA256 set "
            "minus baseline unique SHA256 set minus imported retained SHA256 set"
        ),
    }
    if any(
        type(derivation[key]) is not str
        or derivation[key] != expected_derivation_strings[key]
        for key in expected_derivation_strings
    ):
        raise FuzzHarnessError("unexpected promoted source derivation contract")
    candidate_hashes = validate_digest_inventory(
        derivation["candidate_minimized_sha256"],
        "candidate minimized",
        PROMOTED_SELECTION["candidate_minimized_cases"],
        PROMOTED_SELECTION["candidate_sha256_inventory_sha256"],
    )
    baseline_inventory = validate_digest_inventory(
        derivation["baseline_unique_sha256"],
        "baseline unique",
        PROMOTED_SELECTION["baseline_unique_frames"],
        PROMOTED_SELECTION["baseline_sha256_inventory_sha256"],
    )
    retained_hashes = validate_digest_inventory(
        derivation["imported_retained_sha256"],
        "imported retained",
        PROMOTED_SELECTION["imported_retained_unique_frames"],
        PROMOTED_SELECTION["retained_sha256_inventory_sha256"],
    )
    if len(candidate_hashes & baseline_inventory) != PROMOTED_SELECTION[
        "candidate_baseline_overlap"
    ]:
        raise FuzzHarnessError("candidate/baseline overlap count differs")
    if len(candidate_hashes & retained_hashes) != PROMOTED_SELECTION[
        "candidate_retained_overlap"
    ]:
        raise FuzzHarnessError("candidate/retained overlap count differs")
    if len(baseline_inventory & retained_hashes) != PROMOTED_SELECTION[
        "baseline_retained_overlap"
    ]:
        raise FuzzHarnessError("baseline/retained overlap count differs")
    records = manifest["cases"]
    if (
        type(records) is not list
        or len(records) != PROMOTED_SELECTION["selected_cases"]
    ):
        raise FuzzHarnessError("unexpected promoted source case count")

    cases = []
    metadata_digest = hashlib.sha256()
    frames_digest = hashlib.sha256()
    expected_counts = {"invalid_argument": 0, "verify_rejection": 0}
    total_bytes = 0
    previous_digest = None
    frame_digests = set()
    artifact_members = set()
    expected_results = {
        "invalid_argument": ERR_INVALID_ARGUMENT,
        "verify_rejection": ERR_VERIFY,
    }
    for record in records:
        if type(record) is not dict or set(record) != {
            "artifact_member",
            "expected_result",
            "frame_base64",
            "sha256",
            "size",
        }:
            raise FuzzHarnessError("unexpected promoted source case fields")
        artifact_member = record["artifact_member"]
        expected_name = record["expected_result"]
        encoded = record["frame_base64"]
        frame_sha256 = record["sha256"]
        size = record["size"]
        if (
            type(artifact_member) is not str
            or re.fullmatch(
                r"ml-dsa-44-differential-fuzz/minimized-corpus/[0-9a-f]{40}",
                artifact_member,
            )
            is None
        ):
            raise FuzzHarnessError("invalid promoted source artifact member")
        if type(expected_name) is not str or expected_name not in expected_results:
            raise FuzzHarnessError("unsupported promoted source expected result")
        if type(encoded) is not str:
            raise FuzzHarnessError("promoted source frame base64 must be a string")
        if (
            type(frame_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", frame_sha256) is None
        ):
            raise FuzzHarnessError("invalid promoted source frame SHA256")
        if type(size) is not int or not 1 <= size <= MAX_FRAME_BYTES:
            raise FuzzHarnessError("invalid promoted source frame size")
        if previous_digest is not None and frame_sha256 <= previous_digest:
            raise FuzzHarnessError(
                "promoted source frames are not strictly SHA256-sorted"
            )
        previous_digest = frame_sha256
        if frame_sha256 in frame_digests or artifact_member in artifact_members:
            raise FuzzHarnessError("duplicate promoted source frame")

        try:
            frame = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise FuzzHarnessError("invalid promoted source frame base64") from error
        if base64.b64encode(frame).decode("ascii") != encoded:
            raise FuzzHarnessError("non-canonical promoted source frame base64")
        if len(frame) != size:
            raise FuzzHarnessError("promoted source frame size mismatch")
        if hashlib.sha256(frame).hexdigest() != frame_sha256:
            raise FuzzHarnessError("promoted source frame SHA256 mismatch")
        if hashlib.sha1(frame).hexdigest() != artifact_member.rsplit("/", 1)[1]:
            raise FuzzHarnessError("promoted source artifact member SHA1 mismatch")
        decoded = decode_frame(frame)
        if (
            encode_frame(
                decoded.signature,
                decoded.public_key,
                decoded.context,
                decoded.message,
                decoded.null_flags,
            )
            != frame
        ):
            raise FuzzHarnessError("promoted source frame is not canonical")

        metadata_digest.update(
            (
                f"{frame_sha256}\0{size}\0{expected_name}\0"
                f"{artifact_member}\n"
            ).encode()
        )
        frames_digest.update(len(frame).to_bytes(4, "little"))
        frames_digest.update(frame)
        expected_counts[expected_name] += 1
        total_bytes += len(frame)
        frame_digests.add(frame_sha256)
        artifact_members.add(artifact_member)
        cases.append(
            CorpusCase(
                name=f"sha256_{frame_sha256}",
                source="promoted",
                frame=frame,
                expected=expected_results[expected_name],
            )
        )

    selected_hashes = validate_digest_inventory(
        sorted(frame_digests),
        "selected",
        PROMOTED_SELECTION["selected_cases"],
        PROMOTED_SELECTION["selected_sha256_inventory_sha256"],
    )
    if selected_hashes != candidate_hashes - baseline_inventory - retained_hashes:
        raise FuzzHarnessError("promoted source set derivation differs")
    if expected_counts != PROMOTED_SELECTION["expected_counts"]:
        raise FuzzHarnessError("promoted source expected-result counts differ")
    if total_bytes != PROMOTED_SELECTION["selected_bytes"]:
        raise FuzzHarnessError("promoted source total byte count differs")
    if metadata_digest.hexdigest() != PROMOTED_SELECTION["metadata_sha256"]:
        raise FuzzHarnessError("promoted source metadata aggregate differs")
    if frames_digest.hexdigest() != PROMOTED_SELECTION["frames_sha256"]:
        raise FuzzHarnessError("promoted source frame aggregate differs")
    return cases


def encode_frame(
    signature: bytes,
    public_key: bytes,
    context: bytes,
    message: bytes,
    null_flags: int = 0,
) -> bytes:
    sizes = (len(signature), len(public_key), len(context), len(message))
    maxima = (
        MAX_SIGNATURE_BYTES,
        MAX_PUBLIC_KEY_BYTES,
        MAX_CONTEXT_BYTES,
        MAX_MESSAGE_BYTES,
    )
    if null_flags & ~NULL_MASK:
        raise FuzzHarnessError("invalid frame null flags")
    if any(size > maximum for size, maximum in zip(sizes, maxima)):
        raise FuzzHarnessError(f"frame field exceeds fuzz bound: {sizes}")
    return (
        FRAME_HEADER.pack(FRAME_VERSION, null_flags, *sizes)
        + signature
        + public_key
        + context
        + message
    )


def decode_frame(frame: bytes) -> DecodedFrame:
    if len(frame) < FRAME_HEADER.size:
        raise FuzzHarnessError("truncated corpus frame")
    version, null_flags, signature_size, public_key_size, context_size, message_size = (
        FRAME_HEADER.unpack_from(frame)
    )
    if version != FRAME_VERSION or null_flags & ~NULL_MASK:
        raise FuzzHarnessError("invalid corpus frame header")
    expected_size = (
        FRAME_HEADER.size
        + signature_size
        + public_key_size
        + context_size
        + message_size
    )
    if expected_size != len(frame):
        raise FuzzHarnessError("corpus frame length mismatch")
    cursor = FRAME_HEADER.size
    signature = frame[cursor : cursor + signature_size]
    cursor += signature_size
    public_key = frame[cursor : cursor + public_key_size]
    cursor += public_key_size
    context = frame[cursor : cursor + context_size]
    cursor += context_size
    message = frame[cursor : cursor + message_size]
    return DecodedFrame(null_flags, signature, public_key, context, message)


def configure_test_api(loaded) -> None:
    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    loaded.pqbtc_mldsa44_test_keypair_from_seed.argtypes = [
        byte_pointer,
        byte_pointer,
        byte_pointer,
    ]
    loaded.pqbtc_mldsa44_test_keypair_from_seed.restype = ctypes.c_int
    loaded.pqbtc_mldsa44_test_sign_fixed_randomizer.argtypes = [
        byte_pointer,
        byte_pointer,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
        ctypes.c_size_t,
        byte_pointer,
    ]
    loaded.pqbtc_mldsa44_test_sign_fixed_randomizer.restype = ctypes.c_int


def optional_array(data: bytes):
    return wrapper.as_array(data) if data else None


def sign_fixed(loaded, secret_key, message: bytes, context: bytes) -> bytes:
    signature = (ctypes.c_uint8 * wrapper.SIGNATURE_BYTES)()
    randomizer = wrapper.as_array(bytes(32))
    message_array = optional_array(message)
    context_array = optional_array(context)
    result = loaded.pqbtc_mldsa44_test_sign_fixed_randomizer(
        signature,
        secret_key,
        message_array,
        len(message),
        context_array,
        len(context),
        randomizer,
    )
    if result != OK:
        raise FuzzHarnessError(f"test-only fixed-randomizer signing failed: {result}")
    return bytes(signature)


def project_corpus(test_library: Path) -> list[CorpusCase]:
    vectors = json.loads(wrapper.VECTORS.read_text(encoding="utf8"))["vectors"]
    vector = vectors["pqbtc_sighash_v1"]
    loaded = ctypes.CDLL(str(test_library))
    configure_test_api(loaded)

    public_key = (ctypes.c_uint8 * wrapper.PUBLIC_KEY_BYTES)()
    secret_key = (ctypes.c_uint8 * wrapper.SECRET_KEY_BYTES)()
    seed = wrapper.as_array(bytes.fromhex(vector["seed_hex"]))
    if loaded.pqbtc_mldsa44_test_keypair_from_seed(public_key, secret_key, seed) != OK:
        raise FuzzHarnessError("test-only seeded key generation failed")
    public_key_bytes = bytes(public_key)
    secret_key_bytes = bytes(secret_key)
    if hashlib.sha256(public_key_bytes).hexdigest() != vector["expected_public_key_sha256"]:
        raise FuzzHarnessError("project corpus public key differs from frozen vector")
    if hashlib.sha256(secret_key_bytes).hexdigest() != vector["expected_private_key_sha256"]:
        raise FuzzHarnessError("project corpus secret key differs from frozen vector")

    message = bytes.fromhex(vector["message_hex"])
    context = bytes.fromhex(vector["context_hex"])
    signature = sign_fixed(loaded, secret_key, message, context)
    if hashlib.sha256(signature).hexdigest() != vector["expected_signature_sha256"]:
        raise FuzzHarnessError("project corpus signature differs from frozen vector")

    cases = []

    def add(
        name: str,
        expected: int,
        candidate_signature: bytes = signature,
        candidate_public_key: bytes = public_key_bytes,
        candidate_context: bytes = context,
        candidate_message: bytes = message,
        null_flags: int = 0,
    ) -> None:
        cases.append(
            CorpusCase(
                name=name,
                source="project",
                frame=encode_frame(
                    candidate_signature,
                    candidate_public_key,
                    candidate_context,
                    candidate_message,
                    null_flags,
                ),
                expected=expected,
            )
        )

    add("valid_frozen_vector", OK)
    empty_signature = sign_fixed(loaded, secret_key, b"", b"")
    add(
        "valid_empty_message_context",
        OK,
        candidate_signature=empty_signature,
        candidate_context=b"",
        candidate_message=b"",
        null_flags=NULL_CONTEXT | NULL_MESSAGE,
    )
    max_context = b"A" * 255
    add(
        "valid_max_context",
        OK,
        candidate_signature=sign_fixed(loaded, secret_key, message, max_context),
        candidate_context=max_context,
    )
    max_message = bytes(index % 251 for index in range(MAX_MESSAGE_BYTES))
    add(
        "valid_max_fuzz_message",
        OK,
        candidate_signature=sign_fixed(loaded, secret_key, max_message, b""),
        candidate_context=b"",
        candidate_message=max_message,
    )

    mutated = bytearray(signature)
    mutated[0] ^= 1
    add("reject_ctilde_bit_flip", ERR_VERIFY, bytes(mutated))

    for label, code in (("zero", 0), ("maximum", 0x3FFFF)):
        mutated = bytearray(signature)
        mutated[CTILDE_BYTES] = code & 0xFF
        mutated[CTILDE_BYTES + 1] = (code >> 8) & 0xFF
        mutated[CTILDE_BYTES + 2] = (
            mutated[CTILDE_BYTES + 2] & 0xFC
        ) | ((code >> 16) & 0x03)
        add(f"reject_z_first_code_{label}", ERR_VERIFY, bytes(mutated))

    mutated = bytearray(signature)
    mutated[HINT_OFFSET + HINT_INDICES + 3] = 81
    add("reject_hint_counter_overflow", ERR_VERIFY, bytes(mutated))

    for label, indices in (("reverse", (2, 1)), ("repeated", (1, 1))):
        mutated = bytearray(signature)
        mutated[HINT_OFFSET : HINT_OFFSET + HINT_INDICES + HINT_COUNTERS] = bytes(
            HINT_INDICES + HINT_COUNTERS
        )
        mutated[HINT_OFFSET] = indices[0]
        mutated[HINT_OFFSET + 1] = indices[1]
        mutated[HINT_OFFSET + HINT_INDICES : HINT_OFFSET + HINT_INDICES + 4] = (
            bytes((2, 2, 2, 2))
        )
        add(f"reject_hint_indices_{label}", ERR_VERIFY, bytes(mutated))

    mutated = bytearray(signature)
    mutated[HINT_OFFSET : HINT_OFFSET + HINT_INDICES + HINT_COUNTERS] = bytes(
        HINT_INDICES + HINT_COUNTERS
    )
    mutated[HINT_OFFSET] = 1
    add("reject_hint_nonzero_padding", ERR_VERIFY, bytes(mutated))

    mutated = bytearray(signature)
    mutated[HINT_OFFSET : HINT_OFFSET + HINT_INDICES + HINT_COUNTERS] = bytes(
        HINT_INDICES + HINT_COUNTERS
    )
    mutated[HINT_OFFSET] = 0
    mutated[HINT_OFFSET + 1] = 1
    mutated[HINT_OFFSET + HINT_INDICES : HINT_OFFSET + HINT_INDICES + 4] = bytes(
        (2, 1, 1, 1)
    )
    add("reject_hint_counter_backwards", ERR_VERIFY, bytes(mutated))

    mutated_key = bytearray(public_key_bytes)
    mutated_key[0] ^= 1
    add("reject_public_key_rho_flip", ERR_VERIFY, candidate_public_key=bytes(mutated_key))
    mutated_key = bytearray(public_key_bytes)
    mutated_key[-1] ^= 1
    add("reject_public_key_t1_flip", ERR_VERIFY, candidate_public_key=bytes(mutated_key))

    mutated_message = bytearray(message)
    mutated_message[0] ^= 1
    add("reject_message_flip", ERR_VERIFY, candidate_message=bytes(mutated_message))
    mutated_context = bytearray(context)
    mutated_context[-1] ^= 1
    add("reject_context_flip", ERR_VERIFY, candidate_context=bytes(mutated_context))

    add("reject_signature_empty", ERR_INVALID_ARGUMENT, candidate_signature=b"")
    add("reject_signature_truncated", ERR_INVALID_ARGUMENT, candidate_signature=signature[:-1])
    add("reject_signature_extended", ERR_INVALID_ARGUMENT, candidate_signature=signature + b"\x00")
    add("reject_public_key_empty", ERR_INVALID_ARGUMENT, candidate_public_key=b"")
    add("reject_public_key_truncated", ERR_INVALID_ARGUMENT, candidate_public_key=public_key_bytes[:-1])
    add("reject_public_key_extended", ERR_INVALID_ARGUMENT, candidate_public_key=public_key_bytes + b"\x00")
    add("reject_context_256", ERR_INVALID_ARGUMENT, candidate_context=b"A" * 256)
    add("reject_null_signature", ERR_INVALID_ARGUMENT, null_flags=NULL_SIGNATURE)
    add("reject_null_public_key", ERR_INVALID_ARGUMENT, null_flags=NULL_PUBLIC_KEY)
    add("reject_null_context", ERR_INVALID_ARGUMENT, null_flags=NULL_CONTEXT)
    add("reject_null_message", ERR_INVALID_ARGUMENT, null_flags=NULL_MESSAGE)
    return cases


def wycheproof_corpus(vectors: dict) -> list[CorpusCase]:
    cases = []
    for group in vectors["testGroups"]:
        public_key = bytes.fromhex(group["publicKey"])
        for test in group["tests"]:
            signature = bytes.fromhex(test["sig"])
            context = bytes.fromhex(test.get("ctx", ""))
            message = bytes.fromhex(test["msg"])
            if test["result"] == "valid":
                expected = OK
            elif (
                len(signature) != wrapper.SIGNATURE_BYTES
                or len(public_key) != wrapper.PUBLIC_KEY_BYTES
                or len(context) > 255
            ):
                expected = ERR_INVALID_ARGUMENT
            else:
                expected = ERR_VERIFY
            cases.append(
                CorpusCase(
                    name=f"tc_{test['tcId']:04d}",
                    source="wycheproof",
                    frame=encode_frame(signature, public_key, context, message),
                    expected=expected,
                )
            )
    return cases


def corpus_summary(cases: list[CorpusCase]) -> dict:
    digest = hashlib.sha256()
    expected_counts = {name: 0 for name in RESULT_NAMES.values()}
    source_counts = {}
    frame_hashes = set()
    for case in sorted(cases, key=lambda item: (item.source, item.name)):
        frame_sha256 = hashlib.sha256(case.frame).hexdigest()
        digest.update(
            f"{case.source}\0{case.name}\0{RESULT_NAMES[case.expected]}\0{frame_sha256}\n".encode()
        )
        expected_counts[RESULT_NAMES[case.expected]] += 1
        source_counts[case.source] = source_counts.get(case.source, 0) + 1
        frame_hashes.add(frame_sha256)
    return {
        "total_cases": len(cases),
        "unique_frames": len(frame_hashes),
        "source_counts": source_counts,
        "expected_counts": expected_counts,
        "aggregate_sha256": digest.hexdigest(),
    }


def validate_corpus_manifest(cases: list[CorpusCase]) -> dict:
    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf8"))
    if manifest.get("schema_version") != 1 or manifest.get("frame_version") != FRAME_VERSION:
        raise FuzzHarnessError("unsupported verifier fuzz corpus manifest schema")
    expected_limits = {
        "signature_bytes": MAX_SIGNATURE_BYTES,
        "public_key_bytes": MAX_PUBLIC_KEY_BYTES,
        "context_bytes": MAX_CONTEXT_BYTES,
        "message_bytes": MAX_MESSAGE_BYTES,
        "frame_bytes": MAX_FRAME_BYTES,
    }
    if manifest.get("fuzz_limits") != expected_limits:
        raise FuzzHarnessError("verifier fuzz limits differ from the frozen manifest")
    expected_sources = {
        "repo_vectors_sha256": sha256_file(wrapper.VECTORS),
        "wycheproof_vectors_sha256": sha256_file(WYCHEPROOF_VECTORS),
        "promoted_source_sha256": sha256_file(PROMOTED_SOURCE),
    }
    if manifest.get("sources") != expected_sources:
        raise FuzzHarnessError("verifier fuzz source hashes differ from the frozen manifest")
    identities = [(case.source, case.name) for case in cases]
    if len(set(identities)) != len(identities):
        raise FuzzHarnessError("verifier fuzz corpus contains duplicate case identities")
    filenames = [corpus_filename(case) for case in cases]
    if len(set(filenames)) != len(filenames):
        raise FuzzHarnessError("verifier fuzz corpus contains colliding filenames")
    promoted_hashes = {
        hashlib.sha256(case.frame).hexdigest()
        for case in cases
        if case.source == "promoted"
    }
    baseline_hashes = {
        hashlib.sha256(case.frame).hexdigest()
        for case in cases
        if case.source != "promoted"
    }
    capsule_cases = validate_promoted_source()
    capsule_hashes = {
        hashlib.sha256(case.frame).hexdigest() for case in capsule_cases
    }
    derivation = load_promoted_source_manifest()["derivation"]
    if promoted_hashes != capsule_hashes:
        raise FuzzHarnessError("promoted corpus differs from the source capsule")
    if baseline_hashes != set(derivation["baseline_unique_sha256"]):
        raise FuzzHarnessError("generated baseline differs from derivation inventory")
    if promoted_hashes & baseline_hashes:
        raise FuzzHarnessError("promoted source overlaps the generated baseline corpus")
    summary = corpus_summary(cases)
    if manifest.get("generated_corpus") != summary:
        raise FuzzHarnessError(
            "generated verifier corpus differs from verifier_fuzz_corpus.json:\n"
            + json.dumps(summary, indent=2, sort_keys=True)
        )
    return summary


def pointer_for(data: bytes, force_null: bool):
    if force_null:
        return None, None
    storage = (ctypes.c_uint8 * max(1, len(data)))()
    if data:
        storage[: len(data)] = data
    return storage, storage


def replay_case(loaded, case: CorpusCase) -> int:
    decoded = decode_frame(case.frame)
    signature_pointer, signature_storage = pointer_for(
        decoded.signature, bool(decoded.null_flags & NULL_SIGNATURE)
    )
    public_key_pointer, public_key_storage = pointer_for(
        decoded.public_key, bool(decoded.null_flags & NULL_PUBLIC_KEY)
    )
    context_pointer, context_storage = pointer_for(
        decoded.context, bool(decoded.null_flags & NULL_CONTEXT)
    )
    message_pointer, message_storage = pointer_for(
        decoded.message, bool(decoded.null_flags & NULL_MESSAGE)
    )
    _keepalive = (
        signature_storage,
        public_key_storage,
        context_storage,
        message_storage,
    )
    return loaded.pqbtc_mldsa44_verify_strict(
        signature_pointer,
        len(decoded.signature),
        public_key_pointer,
        len(decoded.public_key),
        message_pointer,
        len(decoded.message),
        context_pointer,
        len(decoded.context),
    )


def replay_corpus(production_library: Path, cases: list[CorpusCase]) -> None:
    loaded = ctypes.CDLL(str(production_library))
    wrapper.configure_public_api(loaded)
    for case in cases:
        actual = replay_case(loaded, case)
        if actual != case.expected:
            raise FuzzHarnessError(
                f"{case.source}/{case.name}: expected {RESULT_NAMES[case.expected]}, "
                f"got {RESULT_NAMES.get(actual, str(actual))}"
            )


def corpus_filename(case: CorpusCase) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", case.name)
    return f"{case.source}_{safe_name}.bin"


def materialize_corpus(directory: Path, cases: list[CorpusCase]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for case in cases:
        (directory / corpus_filename(case)).write_bytes(case.frame)


def import_seed_corpus(source: Path, destination: Path) -> int:
    if not source.is_dir():
        raise FuzzHarnessError(f"seed corpus is not a directory: {source}")
    imported = 0
    total_bytes = 0
    candidates = [
        path for path in sorted(source.iterdir()) if not path.is_symlink() and path.is_file()
    ]
    if len(candidates) > MAX_RETAINED_CORPUS_FILES:
        raise FuzzHarnessError("retained corpus exceeds the file-count bound")
    for path in candidates:
        size = path.stat().st_size
        if size > MAX_FRAME_BYTES:
            raise FuzzHarnessError(f"retained corpus input exceeds fuzz bound: {path}")
        total_bytes += size
        if total_bytes > MAX_RETAINED_CORPUS_BYTES:
            raise FuzzHarnessError("retained corpus exceeds the aggregate byte bound")
        data = path.read_bytes()
        if len(data) != size:
            raise FuzzHarnessError(f"retained corpus input changed during import: {path}")
        digest = hashlib.sha256(data).hexdigest()
        target = destination / f"retained_{digest}.bin"
        if not target.exists():
            target.write_bytes(data)
            imported += 1
    return imported


def directory_summary(directory: Path) -> dict:
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    if directory.is_dir():
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            relative = path.relative_to(directory).as_posix()
            data = path.read_bytes()
            file_digest = hashlib.sha256(data).hexdigest()
            digest.update(f"{relative}\0{len(data)}\0{file_digest}\n".encode())
            file_count += 1
            total_bytes += len(data)
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "aggregate_sha256": digest.hexdigest(),
    }


def compiler_identity(compiler: str) -> str:
    completed = subprocess.run(
        [compiler, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout.splitlines()[0] if completed.stdout else compiler


def repository_commit() -> str:
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha:
        return github_sha
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def repository_dirty() -> bool | None:
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return bool(completed.stdout) if completed.returncode == 0 else None


def compile_fuzzer(
    compiler: str,
    build_dir: Path,
    sanitizer: str,
    coverage: bool,
    *,
    differential_sources: tuple[Path, ...] = (),
    differential_link_args: tuple[str, ...] = (),
) -> Path:
    differential = bool(differential_sources or differential_link_args)
    output_name = (
        "pqbtc_mldsa44_differential_verify_fuzz"
        if differential
        else "pqbtc_mldsa44_verify_fuzz"
    )
    output = build_dir / output_name
    command = wrapper.common_flags(compiler)
    command.extend(
        [
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            f"-fsanitize={SANITIZERS[sanitizer]}",
        ]
    )
    if sanitizer == "memory":
        command.extend(["-fsanitize-memory-track-origins=2", "-fPIE", "-pie"])
    if coverage:
        command.extend(["-fprofile-instr-generate", "-fcoverage-mapping"])
    if differential:
        command.append("-DPQBTC_MLDSA44_DIFFERENTIAL=1")
    command.extend(
        [
            str(wrapper.WRAPPER_SOURCE),
            str(FUZZ_SOURCE),
            *map(str, differential_sources),
            "-o",
            str(output),
            *differential_link_args,
        ]
    )
    wrapper.run(command)
    return output


def captured_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf8", errors="replace")
    return value


def run_fuzzer(
    executable: Path,
    corpus_dir: Path,
    artifact_dir: Path,
    log_path: Path,
    runs: int | None,
    seconds: int | None,
    sanitizer: str,
    profile_pattern: Path | None,
    seed: int,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if sanitizer == "address-undefined":
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
        )
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if sanitizer == "memory":
        env["MSAN_OPTIONS"] = "halt_on_error=1:print_stats=1"
    if profile_pattern is not None:
        env["LLVM_PROFILE_FILE"] = str(profile_pattern)
    limit = f"-max_total_time={seconds}" if seconds is not None else f"-runs={runs}"
    command = [
        str(executable),
        str(corpus_dir),
        f"-artifact_prefix={artifact_dir}{os.sep}",
        f"-max_len={max_frame_bytes}",
        limit,
        f"-seed={seed}",
        "-timeout=5",
        "-rss_limit_mb=1024",
        "-malloc_limit_mb=256",
        "-use_value_profile=1",
        "-print_final_stats=1",
    ]
    wall_timeout = (
        seconds + CAMPAIGN_TIMEOUT_ALLOWANCE_SECONDS
        if seconds is not None
        else None
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=wall_timeout,
        )
    except subprocess.TimeoutExpired as error:
        completed = subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=captured_output(error.stdout),
            stderr=(
                captured_output(error.stderr)
                + f"\ncampaign exceeded the {wall_timeout}-second wall-clock limit\n"
            ),
        )
    log_path.write_text(
        f"command: {' '.join(command)}\n\nstdout:\n{completed.stdout}\n\nstderr:\n{completed.stderr}",
        encoding="utf8",
    )
    return completed


def minimize_corpus(
    executable: Path,
    corpus_dir: Path,
    destination: Path,
    log_path: Path,
    sanitizer: str,
    profile_pattern: Path | None,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> None:
    destination.mkdir()
    env = os.environ.copy()
    if sanitizer == "address-undefined":
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
        )
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if sanitizer == "memory":
        env["MSAN_OPTIONS"] = "halt_on_error=1:print_stats=1"
    if profile_pattern is not None:
        env["LLVM_PROFILE_FILE"] = str(profile_pattern)
    command = [
        str(executable),
        "-merge=1",
        "-use_value_profile=1",
        str(destination),
        str(corpus_dir),
        f"-max_len={max_frame_bytes}",
        "-timeout=5",
        "-rss_limit_mb=1024",
        "-malloc_limit_mb=256",
        "-max_total_time=120",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=CORPUS_MINIMIZATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        log_path.write_text(
            f"command: {' '.join(command)}\n\nstdout:\n"
            f"{captured_output(error.stdout)}\n\nstderr:\n"
            f"{captured_output(error.stderr)}\ncorpus minimization exceeded the "
            f"{CORPUS_MINIMIZATION_TIMEOUT_SECONDS}-second wall-clock limit\n",
            encoding="utf8",
        )
        raise FuzzHarnessError(
            "corpus minimization exceeded its wall-clock limit"
        ) from error
    log_path.write_text(
        f"command: {' '.join(command)}\n\nstdout:\n{completed.stdout}\n\n"
        f"stderr:\n{completed.stderr}",
        encoding="utf8",
    )
    if completed.returncode != 0:
        raise FuzzHarnessError(f"corpus minimization failed ({completed.returncode})")
    if directory_summary(destination)["file_count"] == 0:
        raise FuzzHarnessError("corpus minimization produced an empty corpus")


def minimize_crash_artifacts(
    executable: Path,
    artifact_dir: Path,
    output_dir: Path,
    sanitizer: str,
    seed: int,
    *,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> list[dict]:
    artifacts = sorted(path for path in artifact_dir.iterdir() if path.is_file())
    if not artifacts:
        return []
    destination = output_dir / "minimized-crashes"
    destination.mkdir()
    env = os.environ.copy()
    if sanitizer == "address-undefined":
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
        )
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if sanitizer == "memory":
        env["MSAN_OPTIONS"] = "halt_on_error=1:print_stats=1"
    records = []
    log_parts = []
    for artifact in artifacts[:4]:
        minimized = destination / artifact.name
        command = [
            str(executable),
            "-minimize_crash=1",
            f"-exact_artifact_path={minimized}",
            "-max_total_time=60",
            f"-max_len={max_frame_bytes}",
            f"-seed={seed}",
            "-timeout=5",
            "-rss_limit_mb=1024",
            "-malloc_limit_mb=256",
            str(artifact),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                timeout=CRASH_MINIMIZATION_TIMEOUT_SECONDS,
            )
            return_code = completed.returncode
            timed_out = False
            error_message = None
            log_parts.append(
                f"command: {' '.join(command)}\nstdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}\n"
            )
        except subprocess.TimeoutExpired as error:
            return_code = 124
            timed_out = True
            error_message = (
                "crash minimization exceeded the "
                f"{CRASH_MINIMIZATION_TIMEOUT_SECONDS}-second wall-clock limit"
            )
            log_parts.append(
                f"command: {' '.join(command)}\nstdout:\n"
                f"{captured_output(error.stdout)}\nstderr:\n"
                f"{captured_output(error.stderr)}\nerror: {error_message}\n"
            )
        except OSError as error:
            return_code = None
            timed_out = False
            error_message = str(error)
            log_parts.append(f"command: {' '.join(command)}\nerror: {error}\n")
        records.append(
            {
                "original": artifact.name,
                "original_sha256": sha256_file(artifact),
                "return_code": return_code,
                "timed_out": timed_out,
                "error": error_message,
                "minimized": minimized.name if minimized.is_file() else None,
                "minimized_sha256": sha256_file(minimized) if minimized.is_file() else None,
            }
        )
    (output_dir / "crash-minimization.log").write_text(
        "\n".join(log_parts),
        encoding="utf8",
    )
    return records


def compiler_tool(compiler: str, tool: str) -> str:
    completed = subprocess.run(
        [compiler, f"--print-prog-name={tool}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    printed_candidate = completed.stdout.strip()
    compiler_version = compiler_identity(compiler)
    version_match = re.search(r"\bclang version (\d+)", compiler_version)
    candidates = []
    if printed_candidate and printed_candidate != tool:
        candidates.append(printed_candidate)
    if version_match:
        candidates.append(f"{tool}-{version_match.group(1)}")
    if printed_candidate:
        candidates.append(printed_candidate)
    candidates.append(tool)
    for candidate in dict.fromkeys(candidates):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return resolved
    raise FuzzHarnessError(
        f"matching {tool} is unavailable for {compiler} ({compiler_version})"
    )


def coverage_tool_identities(compiler: str) -> dict:
    identities = {}
    for tool in ("llvm-profdata", "llvm-cov"):
        try:
            path = compiler_tool(compiler, tool)
            identities[tool] = {
                "path": path,
                "version": compiler_identity(path),
            }
        except (FuzzHarnessError, OSError) as error:
            identities[tool] = {"error": str(error)}
    return identities


def write_coverage_report(compiler: str, executable: Path, output_dir: Path) -> None:
    profiles = sorted(output_dir.glob("coverage-*.profraw"))
    if not profiles:
        raise FuzzHarnessError("LLVM coverage profiles are unavailable")
    llvm_profdata = compiler_tool(compiler, "llvm-profdata")
    llvm_cov = compiler_tool(compiler, "llvm-cov")
    merged = output_dir / "coverage.profdata"
    wrapper.run([llvm_profdata, "merge", "-sparse", *map(str, profiles), "-o", str(merged)])
    report = wrapper.run(
        [
            llvm_cov,
            "report",
            str(executable),
            f"-instr-profile={merged}",
        ]
    )
    (output_dir / "coverage.txt").write_text(report, encoding="utf8")
    exported = wrapper.run(
        [
            llvm_cov,
            "export",
            "-summary-only",
            str(executable),
            f"-instr-profile={merged}",
        ]
    )
    parsed = json.loads(exported)
    (output_dir / "coverage.json").write_text(
        json.dumps(parsed, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )


def write_campaign_report(
    output_dir: Path,
    *,
    compiler: str,
    sanitizer: str,
    coverage: bool,
    runs: int | None,
    seconds: int | None,
    imported_seeds: int,
    source_summary: dict,
    started_at: str,
    duration_seconds: float,
    seed: int,
    completed: subprocess.CompletedProcess[str],
    processing_error: str | None,
    crash_minimization: list[dict],
) -> None:
    progress_lines = [
        line.strip()
        for line in completed.stderr.splitlines()
        if re.match(r"^#\d+", line.strip())
    ]
    final_stats = [
        line.strip()
        for line in completed.stderr.splitlines()
        if line.strip().startswith("stat::")
    ]
    report = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "status": (
            "pass" if completed.returncode == 0 and processing_error is None else "fail"
        ),
        "return_code": completed.returncode,
        "processing_error": processing_error,
        "repository_commit": repository_commit(),
        "repository_dirty": repository_dirty(),
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration_seconds, 3),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "compiler": compiler_identity(compiler),
        "coverage_tools": coverage_tool_identities(compiler) if coverage else None,
        "sanitizer": sanitizer,
        "coverage_enabled": coverage,
        "campaign_limit": {"runs": runs, "seconds": seconds},
        "resource_limits": {
            "max_frame_bytes": MAX_FRAME_BYTES,
            "input_timeout_seconds": 5,
            "rss_limit_mb": 1024,
            "malloc_limit_mb": 256,
            "seed": seed,
        },
        "imported_retained_seeds": imported_seeds,
        "source_corpus": source_summary,
        "source_files": {
            "wrapper_sha256": sha256_file(wrapper.WRAPPER_SOURCE),
            "fuzz_target_sha256": sha256_file(FUZZ_SOURCE),
            "corpus_manifest_sha256": sha256_file(CORPUS_MANIFEST),
            "wycheproof_vectors_sha256": sha256_file(WYCHEPROOF_VECTORS),
            "promoted_source_sha256": sha256_file(PROMOTED_SOURCE),
            "source_manifest_sha256": sha256_file(wrapper.SOURCE_MANIFEST),
            "source_capsule_sha256": json.loads(
                wrapper.SOURCE_MANIFEST.read_text(encoding="utf8")
            )["capsule_hash"]["value"],
        },
        "working_corpus": directory_summary(output_dir / "corpus"),
        "minimized_corpus": directory_summary(output_dir / "minimized-corpus"),
        "crash_artifacts": directory_summary(output_dir / "crashes"),
        "minimized_crash_artifacts": directory_summary(
            output_dir / "minimized-crashes"
        ),
        "crash_minimization": crash_minimization,
        "last_progress_line": progress_lines[-1] if progress_lines else None,
        "final_stats": final_stats,
    }
    (output_dir / "campaign.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )


def write_evidence_hashes(output_dir: Path) -> None:
    lines = []
    manifest_path = output_dir / "SHA256SUMS"
    for path in sorted(item for item in output_dir.rglob("*") if item.is_file()):
        if path == manifest_path:
            continue
        relative = path.relative_to(output_dir).as_posix()
        lines.append(f"{sha256_file(path)}  {relative}\n")
    manifest_path.write_text("".join(lines), encoding="utf8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay and fuzz the isolated ML-DSA-44 strict verifier"
    )
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--sanitizers", action="store_true")
    parser.add_argument(
        "--sanitizer",
        choices=sorted(SANITIZERS),
        default="address-undefined",
    )
    parser.add_argument("--runs", type=int)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--seed", type=int, default=188)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed-corpus", type=Path)
    parser.add_argument("--coverage", action="store_true")
    args = parser.parse_args()
    if args.runs is not None and args.seconds is not None:
        raise FuzzHarnessError("--runs and --seconds are mutually exclusive")
    if args.runs is not None and args.runs < 1:
        raise FuzzHarnessError("--runs must be positive")
    if args.seconds is not None and args.seconds < 1:
        raise FuzzHarnessError("--seconds must be positive")
    if not 1 <= args.seed <= 0xFFFFFFFF:
        raise FuzzHarnessError("--seed must be a nonzero unsigned 32-bit integer")
    if args.coverage and not args.sanitizers:
        raise FuzzHarnessError("--coverage requires --sanitizers")
    if args.coverage and args.sanitizer == "memory":
        raise FuzzHarnessError("coverage is collected only in the address-undefined campaign")
    if not args.sanitizers and (
        args.runs is not None
        or args.seconds is not None
        or args.output_dir is not None
        or args.seed_corpus is not None
        or args.coverage
        or args.sanitizer != "address-undefined"
        or args.seed != 188
    ):
        raise FuzzHarnessError("fuzz campaign options require --sanitizers")

    wrapper.validate_source_capsule()
    wycheproof = validate_wycheproof_source()
    promoted = validate_promoted_source()
    if args.manifest_only:
        manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf8"))
        expected_sources = {
            "repo_vectors_sha256": sha256_file(wrapper.VECTORS),
            "wycheproof_vectors_sha256": sha256_file(WYCHEPROOF_VECTORS),
            "promoted_source_sha256": sha256_file(PROMOTED_SOURCE),
        }
        if manifest.get("sources") != expected_sources:
            raise FuzzHarnessError("corpus manifest does not pin every fuzz source")
        print(
            "ML-DSA-44 verifier fuzz sources OK: "
            "180 pinned Wycheproof cases + 38 promoted regressions"
        )
        return 0

    compiler = os.environ.get("CC", "cc")
    if shutil.which(compiler) is None:
        raise FuzzHarnessError(f"C compiler not found: {compiler}")
    if args.sanitizers and args.sanitizer == "memory":
        if not sys.platform.startswith("linux"):
            raise FuzzHarnessError("MemorySanitizer campaigns require Linux")
        if "clang" not in compiler_identity(compiler).lower():
            raise FuzzHarnessError("MemorySanitizer campaigns require Clang")
    with tempfile.TemporaryDirectory(prefix="pqbtc-mldsa44-verifier-fuzz-") as temporary:
        build_dir = Path(temporary)
        production_library = wrapper.compile_shared(compiler, build_dir, testing=False)
        test_library = wrapper.compile_shared(compiler, build_dir, testing=True)
        cases = (
            project_corpus(test_library)
            + wycheproof_corpus(wycheproof)
            + promoted
        )
        summary = validate_corpus_manifest(cases)
        replay_corpus(production_library, cases)
        if args.sanitizers:
            runs = args.runs if args.runs is not None else (None if args.seconds else 1000)
            if args.output_dir is None:
                output_dir = build_dir / "campaign"
            else:
                output_dir = args.output_dir.resolve()
                if output_dir.exists():
                    if not output_dir.is_dir():
                        raise FuzzHarnessError(
                            f"output directory path is not a directory: {output_dir}"
                        )
                    if any(output_dir.iterdir()):
                        raise FuzzHarnessError(
                            f"output directory is not empty: {output_dir}"
                        )
            output_dir.mkdir(parents=True, exist_ok=True)
            corpus_dir = output_dir / "corpus"
            artifact_dir = output_dir / "crashes"
            artifact_dir.mkdir()
            materialize_corpus(corpus_dir, cases)
            imported_seeds = 0
            if args.seed_corpus is not None:
                imported_seeds = import_seed_corpus(args.seed_corpus.resolve(), corpus_dir)
            started_at = datetime.now(timezone.utc).isoformat()
            monotonic_start = time.monotonic()
            completed = subprocess.CompletedProcess([], 1, "", "campaign did not start")
            processing_error = None
            crash_minimization = []
            try:
                fuzzer = compile_fuzzer(
                    compiler,
                    build_dir,
                    sanitizer=args.sanitizer,
                    coverage=args.coverage,
                )
                profile_pattern = (
                    output_dir / "coverage-%p.profraw" if args.coverage else None
                )
                completed = run_fuzzer(
                    fuzzer,
                    corpus_dir,
                    artifact_dir,
                    output_dir / "fuzzer.log",
                    runs=runs,
                    seconds=args.seconds,
                    sanitizer=args.sanitizer,
                    profile_pattern=profile_pattern,
                    seed=args.seed,
                )
                if completed.returncode == 0:
                    merge_profile = (
                        output_dir / "coverage-merge-%p.profraw"
                        if args.coverage
                        else None
                    )
                    minimize_corpus(
                        fuzzer,
                        corpus_dir,
                        output_dir / "minimized-corpus",
                        output_dir / "corpus-minimization.log",
                        sanitizer=args.sanitizer,
                        profile_pattern=merge_profile,
                    )
                    if args.coverage:
                        write_coverage_report(compiler, fuzzer, output_dir)
                else:
                    crash_minimization = minimize_crash_artifacts(
                        fuzzer,
                        artifact_dir,
                        output_dir,
                        sanitizer=args.sanitizer,
                        seed=args.seed,
                    )
            except (FuzzHarnessError, wrapper.HarnessError, OSError, ValueError) as error:
                processing_error = str(error)
            finally:
                write_campaign_report(
                    output_dir,
                    compiler=compiler,
                    sanitizer=args.sanitizer,
                    coverage=args.coverage,
                    runs=runs,
                    seconds=args.seconds,
                    imported_seeds=imported_seeds,
                    source_summary=summary,
                    started_at=started_at,
                    duration_seconds=time.monotonic() - monotonic_start,
                    seed=args.seed,
                    completed=completed,
                    processing_error=processing_error,
                    crash_minimization=crash_minimization,
                )
                write_evidence_hashes(output_dir)
            if processing_error is not None:
                evidence = (
                    f"evidence retained in {output_dir}"
                    if args.output_dir is not None
                    else "temporary evidence discarded; pass --output-dir to retain it"
                )
                raise FuzzHarnessError(
                    f"campaign processing failed; {evidence}: {processing_error}"
                )
            if completed.returncode != 0:
                evidence = (
                    f"evidence retained in {output_dir}"
                    if args.output_dir is not None
                    else "temporary evidence discarded; pass --output-dir to retain it"
                )
                raise FuzzHarnessError(
                    f"fuzzer failed ({completed.returncode}); {evidence}"
                )

    mode = f"{args.sanitizer} fuzz" if args.sanitizers else "deterministic replay"
    print(
        f"ML-DSA-44 verifier {mode} passed: {summary['total_cases']} cases, "
        f"{summary['expected_counts']['ok']} accepted"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FuzzHarnessError, wrapper.HarnessError) as error:
        print(f"verifier fuzz harness: {error}", file=sys.stderr)
        raise SystemExit(1)
