#!/usr/bin/env python3
"""Replay bounded malformed-input mutations against the research oracle CLIs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Protocol


HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "cli_adapter_fuzz_corpus.json"
SOURCE_PATHS = {
    "vectors_sha256": HERE / "vectors.json",
    "compare_driver_sha256": HERE / "compare_oracles.py",
    "cli_fuzz_driver_sha256": Path(__file__).resolve(),
    "c_helper_sha256": HERE / "oracle_cli.h",
    "openssl_adapter_sha256": HERE / "openssl_oracle.c",
    "mldsa_native_adapter_sha256": HERE / "mldsa_native_oracle.c",
    "libcrux_adapter_sha256": HERE / "libcrux_oracle.rs",
}

SEED = 188
MUTATION_CASES = 60
KEYGEN_SEED_BYTES = 32
PRIVATE_KEY_BYTES = 2560
PUBLIC_KEY_BYTES = 1312
RANDOMIZER_BYTES = 32
SIGNATURE_BYTES = 2420
MAX_VERIFY_SIGNATURE_BYTES = SIGNATURE_BYTES + 1
MAX_MESSAGE_BYTES = 8192
MAX_CONTEXT_BYTES = 255

WALL_TIMEOUT_SECONDS = 3
CPU_LIMIT_SECONDS = 2
ADDRESS_SPACE_LIMIT_BYTES = 1024 * 1024 * 1024
STACK_LIMIT_BYTES = 8 * 1024 * 1024
FILE_SIZE_LIMIT_BYTES = 64 * 1024
OPEN_FILE_LIMIT = 64
MAX_ACCEPTED_OUTPUT_BYTES = 64 * 1024

COMMON_FIXED_CASE_IDS = (
    "usage_no_arguments",
    "usage_unknown_command",
    "usage_missing_verify_argument",
    "usage_extra_argument",
    "verify_valid_lowercase",
    "verify_valid_uppercase",
    "verify_public_key_empty",
    "verify_public_key_short",
    "verify_public_key_long",
    "verify_public_key_odd",
    "verify_public_key_nonhex",
    "verify_public_key_whitespace",
    "verify_public_key_prefix",
    "verify_public_key_non_utf8",
    "verify_message_empty",
    "verify_message_maximum",
    "verify_message_oversized",
    "verify_message_odd",
    "verify_message_nonhex",
    "verify_message_whitespace",
    "verify_message_prefix",
    "verify_message_non_utf8",
    "verify_context_empty",
    "verify_context_maximum",
    "verify_context_oversized",
    "verify_context_odd",
    "verify_context_nonhex",
    "verify_context_whitespace",
    "verify_context_prefix",
    "verify_context_non_utf8",
    "verify_signature_empty",
    "verify_signature_short",
    "verify_signature_extended",
    "verify_signature_oversized",
    "verify_signature_odd",
    "verify_signature_nonhex",
    "verify_signature_whitespace",
    "verify_signature_prefix",
    "verify_signature_non_utf8",
)

KEYGEN_FIXED_CASE_IDS = (
    "keygen_seed_short",
    "keygen_seed_long",
    "keygen_seed_odd",
    "keygen_seed_nonhex",
    "keygen_seed_prefix",
    "keygen_seed_non_utf8",
)

PUBLIC_KEY_FIXED_CASE_IDS = (
    "public_key_private_key_short",
    "public_key_private_key_long",
    "public_key_private_key_odd",
    "public_key_private_key_nonhex",
    "public_key_private_key_prefix",
    "public_key_private_key_non_utf8",
)

SIGN_FIXED_CASE_IDS = (
    "sign_private_key_short",
    "sign_private_key_long",
    "sign_private_key_odd",
    "sign_private_key_nonhex",
    "sign_private_key_prefix",
    "sign_private_key_non_utf8",
    "sign_message_oversized",
    "sign_message_odd",
    "sign_message_nonhex",
    "sign_message_non_utf8",
    "sign_context_oversized",
    "sign_context_odd",
    "sign_context_nonhex",
    "sign_context_non_utf8",
    "sign_randomizer_short",
    "sign_randomizer_long",
    "sign_randomizer_odd",
    "sign_randomizer_nonhex",
    "sign_randomizer_non_utf8",
)

SIGN_PUBLIC_KEY_FIXED_CASE_IDS = (
    "sign_public_key_short",
    "sign_public_key_long",
    "sign_public_key_odd",
    "sign_public_key_nonhex",
    "sign_public_key_non_utf8",
)

MUTATION_FIELDS = ("public_key", "message", "context", "signature")
MUTATION_KINDS = (
    "nonhex",
    "odd",
    "whitespace",
    "prefix",
    "non_utf8",
    "oversized",
)

VERIFY_OUTPUT = re.compile(rb"verified=([01])\nverify_ns=([0-9]+)\n")
FATAL_MARKERS = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"runtime error:",
    b"panicked at",
    b"stack overflow",
)


class CliFuzzError(RuntimeError):
    pass


class OracleLike(Protocol):
    executable: Path
    derives_public_key: bool
    sign_requires_public_key: bool
    sanitized: bool


@dataclass(frozen=True)
class CliCase:
    name: str
    arguments: tuple[str | bytes, ...]
    expected: str


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixed_case_contract() -> dict[str, list[str]]:
    return {
        "common": list(COMMON_FIXED_CASE_IDS),
        "keygen": list(KEYGEN_FIXED_CASE_IDS),
        "public_key_derivation": list(PUBLIC_KEY_FIXED_CASE_IDS),
        "sign": list(SIGN_FIXED_CASE_IDS),
        "sign_public_key": list(SIGN_PUBLIC_KEY_FIXED_CASE_IDS),
    }


def parser_limits() -> dict[str, object]:
    return {
        "hex_case": "upper-or-lower-ascii",
        "keygen_seed_bytes": KEYGEN_SEED_BYTES,
        "private_key_bytes": PRIVATE_KEY_BYTES,
        "public_key_bytes": PUBLIC_KEY_BYTES,
        "randomizer_bytes": RANDOMIZER_BYTES,
        "signature_bytes": SIGNATURE_BYTES,
        "maximum_verify_signature_bytes": MAX_VERIFY_SIGNATURE_BYTES,
        "maximum_message_bytes": MAX_MESSAGE_BYTES,
        "selected_acvp_maximum_message_bytes": 8192,
        "maximum_context_bytes": MAX_CONTEXT_BYTES,
        "embedded_nul_argv": "not-representable-by-execve",
    }


def process_limits() -> dict[str, object]:
    return {
        "wall_timeout_seconds": WALL_TIMEOUT_SECONDS,
        "wall_timeout_scope": "all-platforms",
        "cpu_limit_seconds": CPU_LIMIT_SECONDS,
        "address_space_limit_bytes": ADDRESS_SPACE_LIMIT_BYTES,
        "address_space_scope": "unsanitized-linux-children-only",
        "stack_limit_bytes": STACK_LIMIT_BYTES,
        "file_size_limit_bytes": FILE_SIZE_LIMIT_BYTES,
        "open_file_limit": OPEN_FILE_LIMIT,
        "core_size_bytes": 0,
        "rlimit_scope": "linux-children-only",
        "maximum_accepted_output_bytes_per_stream": MAX_ACCEPTED_OUTPUT_BYTES,
        "output_limit_scope": "post-exit-acceptance-gate-not-streaming-cap",
        "scope": "test-process-containment-not-cryptographic-resource-proof",
    }


def mutation_contract() -> dict[str, object]:
    labels = []
    for index, field, kind, _, state in mutation_descriptors():
        labels.append(f"mutation_{index:03d}_{field}_{kind}_{state:08x}")
    digest = hashlib.sha256()
    for label in labels:
        digest.update(label.encode("ascii") + b"\n")
    return {
        "seed": SEED,
        "cases_per_adapter": MUTATION_CASES,
        "fields": list(MUTATION_FIELDS),
        "mutations": list(MUTATION_KINDS),
        "label_inventory_sha256": digest.hexdigest(),
    }


def mutation_descriptors() -> list[tuple[int, str, str, int, int]]:
    state = SEED
    descriptors = []
    index = 0
    for field in MUTATION_FIELDS:
        for kind in MUTATION_KINDS:
            repetitions = 4 if kind in {"nonhex", "whitespace", "non_utf8"} else 1
            for variant in range(repetitions):
                state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
                descriptors.append((index, field, kind, variant, state))
                index += 1
    if len(descriptors) != MUTATION_CASES:
        raise CliFuzzError("mutation descriptor count differs from the contract")
    return descriptors


def validate_manifest() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf8"))
    expected = {
        "schema_version": 1,
        "target": "ml-dsa-44-research-oracle-cli-adapters",
        "parser_limits": parser_limits(),
        "process_limits": process_limits(),
        "fixed_case_contract": fixed_case_contract(),
        "mutation_contract": mutation_contract(),
        "sources": {
            name: sha256_file(path) for name, path in SOURCE_PATHS.items()
        },
    }
    if manifest != expected:
        raise CliFuzzError(
            "CLI adapter fuzz manifest differs from the generated contract:\n"
            + json.dumps(expected, indent=2, sort_keys=True)
        )
    return manifest


def replace_first(value: str, replacement: str) -> str:
    if not value:
        return replacement
    return replacement + value[1:]


def replace_first_bytes(value: str, replacement: bytes) -> bytes:
    encoded = value.encode("ascii")
    return replacement + encoded[1:] if encoded else replacement


def verify_arguments(
    public_key: str | bytes,
    message: str | bytes,
    context: str | bytes,
    signature: str | bytes,
) -> tuple[str | bytes, ...]:
    return ("verify", public_key, message, context, signature)


def sign_arguments(
    oracle: OracleLike,
    private_key: str | bytes,
    message: str | bytes,
    context: str | bytes,
    public_key: str | bytes,
) -> tuple[str | bytes, ...]:
    arguments: list[str | bytes] = ["sign", private_key, message, context]
    if oracle.sign_requires_public_key:
        arguments.append(public_key)
    return tuple(arguments)


def randomized_sign_arguments(
    oracle: OracleLike,
    private_key: str | bytes,
    message: str | bytes,
    context: str | bytes,
    randomizer: str | bytes,
    public_key: str | bytes,
) -> tuple[str | bytes, ...]:
    arguments: list[str | bytes] = [
        "sign-with-randomizer",
        private_key,
        message,
        context,
        randomizer,
    ]
    if oracle.sign_requires_public_key:
        arguments.append(public_key)
    return tuple(arguments)


def fixed_cases(
    oracle: OracleLike,
    *,
    seed: str,
    private_key: str,
    public_key: str,
    message: str,
    context: str,
    signature: str,
) -> list[CliCase]:
    valid_verify = verify_arguments(public_key, message, context, signature)
    cases = [
        CliCase("usage_no_arguments", (), "usage"),
        CliCase("usage_unknown_command", ("unknown",), "usage"),
        CliCase(
            "usage_missing_verify_argument",
            valid_verify[:-1],
            "usage",
        ),
        CliCase(
            "usage_extra_argument",
            valid_verify + ("DO_NOT_ECHO_THIS_ARGUMENT_7f683f78",),
            "usage",
        ),
        CliCase("verify_valid_lowercase", valid_verify, "verify_accept"),
        CliCase(
            "verify_valid_uppercase",
            (
                "verify",
                public_key.upper(),
                message.upper(),
                context.upper(),
                signature.upper(),
            ),
            "verify_accept",
        ),
        CliCase(
            "verify_public_key_empty",
            verify_arguments("", message, context, signature),
            "malformed",
        ),
        CliCase(
            "verify_public_key_short",
            verify_arguments(public_key[:-2], message, context, signature),
            "malformed",
        ),
        CliCase(
            "verify_public_key_long",
            verify_arguments(public_key + "00", message, context, signature),
            "malformed",
        ),
        CliCase(
            "verify_public_key_odd",
            verify_arguments(public_key[:-1], message, context, signature),
            "malformed",
        ),
        CliCase(
            "verify_public_key_nonhex",
            verify_arguments(
                replace_first(public_key, "g"), message, context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_public_key_whitespace",
            verify_arguments(
                replace_first(public_key, " "), message, context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_public_key_prefix",
            verify_arguments(
                "0x" + public_key, message, context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_public_key_non_utf8",
            verify_arguments(
                replace_first_bytes(public_key, b"\xff"),
                message,
                context,
                signature,
            ),
            "malformed",
        ),
        CliCase(
            "verify_message_empty",
            verify_arguments(public_key, "", context, signature),
            "verify_reject",
        ),
        CliCase(
            "verify_message_maximum",
            verify_arguments(
                public_key, "a5" * MAX_MESSAGE_BYTES, context, signature
            ),
            "verify_reject",
        ),
        CliCase(
            "verify_message_oversized",
            verify_arguments(
                public_key, "a5" * (MAX_MESSAGE_BYTES + 1), context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_message_odd",
            verify_arguments(public_key, message + "0", context, signature),
            "malformed",
        ),
        CliCase(
            "verify_message_nonhex",
            verify_arguments(
                public_key, replace_first(message, "g"), context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_message_whitespace",
            verify_arguments(
                public_key, replace_first(message, " "), context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_message_prefix",
            verify_arguments(
                public_key, "0x" + message, context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_message_non_utf8",
            verify_arguments(
                public_key,
                replace_first_bytes(message, b"\xff"),
                context,
                signature,
            ),
            "malformed",
        ),
        CliCase(
            "verify_context_empty",
            verify_arguments(public_key, message, "", signature),
            "verify_reject",
        ),
        CliCase(
            "verify_context_maximum",
            verify_arguments(
                public_key, message, "5a" * MAX_CONTEXT_BYTES, signature
            ),
            "verify_reject",
        ),
        CliCase(
            "verify_context_oversized",
            verify_arguments(
                public_key, message, "5a" * (MAX_CONTEXT_BYTES + 1), signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_context_odd",
            verify_arguments(public_key, message, context + "0", signature),
            "malformed",
        ),
        CliCase(
            "verify_context_nonhex",
            verify_arguments(
                public_key, message, replace_first(context, "g"), signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_context_whitespace",
            verify_arguments(
                public_key, message, replace_first(context, " "), signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_context_prefix",
            verify_arguments(
                public_key, message, "0x" + context, signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_context_non_utf8",
            verify_arguments(
                public_key,
                message,
                replace_first_bytes(context, b"\xff"),
                signature,
            ),
            "malformed",
        ),
        CliCase(
            "verify_signature_empty",
            verify_arguments(public_key, message, context, ""),
            "verify_size_reject",
        ),
        CliCase(
            "verify_signature_short",
            verify_arguments(public_key, message, context, signature[:-2]),
            "verify_size_reject",
        ),
        CliCase(
            "verify_signature_extended",
            verify_arguments(public_key, message, context, signature + "00"),
            "verify_size_reject",
        ),
        CliCase(
            "verify_signature_oversized",
            verify_arguments(public_key, message, context, signature + "0000"),
            "malformed",
        ),
        CliCase(
            "verify_signature_odd",
            verify_arguments(public_key, message, context, signature + "0"),
            "malformed",
        ),
        CliCase(
            "verify_signature_nonhex",
            verify_arguments(
                public_key, message, context, replace_first(signature, "g")
            ),
            "malformed",
        ),
        CliCase(
            "verify_signature_whitespace",
            verify_arguments(
                public_key, message, context, replace_first(signature, " ")
            ),
            "malformed",
        ),
        CliCase(
            "verify_signature_prefix",
            verify_arguments(
                public_key, message, context, "0x" + signature
            ),
            "malformed",
        ),
        CliCase(
            "verify_signature_non_utf8",
            verify_arguments(
                public_key,
                message,
                context,
                replace_first_bytes(signature, b"\xff"),
            ),
            "malformed",
        ),
    ]

    seed_cases = (
        ("keygen_seed_short", seed[:-2]),
        ("keygen_seed_long", seed + "00"),
        ("keygen_seed_odd", seed[:-1]),
        ("keygen_seed_nonhex", replace_first(seed, "g")),
        ("keygen_seed_prefix", "0x" + seed),
        ("keygen_seed_non_utf8", replace_first_bytes(seed, b"\xff")),
    )
    cases.extend(
        CliCase(name, ("keygen", candidate), "malformed")
        for name, candidate in seed_cases
    )

    if oracle.derives_public_key:
        private_key_cases = (
            ("public_key_private_key_short", private_key[:-2]),
            ("public_key_private_key_long", private_key + "00"),
            ("public_key_private_key_odd", private_key[:-1]),
            (
                "public_key_private_key_nonhex",
                replace_first(private_key, "g"),
            ),
            (
                "public_key_private_key_prefix",
                "0x" + private_key,
            ),
            (
                "public_key_private_key_non_utf8",
                replace_first_bytes(private_key, b"\xff"),
            ),
        )
        cases.extend(
            CliCase(name, ("public-key", candidate), "malformed")
            for name, candidate in private_key_cases
        )

    private_key_cases = (
        ("sign_private_key_short", private_key[:-2]),
        ("sign_private_key_long", private_key + "00"),
        ("sign_private_key_odd", private_key[:-1]),
        ("sign_private_key_nonhex", replace_first(private_key, "g")),
        ("sign_private_key_prefix", "0x" + private_key),
        (
            "sign_private_key_non_utf8",
            replace_first_bytes(private_key, b"\xff"),
        ),
    )
    cases.extend(
        CliCase(
            name,
            sign_arguments(
                oracle, candidate, message, context, public_key
            ),
            "malformed",
        )
        for name, candidate in private_key_cases
    )

    sign_field_cases = (
        (
            "sign_message_oversized",
            private_key,
            "00" * (MAX_MESSAGE_BYTES + 1),
            context,
        ),
        ("sign_message_odd", private_key, message + "0", context),
        (
            "sign_message_nonhex",
            private_key,
            replace_first(message, "g"),
            context,
        ),
        (
            "sign_message_non_utf8",
            private_key,
            replace_first_bytes(message, b"\xff"),
            context,
        ),
        (
            "sign_context_oversized",
            private_key,
            message,
            "00" * (MAX_CONTEXT_BYTES + 1),
        ),
        ("sign_context_odd", private_key, message, context + "0"),
        (
            "sign_context_nonhex",
            private_key,
            message,
            replace_first(context, "g"),
        ),
        (
            "sign_context_non_utf8",
            private_key,
            message,
            replace_first_bytes(context, b"\xff"),
        ),
    )
    cases.extend(
        CliCase(
            name,
            sign_arguments(
                oracle,
                candidate_private_key,
                candidate_message,
                candidate_context,
                public_key,
            ),
            "malformed",
        )
        for (
            name,
            candidate_private_key,
            candidate_message,
            candidate_context,
        ) in sign_field_cases
    )

    randomizer = "00" * RANDOMIZER_BYTES
    randomizer_cases = (
        ("sign_randomizer_short", randomizer[:-2]),
        ("sign_randomizer_long", randomizer + "00"),
        ("sign_randomizer_odd", randomizer[:-1]),
        ("sign_randomizer_nonhex", replace_first(randomizer, "g")),
        (
            "sign_randomizer_non_utf8",
            replace_first_bytes(randomizer, b"\xff"),
        ),
    )
    cases.extend(
        CliCase(
            name,
            randomized_sign_arguments(
                oracle,
                private_key,
                message,
                context,
                candidate,
                public_key,
            ),
            "malformed",
        )
        for name, candidate in randomizer_cases
    )

    if oracle.sign_requires_public_key:
        sign_public_key_cases = (
            ("sign_public_key_short", public_key[:-2]),
            ("sign_public_key_long", public_key + "00"),
            ("sign_public_key_odd", public_key[:-1]),
            ("sign_public_key_nonhex", replace_first(public_key, "g")),
            (
                "sign_public_key_non_utf8",
                replace_first_bytes(public_key, b"\xff"),
            ),
        )
        cases.extend(
            CliCase(
                name,
                sign_arguments(
                    oracle,
                    private_key,
                    message,
                    context,
                    candidate,
                ),
                "malformed",
            )
            for name, candidate in sign_public_key_cases
        )

    expected_names = (
        COMMON_FIXED_CASE_IDS
        + KEYGEN_FIXED_CASE_IDS
        + (
            PUBLIC_KEY_FIXED_CASE_IDS
            if oracle.derives_public_key
            else ()
        )
        + SIGN_FIXED_CASE_IDS
        + (
            SIGN_PUBLIC_KEY_FIXED_CASE_IDS
            if oracle.sign_requires_public_key
            else ()
        )
    )
    actual_names = tuple(case.name for case in cases)
    if actual_names != expected_names:
        raise CliFuzzError("generated fixed CLI case order differs from its contract")
    return cases


def mutate_argument(
    value: str,
    kind: str,
    maximum_size: int,
    variant: int,
) -> str | bytes:
    if kind == "oversized":
        return "00" * (maximum_size + 1)
    if kind == "odd":
        return value[:-1] if len(value) >= maximum_size * 2 else value + "0"
    if kind == "prefix":
        return "0x" + value
    positions = (0, len(value) // 3, (2 * len(value)) // 3, len(value) - 1)
    position = positions[variant]
    if kind == "non_utf8":
        encoded = value.encode("ascii")
        return encoded[:position] + b"\xff" + encoded[position + 1 :]
    replacement = "g" if kind == "nonhex" else " "
    if not value:
        return replacement
    return value[:position] + replacement + value[position + 1 :]


def mutation_cases(
    *,
    public_key: str,
    message: str,
    context: str,
    signature: str,
) -> list[CliCase]:
    values = {
        "public_key": public_key,
        "message": message,
        "context": context,
        "signature": signature,
    }
    maxima = {
        "public_key": PUBLIC_KEY_BYTES,
        "message": MAX_MESSAGE_BYTES,
        "context": MAX_CONTEXT_BYTES,
        "signature": MAX_VERIFY_SIGNATURE_BYTES,
    }
    cases = []
    for index, field, kind, variant, state in mutation_descriptors():
        arguments: dict[str, str | bytes] = dict(values)
        arguments[field] = mutate_argument(
            values[field], kind, maxima[field], variant
        )
        name = f"mutation_{index:03d}_{field}_{kind}_{state:08x}"
        cases.append(
            CliCase(
                name,
                verify_arguments(
                    arguments["public_key"],
                    arguments["message"],
                    arguments["context"],
                    arguments["signature"],
                ),
                "malformed",
            )
        )
    expected_digest = mutation_contract()["label_inventory_sha256"]
    actual_digest = hashlib.sha256(
        "".join(f"{case.name}\n" for case in cases).encode("ascii")
    ).hexdigest()
    if actual_digest != expected_digest:
        raise CliFuzzError("generated mutation case labels differ from manifest")
    return cases


def encoded_arguments(arguments: tuple[str | bytes, ...]) -> list[bytes]:
    return [
        argument if isinstance(argument, bytes) else argument.encode("utf8")
        for argument in arguments
    ]


def argument_summary(arguments: tuple[str | bytes, ...]) -> dict[str, object]:
    encoded = encoded_arguments(arguments)
    digest = hashlib.sha256()
    for value in encoded:
        digest.update(len(value).to_bytes(8, "little"))
        digest.update(value)
    return {
        "argument_count": len(encoded),
        "argument_lengths": [len(value) for value in encoded],
        "argv_sha256": digest.hexdigest(),
    }


def apply_child_limits(sanitized: bool) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    resource.setrlimit(resource.RLIMIT_STACK, (STACK_LIMIT_BYTES, STACK_LIMIT_BYTES))
    resource.setrlimit(
        resource.RLIMIT_FSIZE, (FILE_SIZE_LIMIT_BYTES, FILE_SIZE_LIMIT_BYTES)
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (OPEN_FILE_LIMIT, OPEN_FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if not sanitized:
        resource.setrlimit(
            resource.RLIMIT_AS,
            (ADDRESS_SPACE_LIMIT_BYTES, ADDRESS_SPACE_LIMIT_BYTES),
        )


def verify_process_result(
    adapter_name: str,
    case: CliCase,
    completed: subprocess.CompletedProcess[bytes],
) -> None:
    if completed.returncode < 0:
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: terminated by signal "
            f"{-completed.returncode}"
        )
    if (
        len(completed.stdout) > MAX_ACCEPTED_OUTPUT_BYTES
        or len(completed.stderr) > MAX_ACCEPTED_OUTPUT_BYTES
    ):
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: output exceeded the capture bound"
        )
    for marker in FATAL_MARKERS:
        if marker in completed.stdout or marker in completed.stderr:
            raise CliFuzzError(
                f"{adapter_name}/{case.name}: fatal marker {marker!r}"
            )

    if case.expected == "usage":
        valid = (
            completed.returncode == 2
            and completed.stdout == b""
            and completed.stderr.startswith(b"usage: ")
            and completed.stderr.endswith(b"\n")
        )
    elif case.expected == "malformed":
        valid = (
            completed.returncode == 1
            and completed.stdout == b""
            and completed.stderr != b""
            and completed.stderr.endswith(b"\n")
        )
    elif case.expected == "verify_size_reject":
        valid = (
            completed.returncode == 0
            and completed.stdout == b"verified=0\nverify_ns=0\n"
            and completed.stderr == b""
        )
    elif case.expected in {"verify_accept", "verify_reject"}:
        match = VERIFY_OUTPUT.fullmatch(completed.stdout)
        expected_verified = b"1" if case.expected == "verify_accept" else b"0"
        valid = (
            completed.returncode == 0
            and completed.stderr == b""
            and match is not None
            and match.group(1) == expected_verified
        )
    else:
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: unsupported expected result "
            f"{case.expected}"
        )
    if not valid:
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: expected {case.expected}, got "
            f"exit={completed.returncode}, stdout_sha256="
            f"{hashlib.sha256(completed.stdout).hexdigest()}, stderr_sha256="
            f"{hashlib.sha256(completed.stderr).hexdigest()}"
        )

    combined_output = completed.stdout + completed.stderr
    for argument in encoded_arguments(case.arguments):
        if len(argument) >= 32 and argument in combined_output:
            raise CliFuzzError(
                f"{adapter_name}/{case.name}: oracle output echoed an input"
            )


def run_case(adapter_name: str, oracle: OracleLike, case: CliCase) -> dict[str, object]:
    command = [os.fsencode(oracle.executable), *encoded_arguments(case.arguments)]
    environment = os.environ.copy()
    if oracle.sanitized:
        leak_detection = "1" if sys.platform.startswith("linux") else "0"
        environment["ASAN_OPTIONS"] = (
            f"detect_leaks={leak_detection}:halt_on_error=1:abort_on_error=1"
        )
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    preexec_fn = None
    if sys.platform.startswith("linux"):
        preexec_fn = partial(apply_child_limits, oracle.sanitized)
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=WALL_TIMEOUT_SECONDS,
            preexec_fn=preexec_fn,
        )
    except subprocess.TimeoutExpired as error:
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: exceeded the "
            f"{WALL_TIMEOUT_SECONDS}-second wall limit"
        ) from error
    except (OSError, subprocess.SubprocessError) as error:
        raise CliFuzzError(
            f"{adapter_name}/{case.name}: could not execute bounded child"
        ) from error
    verify_process_result(adapter_name, case, completed)
    return {
        "name": case.name,
        "expected": case.expected,
        **argument_summary(case.arguments),
        "return_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def case_inventory_summary(records: list[dict[str, object]]) -> dict[str, object]:
    digest = hashlib.sha256()
    outcome_counts: dict[str, int] = {}
    for record in records:
        outcome = str(record["expected"])
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        digest.update(
            (
                f"{record['name']}\0{outcome}\0{record['argv_sha256']}\0"
                f"{record['return_code']}\0{record['stdout_sha256']}\0"
                f"{record['stderr_sha256']}\n"
            ).encode("ascii")
        )
    return {
        "case_count": len(records),
        "unique_argv_count": len(
            {str(record["argv_sha256"]) for record in records}
        ),
        "outcome_counts": outcome_counts,
        "evidence_aggregate_sha256": digest.hexdigest(),
    }


def evaluate_cli_adapters(
    oracles: dict[str, OracleLike],
    *,
    seed: str,
    private_key: str,
    public_key: str,
    message: str,
    context: str,
    signature: str,
) -> dict[str, object]:
    validate_manifest()
    reports = {}
    mutations = mutation_cases(
        public_key=public_key,
        message=message,
        context=context,
        signature=signature,
    )
    for adapter_name, oracle in oracles.items():
        fixed = fixed_cases(
            oracle,
            seed=seed,
            private_key=private_key,
            public_key=public_key,
            message=message,
            context=context,
            signature=signature,
        )
        fixed_records = [
            run_case(adapter_name, oracle, case) for case in fixed
        ]
        mutation_records = [
            run_case(adapter_name, oracle, case) for case in mutations
        ]
        mutation_summary = case_inventory_summary(mutation_records)
        if mutation_summary["unique_argv_count"] != MUTATION_CASES:
            raise CliFuzzError(
                f"{adapter_name}: generated mutation argv corpus is not unique"
            )
        reports[adapter_name] = {
            "sanitized": oracle.sanitized,
            "limits_applied": {
                "wall_timeout": True,
                "linux_rlimits": sys.platform.startswith("linux"),
                "address_space_rlimit": (
                    sys.platform.startswith("linux") and not oracle.sanitized
                ),
            },
            "fixed": case_inventory_summary(fixed_records),
            "mutations": mutation_summary,
            "cases": fixed_records + mutation_records,
        }
    return {
        "status": "PASS",
        "target": "research-oracle-cli-argv",
        "parser_limits": parser_limits(),
        "process_limits": process_limits(),
        "runtime_limit_application": {
            "platform": sys.platform,
            "wall_timeout_applied": True,
            "linux_rlimits_applied": sys.platform.startswith("linux"),
            "address_space_rlimit_applied": (
                sys.platform.startswith("linux")
                and all(not oracle.sanitized for oracle in oracles.values())
            ),
        },
        "manifest_sha256": sha256_file(MANIFEST_PATH),
        "adapters": reports,
        "scope": (
            "research adapter argv parsing and child-process containment; "
            "not a production parser or cryptographic resource proof"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-only", action="store_true")
    args = parser.parse_args()
    if not args.manifest_only:
        print(
            "run_cli_adapter_fuzz.py: executable adapter paths and deterministic "
            "key material are supplied by compare_oracles.py",
            file=sys.stderr,
        )
        return 1
    try:
        manifest = validate_manifest()
    except (CliFuzzError, OSError, ValueError) as error:
        print(f"run_cli_adapter_fuzz.py: {error}", file=sys.stderr)
        return 1
    print(
        "ML-DSA-44 research CLI fuzz manifest passed: "
        f"{manifest['mutation_contract']['cases_per_adapter']} mutations per adapter"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
