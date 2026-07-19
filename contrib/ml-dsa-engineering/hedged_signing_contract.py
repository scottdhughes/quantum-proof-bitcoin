#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Executable model of the ML-DSA hedged-signing failure contract.

This module is an engineering model, not a cryptographic implementation. It
keeps entropy acquisition inside the public signing boundary and exposes no
deterministic or caller-supplied-randomizer production entry point.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


RANDOMIZER_BYTES = 32
SIGNATURE_BYTES = 2420

__all__ = [
    "HedgedSignError",
    "HedgedSignResult",
    "HedgedSigner",
]


class HedgedSignError(str, Enum):
    INVALID_INPUT = "invalid_input"
    ENTROPY_SOURCE_FAILURE = "entropy_source_failure"
    ENTROPY_SHORT_READ = "entropy_short_read"
    ENTROPY_ZERO_OUTPUT = "entropy_zero_output"
    ENTROPY_REPEATED_OUTPUT = "entropy_repeated_output"
    BACKEND_SIGN_FAILURE = "backend_sign_failure"
    SIGNATURE_LENGTH_MISMATCH = "signature_length_mismatch"
    SELF_VERIFICATION_FAILURE = "self_verification_failure"


@dataclass(frozen=True)
class HedgedSignResult:
    signature: bytes | None
    error: HedgedSignError | None

    def __post_init__(self) -> None:
        if (self.signature is None) == (self.error is None):
            raise ValueError("exactly one of signature or error must be set")

    @property
    def ok(self) -> bool:
        return self.error is None


class _SigningBackend(Protocol):
    """Backend operations required by the project-owned signing boundary."""

    def sign(
        self,
        signing_key: object,
        message: bytes,
        context: bytes,
        randomizer: memoryview,
    ) -> bytes:
        """Return one ML-DSA-44 signature using the supplied hedging value."""

    def verify(
        self,
        verification_key: object,
        message: bytes,
        context: bytes,
        signature: bytes,
    ) -> bool:
        """Return whether the generated signature verifies."""


class _RandomizerSource(Protocol):
    def fill(self, output: memoryview) -> int:
        """Fill output and return the exact number of bytes produced."""


class _SystemRandomizer:
    def fill(self, output: memoryview) -> int:
        generated = os.urandom(RANDOMIZER_BYTES)
        output[:] = generated
        return len(generated)


class _RandomizerGuard:
    """Reject immediate reuse without retaining the randomizer itself."""

    def __init__(self, last_digest: bytes | None = None) -> None:
        self._last_digest = last_digest
        self._lock = threading.Lock()

    def consume(self, randomizer: memoryview) -> bool:
        digest = hashlib.sha256(randomizer).digest()
        with self._lock:
            if self._last_digest is not None and hmac.compare_digest(
                digest, self._last_digest
            ):
                return False
            self._last_digest = digest
            return True

    def snapshot(self) -> _RandomizerGuard:
        with self._lock:
            return _RandomizerGuard(self._last_digest)


def _failure(error: HedgedSignError) -> HedgedSignResult:
    return HedgedSignResult(signature=None, error=error)


class _HedgedSignerCore:
    def __init__(
        self,
        backend: _SigningBackend,
        randomizer_source: _RandomizerSource,
        guard: _RandomizerGuard | None = None,
    ) -> None:
        self._backend = backend
        self._randomizer_source = randomizer_source
        self._guard = guard or _RandomizerGuard()
        self._operation_lock = threading.Lock()

    def sign(
        self,
        signing_key: object,
        verification_key: object,
        message: bytes,
        context: bytes,
    ) -> HedgedSignResult:
        with self._operation_lock:
            return self._sign_locked(
                signing_key,
                verification_key,
                message,
                context,
            )

    def _sign_locked(
        self,
        signing_key: object,
        verification_key: object,
        message: bytes,
        context: bytes,
    ) -> HedgedSignResult:
        if (
            signing_key is None
            or verification_key is None
            or not isinstance(message, bytes)
            or not isinstance(context, bytes)
            or len(context) > 255
        ):
            return _failure(HedgedSignError.INVALID_INPUT)

        randomizer = bytearray(RANDOMIZER_BYTES)
        try:
            try:
                produced = self._randomizer_source.fill(memoryview(randomizer))
            except Exception:
                return _failure(HedgedSignError.ENTROPY_SOURCE_FAILURE)

            if type(produced) is not int or produced != RANDOMIZER_BYTES:
                return _failure(HedgedSignError.ENTROPY_SHORT_READ)
            if not any(randomizer):
                return _failure(HedgedSignError.ENTROPY_ZERO_OUTPUT)
            if not self._guard.consume(memoryview(randomizer)):
                return _failure(HedgedSignError.ENTROPY_REPEATED_OUTPUT)

            try:
                signature = self._backend.sign(
                    signing_key,
                    message,
                    context,
                    memoryview(randomizer),
                )
            except Exception:
                return _failure(HedgedSignError.BACKEND_SIGN_FAILURE)

            if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
                return _failure(HedgedSignError.SIGNATURE_LENGTH_MISMATCH)

            try:
                verified = self._backend.verify(
                    verification_key,
                    message,
                    context,
                    signature,
                )
            except Exception:
                verified = False
            if verified is not True:
                return _failure(HedgedSignError.SELF_VERIFICATION_FAILURE)

            return HedgedSignResult(signature=signature, error=None)
        finally:
            randomizer[:] = bytes(RANDOMIZER_BYTES)

    def snapshot_for_test(self) -> _HedgedSignerCore:
        return _HedgedSignerCore(
            self._backend,
            self._randomizer_source,
            self._guard.snapshot(),
        )


class HedgedSigner:
    """Public hedged-only signing boundary for the engineering contract."""

    def __init__(self, backend: _SigningBackend) -> None:
        self.__core = _HedgedSignerCore(backend, _SystemRandomizer())

    def sign(
        self,
        signing_key: object,
        verification_key: object,
        message: bytes,
        context: bytes,
    ) -> HedgedSignResult:
        return self.__core.sign(signing_key, verification_key, message, context)


def _make_test_signer(
    backend: _SigningBackend,
    randomizer_source: _RandomizerSource,
) -> _HedgedSignerCore:
    return _HedgedSignerCore(backend, randomizer_source)
