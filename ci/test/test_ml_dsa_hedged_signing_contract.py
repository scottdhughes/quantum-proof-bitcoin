import importlib.util
import inspect
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    REPO_ROOT
    / "contrib"
    / "ml-dsa-engineering"
    / "hedged_signing_contract.py"
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract = load_module(CONTRACT_PATH, "ml_dsa_hedged_signing_contract")


class ConstantSource:
    def __init__(self, output: bytes, produced: int | None = None):
        self.output = output
        self.produced = len(output) if produced is None else produced
        self.calls = 0
        self.views = []
        self.lock = threading.Lock()

    def fill(self, output: memoryview) -> int:
        with self.lock:
            self.calls += 1
        self.views.append(output)
        output[: len(self.output)] = self.output
        return self.produced


class SequenceSource:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.lock = threading.Lock()

    def fill(self, output: memoryview) -> int:
        with self.lock:
            generated = self.outputs.pop(0)
        output[:] = generated
        return len(generated)


class FailingSource:
    def fill(self, output: memoryview) -> int:
        del output
        raise OSError("injected entropy failure")


class FailingAfterWriteSource:
    def __init__(self):
        self.views = []

    def fill(self, output: memoryview) -> int:
        self.views.append(output)
        output[:] = bytes([0xA5]) * contract.RANDOMIZER_BYTES
        raise OSError("injected provider failure after write")


class FakeBackend:
    def __init__(
        self,
        *,
        signature: bytes | None = None,
        sign_error: bool = False,
        verify_result: bool = True,
        verify_error: bool = False,
    ):
        self.signature = (
            signature
            if signature is not None
            else bytes([0x5A]) * contract.SIGNATURE_BYTES
        )
        self.sign_error = sign_error
        self.verify_result = verify_result
        self.verify_error = verify_error
        self.sign_calls = 0
        self.verify_calls = 0
        self.randomizer_views = []
        self.active_sign_calls = 0
        self.max_active_sign_calls = 0
        self.lock = threading.Lock()

    def sign(
        self,
        signing_key: object,
        message: bytes,
        context: bytes,
        randomizer: memoryview,
    ) -> bytes:
        del signing_key, message, context
        with self.lock:
            self.sign_calls += 1
            self.active_sign_calls += 1
            self.max_active_sign_calls = max(
                self.max_active_sign_calls, self.active_sign_calls
            )
        self.randomizer_views.append(randomizer)
        if self.sign_error:
            with self.lock:
                self.active_sign_calls -= 1
            raise RuntimeError("injected signing failure")
        time.sleep(0.005)
        with self.lock:
            self.active_sign_calls -= 1
        return self.signature

    def verify(
        self,
        verification_key: object,
        message: bytes,
        context: bytes,
        signature: bytes,
    ) -> bool:
        del verification_key, message, context, signature
        self.verify_calls += 1
        if self.verify_error:
            raise RuntimeError("injected verification failure")
        return self.verify_result


class MLDSAHedgedSigningContractTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = object()
        self.verification_key = object()
        self.message = bytes(range(32))
        self.context = b"PQBTC/tx-signature/v1"

    def signer(self, backend, source):
        return contract._make_test_signer(backend, source)

    def sign(self, signer):
        return signer.sign(
            self.signing_key,
            self.verification_key,
            self.message,
            self.context,
        )

    def assert_failure(self, result, expected):
        self.assertFalse(result.ok)
        self.assertIsNone(result.signature)
        self.assertEqual(result.error, expected)

    def test_public_surface_is_hedged_only(self):
        self.assertEqual(
            contract.__all__,
            [
                "HedgedSignError",
                "HedgedSignResult",
                "HedgedSigner",
            ],
        )
        public_text = " ".join(contract.__all__).lower()
        for forbidden in ("deterministic", "fixed", "randomizer", "entropy"):
            self.assertNotIn(forbidden, public_text)
        self.assertEqual(
            list(inspect.signature(contract.HedgedSigner).parameters), ["backend"]
        )
        self.assertNotIn(
            "randomizer", inspect.signature(contract.HedgedSigner.sign).parameters
        )

    def test_success_returns_only_self_verified_signature(self):
        source = ConstantSource(bytes(range(1, 33)))
        backend = FakeBackend()
        result = self.sign(self.signer(backend, source))
        self.assertTrue(result.ok)
        self.assertEqual(result.signature, backend.signature)
        self.assertIsNone(result.error)
        self.assertEqual(backend.sign_calls, 1)
        self.assertEqual(backend.verify_calls, 1)
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_public_signer_acquires_randomizer_internally(self):
        backend = FakeBackend()
        signer = contract.HedgedSigner(backend)
        with mock.patch.object(
            contract.os, "urandom", return_value=bytes(range(1, 33))
        ) as urandom:
            result = self.sign(signer)
        self.assertTrue(result.ok)
        urandom.assert_called_once_with(contract.RANDOMIZER_BYTES)
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_entropy_exception_is_fail_closed(self):
        backend = FakeBackend()
        result = self.sign(self.signer(backend, FailingSource()))
        self.assert_failure(result, contract.HedgedSignError.ENTROPY_SOURCE_FAILURE)
        self.assertEqual(backend.sign_calls, 0)

    def test_entropy_failure_after_write_is_cleared(self):
        source = FailingAfterWriteSource()
        backend = FakeBackend()
        result = self.sign(self.signer(backend, source))
        self.assert_failure(result, contract.HedgedSignError.ENTROPY_SOURCE_FAILURE)
        self.assertEqual(bytes(source.views[0]), bytes(32))
        self.assertEqual(backend.sign_calls, 0)

    def test_entropy_short_read_is_fail_closed_and_cleared(self):
        source = ConstantSource(bytes(range(1, 32)), produced=31)
        backend = FakeBackend()
        result = self.sign(self.signer(backend, source))
        self.assert_failure(result, contract.HedgedSignError.ENTROPY_SHORT_READ)
        self.assertEqual(backend.sign_calls, 0)
        self.assertEqual(bytes(source.views[0]), bytes(32))

    def test_zero_randomizer_cannot_be_a_deterministic_fallback(self):
        backend = FakeBackend()
        result = self.sign(self.signer(backend, ConstantSource(bytes(32))))
        self.assert_failure(result, contract.HedgedSignError.ENTROPY_ZERO_OUTPUT)
        self.assertEqual(backend.sign_calls, 0)

    def test_immediate_randomizer_reuse_is_rejected(self):
        backend = FakeBackend()
        signer = self.signer(backend, ConstantSource(bytes([0xA5]) * 32))
        self.assertTrue(self.sign(signer).ok)
        second = self.sign(signer)
        self.assert_failure(
            second, contract.HedgedSignError.ENTROPY_REPEATED_OUTPUT
        )
        self.assertEqual(backend.sign_calls, 1)

    def test_fork_or_snapshot_after_use_retains_repeat_guard(self):
        backend = FakeBackend()
        signer = self.signer(backend, ConstantSource(bytes([0x3C]) * 32))
        self.assertTrue(self.sign(signer).ok)
        clone = signer.snapshot_for_test()
        result = self.sign(clone)
        self.assert_failure(
            result, contract.HedgedSignError.ENTROPY_REPEATED_OUTPUT
        )

    def test_repeat_guard_is_atomic_for_concurrent_callers(self):
        backend = FakeBackend()
        signer = self.signer(backend, ConstantSource(bytes([0xC3]) * 32))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.sign(signer), range(2)))
        self.assertEqual(sum(result.ok for result in results), 1)
        self.assertEqual(
            [result.error for result in results].count(
                contract.HedgedSignError.ENTROPY_REPEATED_OUTPUT
            ),
            1,
        )
        self.assertEqual(backend.max_active_sign_calls, 1)

    def test_distinct_concurrent_calls_are_fully_serialized(self):
        backend = FakeBackend()
        source = SequenceSource(
            [bytes([0x69]) * 32, bytes([0x96]) * 32]
        )
        signer = self.signer(backend, source)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.sign(signer), range(2)))
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(backend.sign_calls, 2)
        self.assertEqual(backend.max_active_sign_calls, 1)

    def test_backend_signing_failure_returns_no_output(self):
        backend = FakeBackend(sign_error=True)
        result = self.sign(
            self.signer(backend, ConstantSource(bytes(range(32, 64))))
        )
        self.assert_failure(result, contract.HedgedSignError.BACKEND_SIGN_FAILURE)
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_wrong_signature_length_returns_no_output(self):
        backend = FakeBackend(signature=bytes(contract.SIGNATURE_BYTES - 1))
        result = self.sign(
            self.signer(backend, ConstantSource(bytes(range(64, 96))))
        )
        self.assert_failure(
            result, contract.HedgedSignError.SIGNATURE_LENGTH_MISMATCH
        )
        self.assertEqual(backend.verify_calls, 0)

    def test_self_verification_rejection_returns_no_output(self):
        backend = FakeBackend(verify_result=False)
        result = self.sign(
            self.signer(backend, ConstantSource(bytes(range(96, 128))))
        )
        self.assert_failure(
            result, contract.HedgedSignError.SELF_VERIFICATION_FAILURE
        )
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_truthy_non_boolean_verification_is_rejected(self):
        backend = FakeBackend(verify_result=1)
        result = self.sign(
            self.signer(backend, ConstantSource(bytes(range(160, 192))))
        )
        self.assert_failure(
            result, contract.HedgedSignError.SELF_VERIFICATION_FAILURE
        )
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_self_verification_error_returns_no_output(self):
        backend = FakeBackend(verify_error=True)
        result = self.sign(
            self.signer(backend, ConstantSource(bytes(range(128, 160))))
        )
        self.assert_failure(
            result, contract.HedgedSignError.SELF_VERIFICATION_FAILURE
        )
        self.assertEqual(bytes(backend.randomizer_views[0]), bytes(32))

    def test_invalid_input_does_not_request_entropy(self):
        source = ConstantSource(bytes(range(1, 33)))
        signer = self.signer(FakeBackend(), source)
        result = signer.sign(
            self.signing_key,
            self.verification_key,
            self.message,
            bytes(256),
        )
        self.assert_failure(result, contract.HedgedSignError.INVALID_INPUT)
        self.assertEqual(source.calls, 0)


if __name__ == "__main__":
    unittest.main()
