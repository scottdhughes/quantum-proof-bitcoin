"""Unit tests for SHRINCS KAT locks, resource bounds, and fuzz framing."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_DIR = REPO_ROOT / "contrib" / "shrincs-ref"


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, REF_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CHECK_KATS = load_module("shrincs_check_kats", "check_kats.py")
RESOURCE = load_module("shrincs_resource_model", "resource_model.py")
STACK = load_module("shrincs_stack_usage", "collect_stack_usage.py")
FUZZ = load_module("shrincs_fuzz_corpus", "build_fuzz_corpus.py")


class ShrincsKatResourceTests(unittest.TestCase):
    def test_committed_kat_lock_is_valid(self) -> None:
        lock = CHECK_KATS.load_lock()
        self.assertEqual(lock["corpora"]["stateful"]["vector_count"], 7)
        self.assertEqual(lock["corpora"]["stateless"]["vector_count"], 2)

    def test_kat_lock_digest_tamper_is_rejected(self) -> None:
        lock = CHECK_KATS.load_lock()
        lock = copy.deepcopy(lock)
        lock["corpora"]["stateful"]["sha256"] = "z" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(CHECK_KATS.KatError, "locked SHA-256 is invalid"):
                CHECK_KATS.load_lock(path)

    def test_one_shot_sha256_padding_boundaries(self) -> None:
        self.assertEqual(RESOURCE.sha256_compressions(0), 1)
        self.assertEqual(RESOURCE.sha256_compressions(55), 1)
        self.assertEqual(RESOURCE.sha256_compressions(56), 2)
        self.assertEqual(RESOURCE.sha256_compressions(63), 2)
        self.assertEqual(RESOURCE.sha256_compressions(64), 2)

    def test_wots_tw_exact_step_envelope(self) -> None:
        envelope = RESOURCE.wots_tw_step_envelope()
        self.assertEqual(envelope.minimum, 45)
        self.assertEqual(envelope.maximum, 510)
        maximizers = [
            checksum
            for checksum in range(481)
            if RESOURCE.wots_tw_verify_steps_from_checksum(checksum) == envelope.maximum
        ]
        self.assertEqual(maximizers, [480])

    def test_global_compression_bounds(self) -> None:
        self.assertEqual(RESOURCE.stateful_global_maximum(), 1074)
        self.assertEqual(RESOURCE.stateless_global_maximum(), 5601)

    def test_stateful_length_depth_mapping(self) -> None:
        self.assertEqual(RESOURCE.stateful_signature_depth(554), 1)
        self.assertEqual(RESOURCE.stateful_signature_depth(4618), 255)
        with self.assertRaisesRegex(ValueError, "non-canonical"):
            RESOURCE.stateful_signature_depth(555)

    def test_stack_usage_line_parser(self) -> None:
        entry = STACK.parse_line("file.c:10:2:verify\t992\tstatic\n", Path("x.su"))
        self.assertEqual(entry["frame_bytes"], 992)
        self.assertEqual(entry["qualifier"], "static")

    def vector(self, name: str, signature_bytes: int) -> dict[str, str]:
        return {
            "name": name,
            "public_key": (b"p" * 48).hex(),
            "signature": (b"s" * signature_bytes).hex(),
            "message": (b"m" * 32).hex(),
            "context": b"ctx".hex(),
        }

    def test_fuzz_encoding_has_exact_length_header(self) -> None:
        encoded = FUZZ.encode(b"p" * 48, b"s" * 554, b"m" * 32, b"ctx")
        self.assertEqual(encoded[0], 48)
        self.assertEqual(int.from_bytes(encoded[1:3], "big"), 554)
        self.assertEqual(int.from_bytes(encoded[3:5], "big"), 32)
        self.assertEqual(int.from_bytes(encoded[5:7], "big"), 3)
        self.assertEqual(len(encoded), 7 + 48 + 554 + 32 + 3)

    def test_fuzz_seed_builder_includes_both_modes(self) -> None:
        cases = FUZZ.build([self.vector("stateful", 554)], [self.vector("stateless", 5776)])
        self.assertGreaterEqual(len(cases), 20)
        self.assertTrue(any(name.startswith("valid-stateful") for name in cases))
        self.assertTrue(any(name.startswith("valid-stateless") for name in cases))


if __name__ == "__main__":
    unittest.main()
