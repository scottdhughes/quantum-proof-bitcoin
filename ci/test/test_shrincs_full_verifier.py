"""Unit tests for the strict dual-mode SHRINCS verifier harness."""

from __future__ import annotations

import importlib.util
import contextlib
import copy
import ctypes
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_full.py"
SPEC = importlib.util.spec_from_file_location("shrincs_full_verifier", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def stateful_fixtures() -> list[dict]:
    rows = (
        ("uxmss_depth4_state0", "0004", 0, 1, 1, "", "b82e4291f262975e54c75b4e53c693c5e8b7140514fd1b6381fdb0f9e6933281"),
        ("uxmss_depth4_state1", "0004", 1, 1, 2, "PQBTC/SHRINCS/stateful-v0", "4ab628bf2bdaedadc1a5823f4c5ac87a8fe4d3cd70e2519decdbc3257f194b1e"),
        ("uxmss_depth4_state3", "0004", 3, 1, 4, "context-3", "6f78eb3997d15795a6bd9240161553d18f8e976bd2c400bcd53df07e45ba827f"),
        ("uxmss_depth4_state4", "0004", 4, 0, 4, "terminal-leaf", "cd80f3703c33c7873e2b54c5add8996f132c6a724f8027d10547d82bf20f6114"),
        ("bxmss_depth3_state0", "0103", 0, 0, 3, "", "fc613420c1119212c82920b1fa239e3446a1e750d8b978f2050aa88703ed1972"),
        ("bxmss_depth3_state3", "0103", 3, 3, 3, "balanced-middle", "b84852d6d71d8c503b8262b928510bb0131cf91e420d54b4f9137323b5c0646d"),
        ("bxmss_depth3_state7", "0103", 7, 7, 3, "balanced-final", "410c9d9ffa5336779bd782176b3ec94bc26a4a9a7f5afe1f4e9b487e5d28004d"),
    )
    vectors = []
    for name, structure, state, index, depth, context, message in rows:
        key = bytes.fromhex(("11" if structure == "0004" else "33") * 48)
        signature = bytes(16) + index.to_bytes(8, "big") + bytes(514 + 16 * depth)
        vectors.append({"name": name, "structure": structure, "state": state,
                        "leaf_index": index, "leaf_depth": depth, "message": message,
                        "context": context.encode().hex(), "public_key": key.hex(),
                        "signature": signature.hex(), "public_key_sha256": hashlib.sha256(key).hexdigest(),
                        "signature_sha256": hashlib.sha256(signature).hexdigest()})
    return vectors


def stateless_fixtures() -> list[dict]:
    rows = (
        ("stateless_deterministic_empty_context", "deterministic", None, "",
         "f4dd4a2696c1d6493ff2c86048cee4b019746f2329bdd5a8e37bf2fa843c3883"),
        ("stateless_fixed_randomizer_context", "fixed-randomizer", "2b1aaa0472a7b3fcc5d613a0a7cde55c",
         "PQBTC/SHRINCS/stateless-recovery-v0",
         "6ca8be5ef96403aa67f22a49cf8d1fc9a2c4e72beb6efce6a99a91c7d078222ce9633b5996c7f7cb13b0e5e4ad7d13"),
    )
    key, signature = bytes.fromhex("44" * 48), bytes.fromhex("55" * 5776)
    return [{"name": name, "mode": mode, "opt_rand": rand, "context": ctx.encode().hex(),
             "message": msg, "public_key": key.hex(), "signature": signature.hex(),
             "public_key_sha256": hashlib.sha256(key).hexdigest(),
             "signature_sha256": hashlib.sha256(signature).hexdigest()}
            for name, mode, rand, ctx, msg in rows]


class FullEvidenceContractTests(unittest.TestCase):
    def setUp(self):
        # Synthetic byte fixtures exercise validation/control flow, not crypto.
        # The real unpatched frozen table is qualified by contained native replay.
        hashes = {v["name"]: (v["public_key_sha256"], v["signature_sha256"])
                  for v in stateful_fixtures() + stateless_fixtures()}
        patch = mock.patch.object(CHECKER, "FROZEN_VECTOR_HASHES", hashes, create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def valid_only_verifier(self, *args):
        if args[1] != 48 or args[3] not in (554, 570, 586, 602, 5776) or args[5] > 4096 or args[7] > 255:
            return 0
        values = tuple(ctypes.string_at(args[i], args[i + 1]) if args[i] is not None else b""
                       for i in range(0, 8, 2))
        # A null pointer with nonzero length is invalid, not an empty value.
        if any(args[i] is None and args[i + 1] != 0 for i in range(0, 8, 2)):
            return 0
        valid = {tuple(bytes.fromhex(v[field]) for field in ("public_key", "signature", "message", "context"))
                 for v in stateful_fixtures() + stateless_fixtures()}
        return int(values in valid)

    def corpus(self, mode="stateful") -> dict:
        return {"profile": f"pqbtc-shrincs-current-draft-{mode}-kat-v0",
                "draft_commit": "acc6bda51dc3b94848d118967247ad0f3cd7a80e",
                "libshrincs_commit": "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5",
                "vectors": stateful_fixtures() if mode == "stateful" else stateless_fixtures()}

    def read(self, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vectors.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return CHECKER.read_corpus(path)

    def test_complete_structural_corpora_load(self):
        self.assertEqual(len(self.read(self.corpus())), 7)
        self.assertEqual(len(self.read(self.corpus("stateless"))), 2)

    def test_corpus_metadata_and_coverage_cannot_be_reduced(self):
        mutations = (
            lambda d: d.update(profile="other"),
            lambda d: d.update(draft_commit="00" * 20),
            lambda d: d.update(libshrincs_commit="00" * 20),
            lambda d: d["vectors"].pop(),
            lambda d: d["vectors"].reverse(),
            lambda d: d["vectors"].__setitem__(1, copy.deepcopy(d["vectors"][0])),
            lambda d: d.update(padding="x" * 70000),
        )
        for mode in ("stateful", "stateless"):
            for number, mutate in enumerate(mutations):
                with self.subTest(mode=mode, mutation=number):
                    data = self.corpus(mode)
                    mutate(data)
                    with self.assertRaises(CHECKER.FullVerifierError):
                        self.read(data)

    def test_stateful_fields_and_hashes_bind_retained_bytes(self):
        for field, value in (("signature_sha256", "00" * 32), ("public_key_sha256", "00" * 32),
                             ("leaf_index", 0), ("leaf_depth", 2), ("state", 1), ("structure", "0103"),
                             ("message", "00" * 32), ("context", "00"), ("signature", "11" * 555)):
            with self.subTest(field=field):
                data = self.corpus()
                data["vectors"][0][field] = value
                with self.assertRaises(CHECKER.FullVerifierError):
                    self.read(data)

    def test_self_rehashed_substitutions_cannot_replace_frozen_vectors(self):
        for mode in ("stateful", "stateless"):
            for field in ("public_key", "signature"):
                with self.subTest(mode=mode, field=field):
                    data = self.corpus(mode)
                    # Rewrite every key to retain each group's shared-key invariant.
                    for vector in data["vectors"]:
                        value = bytes.fromhex(vector[field])
                        value = bytes([value[0] ^ 1]) + value[1:]
                        vector[field] = value.hex()
                        vector[field + "_sha256"] = hashlib.sha256(value).hexdigest()
                    with self.assertRaisesRegex(CHECKER.FullVerifierError, "frozen.*identity"):
                        self.read(data)

    def test_native_errors_are_not_counted_as_invalid_signatures(self):
        for status in (-1, 2):
            with self.subTest(status=status), self.assertRaisesRegex(CHECKER.FullVerifierError, "ABI status"):
                CHECKER.call_verify(lambda *args: status, b"p", b"s", b"m", b"")

    def test_reduced_in_memory_campaign_cannot_report_pass(self):
        with self.assertRaises(CHECKER.FullVerifierError):
            CHECKER.run(lambda *args: 0, [], [])

    def test_complete_campaign_reports_observed_checks(self):
        result = CHECKER.run(self.valid_only_verifier, stateful_fixtures(), stateless_fixtures())
        self.assertEqual(result, {"valid_stateful": 7, "valid_stateless": 2,
                                  "strict_negatives": 60, "native_abi_checks": 28, "result": "PASS"})

    def test_incomplete_native_campaign_cannot_report_pass(self):
        with mock.patch.object(CHECKER, "exercise_native_abi_cases", return_value=0):
            with self.assertRaisesRegex(CHECKER.FullVerifierError, "incomplete"):
                CHECKER.run(self.valid_only_verifier, stateful_fixtures(), stateless_fixtures())

    def test_manifest_controls_are_checked_before_native_load(self):
        original = json.loads((REPO_ROOT / "contrib/shrincs/manifest.json").read_text())
        for field, value in (("production_backend", "other"), ("consensus_enabled", True),
                             ("release_hold", False), ("required_gates", {})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "manifest.json"
                path.write_text(json.dumps(dict(original, **{field: value})))
                args = ["check_full", "--manifest", str(path), "--library", "missing.so",
                        "--stateful-vectors", "missing.json", "--stateless-vectors", "missing2.json"]
                with mock.patch("sys.argv", args), mock.patch.object(CHECKER, "load_verifier") as load:
                    with self.assertRaises(CHECKER.FullVerifierError):
                        CHECKER.main()
                    load.assert_not_called()

    def test_cli_success_emits_only_after_complete_campaign(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = [Path(temp) / f"{mode}.json" for mode in ("stateful", "stateless")]
            for path, mode in zip(paths, ("stateful", "stateless")):
                path.write_text(json.dumps(self.corpus(mode)))
            args = ["check_full", "--library", "fixture.so", "--stateful-vectors", str(paths[0]),
                    "--stateless-vectors", str(paths[1]), "--json"]
            output = io.StringIO()
            with mock.patch("sys.argv", args), contextlib.redirect_stdout(output), \
                    mock.patch.object(CHECKER, "load_verifier", return_value=self.valid_only_verifier):
                self.assertEqual(CHECKER.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["native_abi_checks"], 28)

    def test_native_abi_campaign_cannot_be_skipped_or_mask_errors(self):
        exercise = getattr(CHECKER, "exercise_native_abi_cases", None)
        self.assertTrue(callable(exercise), "combined ABI guards must be exercised in the committed campaign")
        for vectors in (stateful_fixtures(), stateless_fixtures()):
            calls = []

            def verify(*args):
                calls.append(args)
                return int(len(calls) == 1)

            self.assertEqual(exercise(verify, vectors[0]), 14)
            self.assertEqual(len(calls), 14)
            self.assertIsNone(calls[1][0])
            self.assertIsNone(calls[2][2])
            self.assertEqual(calls[10][4:6], (None, 1))
            self.assertEqual(calls[11][6:8], (None, 1))
            self.assertEqual(calls[12][5], 4097)
            self.assertEqual(calls[13][7], 256)
            for invalid in (-1, 1, 2):
                statuses = iter((1, invalid))
                with self.subTest(status=invalid), self.assertRaises(CHECKER.FullVerifierError):
                    exercise(lambda *args: next(statuses), vectors[0])

    def test_bad_corpus_rejected_before_native_library_load(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text(json.dumps(self.corpus("stateless")), encoding="utf-8")
            # The first input is explicitly the stateful slot, not interchangeable.
            args = ["check_full", "--library", "missing.so", "--stateful-vectors", str(path),
                    "--stateless-vectors", str(path), "--json"]
            with mock.patch("sys.argv", args), mock.patch.object(CHECKER, "load_verifier") as load:
                with self.assertRaises(CHECKER.FullVerifierError):
                    CHECKER.main()
                load.assert_not_called()


@unittest.skipUnless(shutil.which("cc"), "C compiler required for the real dispatcher regression")
class FullNativeDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pqbtc-full-dispatch-")
        root = Path(cls.temp.name)
        stub = root / "components.c"
        # Instrument project-owned component boundaries, not cryptographic primitives.
        stub.write_text("""
#include <stddef.h>
#include <stdint.h>
int calls = 0, mode = 0;
#define ARGS const uint8_t *p,size_t n,const uint8_t *s,size_t l,const uint8_t *m,size_t z,const uint8_t *c,size_t q
#define HIT(k) (void)p;(void)n;(void)s;(void)l;(void)m;(void)z;(void)c;(void)q;calls++;mode=k;return 1
int pqbtc_shrincs_stateful_verify(ARGS) { HIT(1); }
int pqbtc_shrincs_stateless_verify(ARGS) { HIT(2); }
""", encoding="utf-8")
        library = root / "dispatch.so"
        subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-shared", "-fPIC",
                        str(REPO_ROOT / "contrib/shrincs-ref/full_verify.c"), str(stub), "-o", str(library)],
                       check=True, capture_output=True, text=True)
        cls.library = ctypes.CDLL(str(library))
        cls.verify = CHECKER.load_verifier(library)
        cls.calls = ctypes.c_int.in_dll(cls.library, "calls")
        cls.mode = ctypes.c_int.in_dll(cls.library, "mode")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_all_lengths_route_only_the_canonical_mode(self):
        key, signature = CHECKER.c_buffer(bytes(49)), CHECKER.c_buffer(bytes(6001))
        for length in range(6001):
            self.calls.value = self.mode.value = 0
            expected = 2 if length == 5776 else (1 if length in range(554, 4619, 16) else 0)
            status = self.verify(key, 48, signature, length, None, 0, None, 0)
            self.assertEqual((status, self.calls.value, self.mode.value),
                             (int(expected != 0), int(expected != 0), expected), length)

    def test_pointer_and_size_guards_precede_both_components(self):
        key, signature = CHECKER.c_buffer(bytes(49)), CHECKER.c_buffer(bytes(6001))
        message, context = CHECKER.c_buffer(bytes(4097)), CHECKER.c_buffer(bytes(256))
        for length in (554, 4618, 5776):
            base = [key, 48, signature, length, None, 0, None, 0]
            cases = []
            for pointer in (0, 2):
                args = base.copy()
                args[pointer] = None
                cases.append(args)
            for size in (0, 47, 49):
                args = base.copy()
                args[1] = size
                cases.append(args)
            for pointer, buffer, size in ((4, None, 1), (6, None, 1),
                                          (4, message, 4097), (6, context, 256)):
                args = base.copy()
                args[pointer:pointer + 2] = [buffer, size]
                cases.append(args)
            for args in cases:
                self.calls.value = 0
                self.assertEqual(self.verify(*args), 0)
                self.assertEqual(self.calls.value, 0)
            self.assertEqual(self.verify(key, 48, signature, length, message, 4096, context, 255), 1)


class ShrincsFullVerifierTests(unittest.TestCase):
    def vector(self, name: str, signature_bytes: int) -> dict[str, str]:
        return {
            "name": name,
            "public_key": "11" * CHECKER.PUBLIC_KEY_BYTES,
            "signature": "22" * signature_bytes,
            "message": "33" * 32,
            "context": "",
        }

    def test_stateful_bounds_are_disjoint_from_stateless(self) -> None:
        self.assertLess(CHECKER.STATEFUL_MAX, CHECKER.STATELESS_BYTES)

    def test_corpus_requires_vectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text(json.dumps({"vectors": []}), encoding="utf-8")
            with self.assertRaisesRegex(CHECKER.FullVerifierError, "must contain vectors"):
                CHECKER.read_corpus(path)

    def test_invalid_hex_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.FullVerifierError, "invalid hex"):
            CHECKER.decode_hex("zz", "signature")

    def test_unpack_rejects_wrong_public_key_size(self) -> None:
        vector = self.vector("bad-key", CHECKER.STATEFUL_MIN)
        vector["public_key"] = "11" * (CHECKER.PUBLIC_KEY_BYTES - 1)
        with self.assertRaisesRegex(CHECKER.FullVerifierError, "public-key length drifted"):
            CHECKER.unpack(vector)

    def test_vector_shapes_cover_both_modes(self) -> None:
        stateful = self.vector("stateful", CHECKER.STATEFUL_MIN)
        stateless = self.vector("stateless", CHECKER.STATELESS_BYTES)
        self.assertEqual(len(CHECKER.unpack(stateful)[1]), CHECKER.STATEFUL_MIN)
        self.assertEqual(len(CHECKER.unpack(stateless)[1]), CHECKER.STATELESS_BYTES)


if __name__ == "__main__":
    unittest.main()
