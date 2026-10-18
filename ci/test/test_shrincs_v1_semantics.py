"""Behavioral v1 envelope and hash-composition tests (not cryptographic KATs)."""

from __future__ import annotations

import ctypes
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class V1PolicyTests(unittest.TestCase):
    def test_current_recovery_does_not_claim_current_native_signing(self):
        data = json.loads((ROOT / "contrib/shrincs/manifest.json").read_text())
        self.assertEqual(data["component_evidence"]["wotsc"].get("current_keygen_sign_compatible"), False)
        self.assertEqual(data["component_evidence"]["wotsc"].get("current_recovery_case_count"), 8)
        self.assertEqual(data["required_gates"], dict.fromkeys(data["required_gates"], False))
        self.assertEqual(len(data["required_gates"]), 14)

    def test_old_profile_cannot_replace_active_v1_policy(self):
        spec = importlib.util.spec_from_file_location("v1_policy", ROOT / "contrib/shrincs/check_manifest.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        data = policy.load_manifest()
        policy.validate_manifest(data)
        data["candidate_id"] = "pqbtc-shrincs-v0"
        with self.assertRaises(policy.ManifestError):
            policy.validate_manifest(data)


class V1NativeEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only PQBTC code is compiled on the host. Controlled zero-output
        # primitives expose the real parser and SHA preimages, not crypto parity.
        cls.temp = tempfile.TemporaryDirectory(prefix="pqbtc-v1-parser-")
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        (directory / "sha256.h").write_text(
            "#include <stddef.h>\n#include <stdint.h>\n"
            "void shrincs_sha256(uint8_t *, const uint8_t *, size_t);\n")
        (directory / "thash.h").write_text(
            "#include <stddef.h>\n#include <stdint.h>\n"
            "void shrincs_thash(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, size_t);\n")
        (directory / "wots.h").write_text(
            "#include <stdint.h>\n#define SHRINCS_WOTS_ADDR_BYTES 22\n"
            "#define SHRINCS_WOTS_MSG_BYTES 32\n#define SHRINCS_WOTS_SIG_BYTES 514\n"
            "#define SHRINCS_WOTS_OK 0\n"
            "int shrincs_wots_pubkey_from_sig(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *);\n")
        fixture = directory / "fixture.c"
        fixture.write_text(r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
unsigned fixture_work = 0;
uint8_t fixture_outer[73];
void shrincs_sha256(uint8_t *out, const uint8_t *in, size_t length) {
    ++fixture_work;
    if (length == 73) memcpy(fixture_outer, in, 73);
    memset(out, 0, 32);
}
void shrincs_thash(uint8_t *out, const uint8_t *seed, const uint8_t *address,
                  const uint8_t *in, size_t length) {
    (void)seed; (void)address; (void)in; (void)length;
    ++fixture_work; memset(out, 0, 16);
}
int shrincs_wots_pubkey_from_sig(uint8_t *out, const uint8_t *sig, const uint8_t *msg,
                               const uint8_t *seed, uint8_t *address) {
    (void)sig; (void)msg; (void)seed; (void)address;
    ++fixture_work; memset(out, 0, 16); return 0;
}
''' + '\n#include "' + str(ROOT / "contrib/shrincs-ref/stateful_verify.c") + '"\n' + r'''
int fixture_digest(void) {
    uint8_t out[32], randomizer[16], seed[16], root[16], leaf[9] = {254,0,0,0,0,0,0,0,1};
    memset(randomizer, 0x42, 16); memset(seed, 0x24, 16); memset(root, 0, 16);
    return compute_stateful_message_digest(out, randomizer, seed, root, root,
                                          leaf, NULL, 0, NULL, 0);
}
''')
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("C compiler required for native parser contract tests")
        library = directory / "fixture.so"
        subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                        "-I" + str(directory), str(fixture),
                        str(ROOT / "contrib/shrincs-ref/stateless_verify.c"),
                        str(ROOT / "contrib/shrincs-ref/full_verify.c"), "-o", str(library)],
                       check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.verify = cls.lib.pqbtc_shrincs_verify
        cls.verify.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * 4
        cls.verify.restype = ctypes.c_int

    def call(self, signature, message=b"", context=b"", public_key=bytes(48)):
        self.work.value = 0
        return self.verify(public_key, len(public_key), signature, len(signature),
                           message, len(message), context, len(context))

    def setUp(self):
        self.work = ctypes.c_uint.in_dll(self.lib, "fixture_work")

    @staticmethod
    def stateful(height=254, index=1, width=1, path_bytes=16):
        return bytes([height]) + b"B" * 16 + index.to_bytes(width, "big") + bytes(514 + path_bytes)

    def test_canonical_depth_and_index_width_boundaries(self):
        rows = ((254, 1, 1, 16, 548), (247, 255, 1, 128, 660),
                (246, 511, 2, 144, 677), (192, (1 << 63) - 1, 8, 1008, 1547),
                (191, (1 << 64) - 1, 8, 1024, 1563),
                (190, (1 << 64) - 1, 8, 1040, 1579),
                (0, (1 << 64) - 1, 8, 4080, 4619))
        for height, index, width, path, length in rows:
            with self.subTest(height=height):
                signature = self.stateful(height, index, width, path)
                self.assertEqual(len(signature), length)
                self.assertEqual(self.call(signature), 1)
                self.assertGreater(self.work.value, 0)

    def test_noncanonical_headers_reject_before_crypto(self):
        signatures = (b"", b"\xff", self.stateful()[:-1], self.stateful() + b"\0",
                      self.stateful(index=2), self.stateful(width=2),
                      self.stateful(height=255), bytes(554), bytes(5776),
                      b"\xff" + bytes(5777))
        for signature in signatures:
            with self.subTest(length=len(signature), first=signature[:1]):
                self.assertEqual(self.call(signature), 0)
                self.assertEqual(self.work.value, 0)

    def test_stateless_requires_indicator_and_exact_length(self):
        self.assertEqual(self.call(b"\xff" + bytes(5776)), 1)
        self.assertGreater(self.work.value, 0)
        self.assertEqual(self.call(bytes(5777)), 0)
        self.assertEqual(self.work.value, 0)

    def test_stateful_hash_appends_leaf_after_inner_digest(self):
        self.assertEqual(self.lib.fixture_digest(), 1)
        actual = bytes((ctypes.c_uint8 * 73).in_dll(self.lib, "fixture_outer"))
        # Literal ordered preimage, independent of any production helper.
        self.assertEqual(actual, b"B" * 16 + b"$" * 16 + bytes(32) +
                         bytes.fromhex("fe0000000000000001"))

    def test_input_limits_fail_before_crypto(self):
        valid = self.stateful()
        for key, message, context in ((bytes(47), b"", b""), (bytes(49), b"", b""),
                                      (bytes(48), bytes(4097), b""),
                                      (bytes(48), b"", bytes(256))):
            with self.subTest(key=len(key), message=len(message), context=len(context)):
                self.assertEqual(self.call(valid, message, context, key), 0)
                self.assertEqual(self.work.value, 0)
        self.assertEqual(self.call(valid, bytes(4096), bytes(255)), 1)


if __name__ == "__main__":
    unittest.main()
