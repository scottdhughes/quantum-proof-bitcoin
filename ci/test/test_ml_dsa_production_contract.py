#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Executable draft byte-contract tests; no signing, native loads or node wire."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "contrib/ml-dsa-production-contract"
MODEL = HERE / "contract_model.py"
NETWORKS = {
    "main": ("8592a7ad", "2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4"),
    "test": ("a7e29cf7", "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979"),
    "regtest": ("96bd87e9", "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"),
}


def example():
    return {
        "schema": "PQBTC-MLDSA44-DRAFT-0", "network": "test",
        "transaction": {
            "version": 2,
            "inputs": [{"prev_txid": "11" * 32, "prev_index": 3,
                        "sequence": 4294967293, "amount": 1000,
                        "script_pubkey": "0014" + "22" * 20}],
            "outputs": [{"amount": 900, "script_pubkey": "6a"}],
            "lock_time": 9,
        },
        "input_index": 0,
        "public_key": (bytes(range(256)) * 5 + bytes(range(32))).hex(),
    }


def reference_size(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 4294967295:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def reference_envelope(request):
    """Independent grammar transcription; never calls the model encoder."""
    magic, genesis = NETWORKS[request["network"]]
    tx = request["transaction"]
    out = b"PQBTC-MLDSA44-DRAFT0\x00" + bytes.fromhex(magic)
    out += bytes.fromhex(genesis)[::-1] + struct.pack("<iBI", tx["version"], 1, request["input_index"])
    out += bytes.fromhex(request["public_key"]) + reference_size(len(tx["inputs"]))
    for entry in tx["inputs"]:
        script = bytes.fromhex(entry["script_pubkey"])
        out += bytes.fromhex(entry["prev_txid"])[::-1]
        out += struct.pack("<IIQ", entry["prev_index"], entry["sequence"], entry["amount"])
        out += reference_size(len(script)) + script
    out += reference_size(len(tx["outputs"]))
    for entry in tx["outputs"]:
        script = bytes.fromhex(entry["script_pubkey"])
        out += struct.pack("<Q", entry["amount"]) + reference_size(len(script)) + script
    return out + struct.pack("<I", tx["lock_time"])


def reference_hash(tag, data):
    prefix = hashlib.sha256(tag).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


class ProductionContractTests(unittest.TestCase):
    def model(self):
        self.assertTrue(MODEL.is_file(), "draft contract byte model is missing")
        spec = importlib.util.spec_from_file_location("draft_contract", MODEL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_literal_vector_has_independent_reference(self):
        module = self.model()
        vector = json.loads((HERE / "vectors.json").read_text())
        request = vector["request"]
        self.assertEqual(request, example())
        raw = bytes.fromhex(vector["envelope_hex"])
        self.assertEqual(raw, reference_envelope(request))
        self.assertEqual(module.encode_request(request), raw)
        self.assertEqual(module.decode_request(raw), request)
        self.assertEqual(module.signing_message(request).hex(), vector["signing_message_hex"])
        self.assertEqual(reference_hash(b"PQBTC/MLDSA44/draft-0/sighash-all", raw).hex(), vector["signing_message_hex"])
        magic, genesis = NETWORKS["test"]
        data = bytes.fromhex(magic) + bytes.fromhex(genesis)[::-1] + bytes.fromhex(request["public_key"])
        self.assertEqual(reference_hash(b"PQBTC/MLDSA44/draft-0/key", data).hex(), vector["key_commitment_hex"])
        self.assertEqual(module.key_commitment("test", bytes.fromhex(request["public_key"])).hex(), vector["key_commitment_hex"])

    def test_roundtrip_networks_and_compact_size_script_boundaries(self):
        module = self.model()
        for network in NETWORKS:
            for size in (0, 1, 252, 253, 255, 256, 10000):
                request = example()
                request["network"] = network
                request["transaction"]["inputs"][0]["script_pubkey"] = "51" * size
                with self.subTest(network=network, size=size):
                    raw = module.encode_request(request)
                    self.assertEqual(raw, reference_envelope(request))
                    self.assertEqual(module.decode_request(raw), request)

    def test_every_bound_field_changes_the_message(self):
        module = self.model()
        base = example()
        changes = [
            (["network"], "regtest"), (["public_key"], "01" * 1312),
            (["transaction", "version"], 3), (["transaction", "lock_time"], 10),
            (["transaction", "inputs", 0, "prev_txid"], "12" * 32),
            (["transaction", "inputs", 0, "prev_index"], 4),
            (["transaction", "inputs", 0, "sequence"], 1),
            (["transaction", "inputs", 0, "amount"], 1001),
            (["transaction", "inputs", 0, "script_pubkey"], "51"),
            (["transaction", "outputs", 0, "amount"], 899),
            (["transaction", "outputs", 0, "script_pubkey"], "51"),
        ]
        want = module.signing_message(base)
        for path, value in changes:
            changed = copy.deepcopy(base)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertNotEqual(module.signing_message(changed), want)

    def test_selector_and_other_inputs_are_bound(self):
        module = self.model()
        request = example()
        second = copy.deepcopy(request["transaction"]["inputs"][0])
        second["prev_index"] = 4
        request["transaction"]["inputs"].append(second)
        original = module.signing_message(request)
        request["input_index"] = 1
        self.assertNotEqual(module.signing_message(request), original)
        request["input_index"] = 0
        request["transaction"]["inputs"][1]["amount"] += 1
        self.assertNotEqual(module.signing_message(request), original)

    def test_key_commitment_binds_network_and_exact_key(self):
        module = self.model()
        key = bytes.fromhex(example()["public_key"])
        values = {module.key_commitment(network, key) for network in NETWORKS}
        self.assertEqual(len(values), 3)
        self.assertNotEqual(module.key_commitment("test", key), module.key_commitment("test", bytes(1312)))
        for bad in (b"", key[:-1], key + b"\x00", "not bytes"):
            with self.subTest(bad_type=type(bad).__name__), self.assertRaises(module.ContractError):
                module.key_commitment("test", bad)
        with self.assertRaises(module.ContractError):
            module.key_commitment("signet", key)

    def test_all_truncations_and_trailing_binary_reject(self):
        module = self.model()
        raw = module.encode_request(example())
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(module.ContractError):
                module.decode_request(raw[:end])
        for tail in (b"\x00", b"\x00\x00", raw):
            with self.subTest(tail_size=len(tail)), self.assertRaises(module.ContractError):
                module.decode_request(raw + tail)

    def test_prefix_network_genesis_and_sighash_reject(self):
        module = self.model()
        raw = bytearray(module.encode_request(example()))
        prefix = len(b"PQBTC-MLDSA44-DRAFT0\x00")
        for offset in (0, prefix - 1, prefix, prefix + 4, prefix + 4 + 32 + 4):
            changed = raw.copy()
            changed[offset] ^= 0x80
            with self.subTest(offset=offset), self.assertRaises(module.ContractError):
                module.decode_request(bytes(changed))

    def test_nonminimal_and_oversize_counts_reject_before_loops(self):
        module = self.model()
        raw = module.encode_request(example())
        offset = len(b"PQBTC-MLDSA44-DRAFT0\x00") + 4 + 32 + 4 + 1 + 4 + 1312
        for count in (b"\xfd\x01\x00", b"\xfe\x01\x00\x00\x00", b"\xff" + b"\xff" * 8, b"\x65"):
            with self.subTest(count=count.hex()), self.assertRaises(module.ContractError):
                module.decode_request(raw[:offset] + count + raw[offset + 1:])

    def test_unknown_missing_duplicate_json_members_reject(self):
        module = self.model()
        base = example()
        for obj in (dict(base, extra=1), {k: v for k, v in base.items() if k != "schema"}):
            with self.assertRaises(module.ContractError):
                module.encode_request(obj)
        good = json.dumps(base)
        for text in ('{"network":"main",' + good[1:], good + '{}', good.replace('"input_index": 0', '"input_index": NaN')):
            with self.subTest(text_prefix=text[:50]), self.assertRaises(module.ContractError):
                module.read_request(text)
        self.assertEqual(module.read_request(good), base)

    def test_integer_ranges_bool_and_noncanonical_hex_reject(self):
        module = self.model()
        for index in (True, -1, 1, 2**32, 0.0, "0"):
            with self.subTest(index=index), self.assertRaises(module.ContractError):
                module.encode_request(dict(example(), input_index=index))
        for key in ("00" * 1311, "00" * 1313, "AA" * 1312, "00 " * 1312, "gg" * 1312):
            with self.subTest(key_prefix=key[:4]), self.assertRaises(module.ContractError):
                module.encode_request(dict(example(), public_key=key))
        for field, value in (("version", -(2**31)-1), ("version", 2**31), ("version", True), ("lock_time", -1), ("lock_time", 2**32)):
            request = example()
            request["transaction"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(module.ContractError):
                module.encode_request(request)

    def test_empty_duplicate_and_unfunded_requests_reject(self):
        module = self.model()
        bad = []
        for field in ("inputs", "outputs"):
            request = example()
            request["transaction"][field] = []
            bad.append(request)
        request = example()
        request["transaction"]["inputs"] *= 2
        bad.append(request)
        for amount in (-1, True, 1001, 2100000000000001):
            request = example()
            request["transaction"]["outputs"][0]["amount"] = amount
            bad.append(request)
        for request in bad:
            with self.subTest(request=str(request)[:80]), self.assertRaises(module.ContractError):
                module.encode_request(request)

    def test_array_script_money_and_nested_schema_limits(self):
        module = self.model()
        variants = []
        request = example()
        request["transaction"]["outputs"] *= 101
        variants.append(request)
        request = example()
        request["transaction"]["inputs"][0]["script_pubkey"] = "00" * 10001
        variants.append(request)
        request = example()
        request["transaction"]["inputs"][0]["amount"] = 2100000000000001
        variants.append(request)
        request = example()
        request["transaction"]["inputs"][0]["unused"] = 1
        variants.append(request)
        for request in variants:
            with self.assertRaises(module.ContractError):
                module.encode_request(request)

    def test_cli_checks_real_vectors_and_rejects_corrupted_expected_value(self):
        module = self.model()
        result = module.verify_vectors(HERE / "vectors.json")
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["positive_vectors"], 1)
        self.assertGreaterEqual(result["rejected_vectors"], 6)
        completed = subprocess.run([sys.executable, str(MODEL), "--vectors", str(HERE / "vectors.json")], text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), result)
        import tempfile
        vector = json.loads((HERE / "vectors.json").read_text())
        vector["signing_message_hex"] = "00" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(vector))
            failed = subprocess.run([sys.executable, str(MODEL), "--vectors", str(path)], text=True, capture_output=True, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(failed.stdout, "")
        self.assertIn("signing message", failed.stderr)

    def test_signer_boundary_returns_exact_message_and_draft_context(self):
        module = self.model()
        self.assertTrue(hasattr(module, "signer_input"), "explicit message/context boundary is missing")
        message, context = module.signer_input(example())
        vector = json.loads((HERE / "vectors.json").read_text())
        self.assertEqual(message.hex(), vector["signing_message_hex"])
        self.assertEqual(context.hex(), "50514254432f74782d7369676e61747572652f64726166742d30")
        self.assertEqual(context.hex(), vector["context_hex"])
        self.assertEqual(len(message), 32)
        with self.assertRaises(module.ContractError):
            module.encode_request(dict(example(), context="PQBTC/tx-signature/v1"))

    def test_coinbase_and_aggregate_amount_overflow_reject(self):
        module = self.model()
        request = example()
        request["transaction"]["inputs"][0].update(prev_txid="00" * 32, prev_index=2**32 - 1)
        with self.assertRaises(module.ContractError):
            module.encode_request(request)
        request = example()
        request["transaction"]["inputs"][0]["amount"] = 2100000000000000
        second = copy.deepcopy(request["transaction"]["inputs"][0])
        second.update(prev_index=4, amount=1)
        request["transaction"]["inputs"].append(second)
        with self.assertRaises(module.ContractError):
            module.encode_request(request)
        request["transaction"]["inputs"][1]["amount"] = 0
        request["transaction"]["outputs"] = [{"amount": 2100000000000000, "script_pubkey": ""}]
        self.assertEqual(module.decode_request(module.encode_request(request)), request)
        request["transaction"]["outputs"].append({"amount": 1, "script_pubkey": ""})
        with self.assertRaises(module.ContractError):
            module.encode_request(request)

    def test_nonminimal_script_length_rejects(self):
        module = self.model()
        raw = module.encode_request(example())
        offset = len(b"PQBTC-MLDSA44-DRAFT0\x00") + 4 + 32 + 4 + 1 + 4 + 1312 + 1 + 32 + 4 + 4 + 8
        self.assertEqual(raw[offset], 22)
        for length in (b"\xfd\x16\x00", b"\xfe\x16\x00\x00\x00", b"\xfd\x11\x27"):
            with self.subTest(length=length.hex()), self.assertRaises(module.ContractError):
                module.decode_request(raw[:offset] + length + raw[offset + 1:])

    def test_invalid_types_and_nested_integer_boundaries_reject(self):
        module = self.model()
        for text in ("null", "[]", "true", "1", "{", '{"x": Infinity}'):
            with self.subTest(text=text), self.assertRaises(module.ContractError):
                module.read_request(text)
        for raw in (None, "", bytearray(), memoryview(b"")):
            with self.assertRaises(module.ContractError):
                module.decode_request(raw)
        for field in ("prev_index", "sequence"):
            for value in (True, -1, 2**32, 0.0):
                request = example()
                request["transaction"]["inputs"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(module.ContractError):
                    module.encode_request(request)

    def test_negative_corpus_cannot_label_valid_input_as_rejecting(self):
        module = self.model()
        import tempfile
        for field, replacement in (("reject_overrides", [{"network": "main"}]),
                                   ("reject_binary_hex", [module.encode_request(example()).hex()])):
            vector = json.loads((HERE / "vectors.json").read_text())
            vector[field] = replacement
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "false-negative.json"
                path.write_text(json.dumps(vector))
                with self.assertRaisesRegex(module.ContractError, "unexpectedly accepted"):
                    module.verify_vectors(path)


if __name__ == "__main__":
    unittest.main()
