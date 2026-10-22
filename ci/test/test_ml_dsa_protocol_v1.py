#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Public byte-model tests; neither backend integration nor custody qualification."""

import copy
import hashlib
import hmac
import importlib
import json
from pathlib import Path
import struct
import sys
import unittest


MODEL = Path(__file__).resolve().parents[2] / "contrib/ml-dsa-production-contract"
sys.path.insert(0, str(MODEL))
wire = importlib.import_module("protocol_v1")
wallet = importlib.import_module("wallet_v1")
ipc = importlib.import_module("ipc_v1")
sys.path.pop(0)

PK = bytes(range(256)) * 5 + bytes(range(32))
PROGRAM = bytes(range(32))
SCRIPT = "5220" + PROGRAM.hex()
TX = {"version": 2, "inputs": [
    {"prev_txid": "11" * 32, "prev_index": 3, "sequence": 4294967294,
     "amount": 100000, "script_pubkey": SCRIPT}],
    "outputs": [{"amount": 99000, "script_pubkey": SCRIPT}], "lock_time": 7}
# Independently transcribed Bitcoin-derived serialization, not model output.
UNSIGNED = bytes.fromhex("0200000001" + "11" * 32 + "0300000000feffffff01"
                         "b882010000000000225220" + PROGRAM.hex() + "07000000")


def reference_digest(tx, network, index):
    """Independent fixed-fixture transcription of the v1 component-hash contract."""
    # All scripts in this reference fixture are <253 bytes.
    magic = {"main": "8592a7ad", "test": "a7e29cf7", "regtest": "96bd87e9"}[network]
    genesis = {"main": "2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4",
               "test": "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979",
               "regtest": "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"}[network]
    ins, outs = tx["inputs"], tx["outputs"]
    components = [b"".join(bytes.fromhex(i["prev_txid"])[::-1] + struct.pack("<I", i["prev_index"]) for i in ins),
                  b"".join(struct.pack("<Q", i["amount"]) for i in ins),
                  b"".join(bytes([len(bytes.fromhex(i["script_pubkey"]))]) + bytes.fromhex(i["script_pubkey"]) for i in ins),
                  b"".join(struct.pack("<I", i["sequence"]) for i in ins),
                  b"".join(struct.pack("<Q", o["amount"]) + bytes([len(bytes.fromhex(o["script_pubkey"]))]) + bytes.fromhex(o["script_pubkey"]) for o in outs)]
    preimage = (bytes.fromhex(magic) + bytes.fromhex(genesis)[::-1] +
                struct.pack("<iIBII", tx["version"], tx["lock_time"], 1, len(ins), len(outs)) +
                b"".join(hashlib.sha256(c).digest() for c in components) + struct.pack("<I", index))
    tag = hashlib.sha256(b"PQBTC/MLDSA44/sighash/v1").digest()
    return hashlib.sha256(tag * 2 + preimage).digest()


class WireTests(unittest.TestCase):
    def test_literal_public_v1_corpus(self):
        corpus = json.loads((MODEL / "vectors_v1.json").read_text())
        root = bytes.fromhex(corpus["fixture_root_hex"])
        for case in corpus["networks"]:
            network = case["network"]
            self.assertEqual(wire.binding(network).hex(), case["binding_hex"])
            self.assertEqual(wire.encode_address(network, PROGRAM), case["program_address"])
            self.assertEqual(wire.key_commitment(network, PK).hex(), case["key_commitment_hex"])
            self.assertEqual(wire.encode_address(network, bytes.fromhex(case["key_commitment_hex"])), case["key_address"])
            self.assertEqual(wallet.wallet_id(root, network).hex(), case["wallet_id_hex"])
            for child in case["children"]:
                self.assertEqual(wallet.derive_seed(root, network, child["branch"], child["index"]).hex(), child["seed_hex"])

    def test_unsigned_wire_literal_and_decode(self):
        self.assertEqual(wire.encode_unsigned(TX), UNSIGNED)
        self.assertEqual(wire.decode_unsigned(UNSIGNED, [(100000, SCRIPT)]), TX)

    def test_wire_rejects_truncation_trailing_nonminimal_and_scriptsig(self):
        for data in [UNSIGNED[:n] for n in range(len(UNSIGNED))] + [UNSIGNED + b"\x00", UNSIGNED[:4] + b"\xfd\x01\x00" + UNSIGNED[5:], UNSIGNED[:41] + b"\x01\x00" + UNSIGNED[42:]]:
            with self.subTest(size=len(data)), self.assertRaises(wire.ProtocolError):
                wire.decode_unsigned(data, [(100000, SCRIPT)])

    def test_money_types_duplicate_prevouts_and_metadata(self):
        for mutate in [lambda t: t.update(version=True), lambda t: t["outputs"][0].update(amount=100001), lambda t: t["inputs"].append(copy.deepcopy(t["inputs"][0])), lambda t: t["inputs"][0].update(amount=2100000000000001), lambda t: t.update(extra=1)]:
            value = copy.deepcopy(TX)
            mutate(value)
            with self.assertRaises(wire.ProtocolError):
                wire.encode_unsigned(value)
        for metadata in [[], [(True, SCRIPT)], [(100000, SCRIPT), (0, SCRIPT)]]:
            with self.assertRaises(wire.ProtocolError):
                wire.decode_unsigned(UNSIGNED, metadata)

    def test_witness_wire_exact_lengths(self):
        signature = b"\x33" * 2420
        data = wire.encode_signed(TX, [(signature, PK)])
        expected = (UNSIGNED[:4] + b"\x00\x01" + UNSIGNED[4:-4] +
                    b"\x02\xfd\x74\x09" + signature + b"\xfd\x20\x05" + PK + UNSIGNED[-4:])
        self.assertEqual(data, expected)
        for witness in [[], [(signature + b"\x01", PK)], [(signature, PK[:-1])], [(signature, PK, b"")]]:
            with self.assertRaises(wire.ProtocolError):
                wire.encode_signed(TX, witness)

    def test_commitment_domain_and_address_program(self):
        tag = hashlib.sha256(b"PQBTC/MLDSA44/key/v1").digest()
        binding = bytes.fromhex("96bd87e9e215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36")
        self.assertEqual(wire.key_commitment("regtest", PK), hashlib.sha256(tag * 2 + binding + PK).digest())
        self.assertEqual(wire.script_pubkey(PROGRAM), bytes.fromhex(SCRIPT))
        with self.assertRaises(wire.ProtocolError):
            wire.key_commitment("main", PK[:-1])

    def test_sighash_all_fields_network_and_index_bound(self):
        self.assertEqual(wire.signing_message("regtest", TX, 0), reference_digest(TX, "regtest", 0))
        base = wire.signing_message("regtest", TX, 0)
        for path, value in [(('version',), 3), (('lock_time',), 8), (('inputs', 0, 'prev_txid'), '22' * 32), (('inputs', 0, 'prev_index'), 4), (('inputs', 0, 'sequence'), 1), (('inputs', 0, 'amount'), 100001), (('inputs', 0, 'script_pubkey'), '5220' + '22' * 32), (('outputs', 0, 'amount'), 98000), (('outputs', 0, 'script_pubkey'), '5220' + '33' * 32)]:
            changed = copy.deepcopy(TX)
            node = changed
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = value
            self.assertNotEqual(wire.signing_message("regtest", changed, 0), base)
        self.assertNotEqual(wire.signing_message("main", TX, 0), base)
        for index in [-1, 1, True]:
            with self.assertRaises(wire.ProtocolError):
                wire.signing_message("regtest", TX, index)

    def test_bech32m_official_checksum_vectors(self):
        for address in ["A1LQFN3A", "a1lqfn3a", "split1checkupstagehandshakeupstreamerranterredcaperredlc445v"]:
            wire.bech32m_decode(address)
        for address in ["a1lqfn3q", "a1LQFN3A", "A1G7SGD8", " 1xj0phk"]:
            with self.assertRaises(wire.ProtocolError):
                wire.bech32m_decode(address)

    def test_address_network_version_checksum_and_case(self):
        for network in ["main", "test", "regtest"]:
            address = wire.encode_address(network, PROGRAM)
            self.assertEqual(wire.decode_address(network, address), PROGRAM)
            self.assertEqual(wire.decode_address(network, address.upper()), PROGRAM)
            other = "test" if network != "test" else "main"
            with self.assertRaises(wire.ProtocolError):
                wire.decode_address(other, address)
            with self.assertRaises(wire.ProtocolError):
                wire.decode_address(network, address[:-1] + ("q" if address[-1] != "q" else "p"))
        with self.assertRaises(wire.ProtocolError):
            wire.encode_address("main", PROGRAM[:-1])


class WalletTests(unittest.TestCase):
    def test_hkdf_rfc5869_case_one(self):
        self.assertEqual(wallet.hkdf_sha256(b"\x0b" * 22, bytes(range(13)), bytes(range(240, 250)), 42).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        with self.assertRaises(wire.ProtocolError):
            wallet.hkdf_sha256(b"a", b"b", b"c", 8161)

    def test_private_hd_network_branch_index_and_domain(self):
        root = bytes(range(32))
        salt = b"PQBTC/MLDSA44/wallet-root/v1" + bytes.fromhex("96bd87e9e215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36")
        prk = hmac.new(salt, root, hashlib.sha256).digest()
        info = b"PQBTC/MLDSA44/keygen-seed/v1" + bytes.fromhex("8000000080000000")
        self.assertEqual(wallet.derive_seed(root, "regtest", 0, 0), hmac.new(prk, info + b"\x01", hashlib.sha256).digest())
        values = {wallet.derive_seed(root, n, b, i) for n in ["main", "test", "regtest"] for b in [0, 1] for i in [0, 1]}
        self.assertEqual(len(values), 12)
        for args in [(root[:-1], "main", 0, 0), (root, "bad", 0, 0), (root, "main", 2, 0), (root, "main", 0, 2**31), (root, "main", True, 0)]:
            with self.assertRaises(wire.ProtocolError):
                wallet.derive_seed(*args)

    def test_wallet_id_network_and_counter_exhaustion(self):
        root = bytes(range(32))
        binding = bytes.fromhex("96bd87e9e215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36")
        self.assertEqual(wallet.wallet_id(root, "regtest"), hmac.new(root, b"PQBTC/MLDSA44/wallet-id/v1" + binding, hashlib.sha256).digest()[:16])
        self.assertEqual(wallet.reserve_index(2**31 - 1), (2**31 - 1, 2**31))
        for count in [2**31, -1, True]:
            with self.assertRaises(wire.ProtocolError):
                wallet.reserve_index(count)

    def test_record_structural_only_exact_header_and_bounds(self):
        header = wallet.record_header("regtest", bytes(range(16)), 1, b"\x22" * 16, b"\x33" * 12)
        self.assertEqual(len(header), 111)
        self.assertEqual(header[:10], b"PQWMLD1\x00\x01\x00")
        self.assertEqual(header[62:83], bytes.fromhex("010000000000000001000002000800000001000000"))
        record = header + b"\x44" * 40 + b"\x55" * 16
        parsed = wallet.parse_record(record, "regtest")
        self.assertIs(parsed["authenticated"], False)
        self.assertEqual(parsed["generation"], 1)
        self.assertEqual(parsed["aad"], header)
        # A framing parser must NOT claim to reject an invalid authentication tag.
        self.assertIs(wallet.parse_record(record[:-1] + b"\x56", "regtest")["authenticated"], False)
        for altered in [record[:-1], record + b"\x00", b"X" + record[1:], record[:71] + b"\x01" + record[72:]]:
            with self.assertRaises(wire.ProtocolError):
                wallet.parse_record(altered, "regtest")
        with self.assertRaises(wire.ProtocolError):
            wallet.parse_record(record, "main")


class IPCTests(unittest.TestCase):
    def test_frame_literal_and_roundtrip(self):
        frame = ipc.encode_frame(1, bytes(range(16)), b"hello")
        self.assertEqual(frame, b"PQMSIPC1\x01\x00\x01\x00" + bytes(range(16)) + b"\x05\x00\x00\x00hello")
        self.assertEqual(ipc.decode_frame(frame), (1, bytes(range(16)), b"hello"))
        for data in [frame[:i] for i in range(len(frame))] + [frame + b"x", frame[:11] + b"\x01" + frame[12:], frame[:10] + b"\x06" + frame[11:]]:
            with self.assertRaises(wire.ProtocolError):
                ipc.decode_frame(data)
        with self.assertRaises(wire.ProtocolError):
            ipc.encode_frame(3, bytes(range(16)), bytes(1048577))

    def test_hello_hash_and_network_binding(self):
        value = ipc.hello("regtest", b"\x66" * 32)
        self.assertEqual(len(value), 68)
        self.assertEqual(value[-32:], b"\x66" * 32)
        self.assertNotEqual(value, ipc.hello("main", b"\x66" * 32))
        with self.assertRaises(wire.ProtocolError):
            ipc.hello("main", b"short")

    def test_sign_payload_reconstructs_transaction_and_paths(self):
        body = ipc.encode_sign_request(b"\x77" * 16, TX, [(0, 4)])
        self.assertEqual(body[:17], b"\x77" * 16 + bytes([len(UNSIGNED)]))
        self.assertEqual(ipc.decode_sign_request(body), (b"\x77" * 16, TX, [(0, 4)]))
        for data in [body[:i] for i in range(len(body))] + [body + b"x"]:
            with self.assertRaises(wire.ProtocolError):
                ipc.decode_sign_request(data)
        for paths in [[], [(2, 0)], [(0, 2**31)], [(True, 0)]]:
            with self.assertRaises(wire.ProtocolError):
                ipc.encode_sign_request(b"\x77" * 16, TX, paths)

    def test_status_does_not_leak_error_payload(self):
        self.assertEqual(ipc.response_body(5, b""), b"\x05\x00")
        self.assertEqual(ipc.response_body(0, b"ok"), b"\x00\x00ok")
        for status, payload in [(5, b"secret"), (14, b""), (True, b"")]:
            with self.assertRaises(wire.ProtocolError):
                ipc.response_body(status, payload)


if __name__ == "__main__":
    unittest.main()
