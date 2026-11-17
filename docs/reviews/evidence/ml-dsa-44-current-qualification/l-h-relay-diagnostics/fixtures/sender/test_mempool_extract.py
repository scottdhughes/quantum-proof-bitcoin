"""Pure adversarial format/ownership tests. No Docker or native executable."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
FROZEN = HERE.parent / "source-clean-7223772e"
sys.path.insert(0, str(FROZEN / "test/functional"))
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness  # noqa: E402

spec = importlib.util.spec_from_file_location("forensic_extract", HERE / "mempool_extract.py")
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)


def compact(n):
    if n < 253:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n) if n <= 65535 else b"\xfe" + struct.pack("<I", n)


def transaction(witness=True):
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(123, 0), b"", 0xfffffffe)]
    tx.vout = [CTxOut(12345, b"\x51")]
    if witness:
        item = CTxInWitness()
        item.scriptWitness.stack = [b"public-signature-fixture", b"public-key-fixture"]
        tx.wit.vtxinwit = [item]
    return tx


def dump(records, *, version=2, footer=b"\0\0", wrong_offset=False):
    body = struct.pack("<Q", len(records))
    for raw in records:
        body += raw + struct.pack("<qq", 1794890000, -17)
    body += footer
    if version == 1:
        return struct.pack("<Q", 1) + body
    key = bytes.fromhex("0123456789abcdef")
    offset = 0 if wrong_offset else 17
    encoded = bytes(v ^ key[(offset + i) % 8] for i, v in enumerate(body))
    return struct.pack("<Q", version) + b"\x08" + key + encoded


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.tx = transaction()
        self.raw = self.tx.serialize_with_witness()
        self.txid = self.tx.txid_hex
        self.sha = hashlib.sha256(self.raw).hexdigest()

    def parse(self, raw, **kwargs):
        return extract.decode_mempool(raw, CTransaction, expected_txid=self.txid,
                                      expected_raw_sha256=self.sha, **kwargs)

    def test_v1_and_v2_extract_identical_witness_bytes(self):
        for version in [1, 2]:
            result = self.parse(dump([self.raw], version=version))
            self.assertEqual(result["selected_raw"], self.raw)
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(result["version"], version)
            self.assertEqual(result["selected_timestamp"], 1794890000)
            self.assertEqual(result["selected_fee_delta"], -17)

    def test_legacy_transaction_without_witness(self):
        tx = transaction(False)
        raw = tx.serialize_without_witness()
        result = extract.decode_mempool(dump([raw]), CTransaction, expected_txid=tx.txid_hex,
                                       expected_raw_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["selected_raw"], raw)

    def test_v2_absolute_offset_is_not_payload_relative(self):
        with self.assertRaises(extract.Refusal):
            self.parse(dump([self.raw], wrong_offset=True))

    def test_every_truncation_of_valid_file_is_rejected(self):
        raw = dump([self.raw])
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(extract.Refusal):
                self.parse(raw[:end])

    def test_exact_eof_rejects_trailing_data(self):
        with self.assertRaisesRegex(extract.Refusal, "TRAILING"):
            self.parse(dump([self.raw], footer=b"\0\0garbage"))

    def test_unknown_version_and_noncanonical_key_prefix(self):
        for raw in [struct.pack("<Q", 3) + b"\0" * 40,
                    struct.pack("<Q", 2) + b"\xfd\x08\0" + b"\0" * 30,
                    struct.pack("<Q", 2) + b"\x09" + b"\0" * 30]:
            with self.assertRaises(extract.Refusal):
                self.parse(raw)

    def test_record_count_bound_precedes_transaction_allocation(self):
        factory = mock.Mock(side_effect=AssertionError("must not allocate transaction"))
        raw = struct.pack("<QQ", 1, extract.MAX_RECORDS + 1)
        with self.assertRaisesRegex(extract.Refusal, "RECORD_COUNT"):
            extract.decode_mempool(raw, factory, expected_txid=self.txid, expected_raw_sha256=self.sha)
        factory.assert_not_called()

    def test_vin_count_bound_precedes_transaction_allocation(self):
        malicious = struct.pack("<I", 2) + compact(extract.MAX_INPUTS + 1) + b"\0" * 100
        factory = mock.Mock(side_effect=AssertionError("must not allocate transaction"))
        with self.assertRaisesRegex(extract.Refusal, "INPUT_COUNT"):
            extract.decode_mempool(dump([malicious], version=1), factory,
                                   expected_txid=self.txid, expected_raw_sha256=self.sha)
        factory.assert_not_called()

    def test_script_length_bound_precedes_transaction_allocation(self):
        malicious = struct.pack("<I", 2) + b"\x01" + b"\0" * 36
        malicious += compact(extract.MAX_SCRIPT_BYTES + 1) + b"\0" * 100
        factory = mock.Mock(side_effect=AssertionError("must not allocate transaction"))
        with self.assertRaisesRegex(extract.Refusal, "SCRIPT"):
            extract.decode_mempool(dump([malicious], version=1), factory,
                                   expected_txid=self.txid, expected_raw_sha256=self.sha)
        factory.assert_not_called()

    def test_output_count_bound_precedes_transaction_allocation(self):
        malicious = struct.pack("<I", 2) + b"\x01" + b"\0" * 36 + b"\0" + b"\xff" * 4
        malicious += compact(extract.MAX_OUTPUTS + 1) + b"\0" * 100
        factory = mock.Mock(side_effect=AssertionError("must not allocate transaction"))
        with self.assertRaisesRegex(extract.Refusal, "OUTPUT_COUNT"):
            extract.decode_mempool(dump([malicious], version=1), factory,
                                   expected_txid=self.txid, expected_raw_sha256=self.sha)
        factory.assert_not_called()

    def test_per_transaction_total_bytes_bound_before_framework(self):
        with mock.patch.object(extract, "MAX_TX_BYTES", len(self.raw) - 1):
            with self.assertRaisesRegex(extract.Refusal, "TX_BYTES"):
                self.parse(dump([self.raw], version=1))

    def test_invalid_witness_flags_and_noncanonical_tx_count(self):
        malformed = self.raw[:5] + b"\x02" + self.raw[6:]
        noncanonical = self.raw[:6] + b"\xfd\x01\0" + self.raw[7:]
        for raw in [malformed, noncanonical]:
            with self.assertRaises(extract.Refusal):
                self.parse(dump([raw], version=1))

    def test_global_witness_item_bound_before_framework(self):
        with mock.patch.object(extract, "MAX_WITNESS_ITEMS", 1):
            with self.assertRaisesRegex(extract.Refusal, "WITNESS"):
                self.parse(dump([self.raw], version=1))

    def test_roundtrip_must_match_entire_consumed_transaction(self):
        class Dishonest(CTransaction):
            def serialize_with_witness(self):
                return super().serialize_with_witness() + b"\0"
        with self.assertRaisesRegex(extract.Refusal, "ROUNDTRIP"):
            extract.decode_mempool(dump([self.raw]), Dishonest,
                                   expected_txid=self.txid, expected_raw_sha256=self.sha)

    def test_duplicate_or_absent_target_and_raw_sha_mismatch(self):
        for raw in [dump([self.raw, self.raw]), dump([])]:
            with self.assertRaises(extract.Refusal):
                self.parse(raw)
        with self.assertRaisesRegex(extract.Refusal, "RAW_SHA"):
            extract.decode_mempool(dump([self.raw]), CTransaction,
                                   expected_txid=self.txid, expected_raw_sha256="0" * 64)

    def test_canonical_bounded_footer_and_exact_order(self):
        keys = [bytes([1]) + b"\0" * 31, bytes([2]) + b"\0" * 31]
        good = compact(2) + b"".join(k + struct.pack("<q", -1) for k in keys)
        good += compact(2) + b"".join(keys)
        result = self.parse(dump([self.raw], footer=good))
        self.assertEqual((result["fee_delta_entries"], result["unbroadcast_entries"]), (2, 2))
        bad = [b"\xfd\0\0\0", compact(extract.MAX_FOOTER_ENTRIES + 1),
               compact(2) + b"".join(k + struct.pack("<q", 0) for k in reversed(keys)) + b"\0",
               b"\0" + compact(2) + keys[0] * 2]
        for footer in bad:
            with self.assertRaises(extract.Refusal):
                self.parse(dump([self.raw], footer=footer))

    def test_file_size_bound(self):
        with mock.patch.object(extract, "MAX_FILE_BYTES", 16):
            with self.assertRaisesRegex(extract.Refusal, "FILE_SIZE"):
                self.parse(dump([self.raw]))


class FileGuardTests(unittest.TestCase):
    def test_decoder_requires_exact_unprivileged_source_owner(self):
        extract.validate_decoder_uid(1001, 1001)
        for uid, euid in [(0, 0), (1000, 1000), (1001, 0), (0, 1001)]:
            with self.assertRaisesRegex(extract.Refusal, "UID1001"):
                extract.validate_decoder_uid(uid, euid)

    def test_output_requires_new_private_source_owner_volume(self):
        good = {"st_mode": 0o40700, "st_uid": 1001, "st_gid": 1000}
        extract.validate_output_directory(SimpleNamespace(**good), True)
        for mutation, empty in [({"st_uid": 0}, True), ({"st_gid": 0}, True),
                                ({"st_mode": 0o40755}, True), ({"st_mode": 0o120700}, True),
                                ({"st_mode": 0o100700}, True), ({}, False)]:
            with self.assertRaisesRegex(extract.Refusal, "OUTPUT_VOLUME"):
                extract.validate_output_directory(SimpleNamespace(**(good | mutation)), empty)

    def test_regular_owned600_file_and_source_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "mempool.dat"
            p.write_bytes(b"public fixture")
            p.chmod(0o600)
            raw, receipt = extract.read_stable_public_file(p, expected_uid=os.getuid())
            self.assertEqual(raw, b"public fixture")
            self.assertEqual(receipt["sha256"], hashlib.sha256(raw).hexdigest())

    def test_symlink_hardlink_wrong_mode_and_wrong_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p = root / "mempool.dat"
            p.write_bytes(b"public fixture")
            p.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(p)
            with self.assertRaises(extract.Refusal):
                extract.read_stable_public_file(alias, expected_uid=os.getuid())
            alias.unlink()
            os.link(p, alias)
            with self.assertRaises(extract.Refusal):
                extract.read_stable_public_file(p, expected_uid=os.getuid())
            alias.unlink()
            p.chmod(0o644)
            with self.assertRaises(extract.Refusal):
                extract.read_stable_public_file(p, expected_uid=os.getuid())
            p.chmod(0o600)
            with self.assertRaises(extract.Refusal):
                extract.read_stable_public_file(p, expected_uid=os.getuid() + 1)

    def test_changed_second_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "mempool.dat"
            p.write_bytes(b"public fixture")
            p.chmod(0o600)
            with mock.patch.object(extract, "hash_open_fd", return_value="0" * 64):
                with self.assertRaisesRegex(extract.Refusal, "SOURCE_CHANGED"):
                    extract.read_stable_public_file(p, expected_uid=os.getuid())

    def test_atomic_path_replacement_while_original_fd_open_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "mempool.dat"
            p.write_bytes(b"public original")
            p.chmod(0o600)
            original = extract.hash_open_fd

            def replace(fd):
                replacement = p.with_name("replacement")
                replacement.write_bytes(b"public original")
                replacement.chmod(0o600)
                os.replace(replacement, p)
                return original(fd)
            with mock.patch.object(extract, "hash_open_fd", side_effect=replace):
                with self.assertRaisesRegex(extract.Refusal, "SOURCE_CHANGED"):
                    extract.read_stable_public_file(p, expected_uid=os.getuid())

    def test_marker_rejects_duplicate_identity_even_with_right_final_value(self):
        correct = ('{"volume_id":"' + extract.SENDER_VOLUME_ID + '","profile_sha256":"' + extract.PROFILE + '"}').encode()
        self.assertEqual(extract.parse_public_marker(correct)["volume_id"], extract.SENDER_VOLUME_ID)
        duplicate = b'{"volume_id":"wrong",' + correct[1:]
        with self.assertRaisesRegex(extract.Refusal, "DUPLICATE"):
            extract.parse_public_marker(duplicate)

    def test_output_is_exclusive0600_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "public.raw"
            extract.write_public_raw(p, b"signed public bytes")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(extract.Refusal):
                extract.write_public_raw(p, b"replacement")
            self.assertEqual(p.read_bytes(), b"signed public bytes")


if __name__ == "__main__":
    unittest.main()
