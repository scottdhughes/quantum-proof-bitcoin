#!/usr/bin/env python3
"""Strict public mempool decoder. Importing performs no file/runtime operations."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_TX_BYTES = 4_000_000
MAX_INPUTS = 4096
MAX_OUTPUTS = 4096
MAX_SCRIPT_BYTES = 100_000
MAX_WITNESS_ITEMS = 16_384
MAX_WITNESS_ITEM_BYTES = 1_000_000
MAX_FOOTER_ENTRIES = 10_000
TARGET_TXID = "f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94"
TARGET_RAW_SHA256 = "d9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028"
SENDER_VOLUME_ID = "950103c07647484786b2791525bfaf2b"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"


class Refusal(ValueError):
    """Only fixed guard labels reach the CLI receipt."""


def require(value, label):
    if not value:
        raise Refusal(label)


class Reader:
    def __init__(self, data, start=0, limit=None):
        self.data, self.pos = memoryview(data), start
        self.limit = limit

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def skip(self, count):
        require(type(count) is int and count >= 0, "READ_COUNT")
        require(self.limit is None or self.pos + count <= self.limit, "TX_BYTES_BOUND")
        require(count <= self.remaining, "TRUNCATED")
        old = self.pos
        self.pos += count
        return old

    def read(self, count):
        old = self.skip(count)
        return self.data[old:self.pos].tobytes()

    def compact(self, maximum, label):
        prefix = self.read(1)[0]
        if prefix < 253:
            value = prefix
        else:
            size = {253: 2, 254: 4, 255: 8}[prefix]
            value = int.from_bytes(self.read(size), "little")
            require(value >= {253: 253, 254: 65536, 255: 4294967296}[prefix], "NONCANONICAL_COMPACTSIZE")
        require(value <= maximum, label)
        return value


def scan_transaction(reader):
    """Validate every length/count without allocating vectors or script buffers."""
    start = reader.pos
    scan = Reader(reader.data, start, start + MAX_TX_BYTES)
    scan.skip(4)
    inputs = scan.compact(MAX_INPUTS, "INPUT_COUNT_BOUND")
    witness = inputs == 0
    if witness:
        require(scan.read(1) == b"\x01", "WITNESS_FLAG")
        inputs = scan.compact(MAX_INPUTS, "INPUT_COUNT_BOUND")
    require(inputs > 0, "INPUT_COUNT_ZERO")
    for _ in range(inputs):
        scan.skip(36)
        scan.skip(scan.compact(MAX_SCRIPT_BYTES, "SCRIPT_BYTES_BOUND"))
        scan.skip(4)
    outputs = scan.compact(MAX_OUTPUTS, "OUTPUT_COUNT_BOUND")
    require(outputs > 0, "OUTPUT_COUNT_ZERO")
    for _ in range(outputs):
        scan.skip(8)
        scan.skip(scan.compact(MAX_SCRIPT_BYTES, "SCRIPT_BYTES_BOUND"))
    witness_items = 0
    if witness:
        for _ in range(inputs):
            count = scan.compact(MAX_WITNESS_ITEMS - witness_items, "WITNESS_ITEMS_BOUND")
            witness_items += count
            for _ in range(count):
                scan.skip(scan.compact(MAX_WITNESS_ITEM_BYTES, "WITNESS_BYTES_BOUND"))
        require(witness_items > 0, "SUPERFLUOUS_WITNESS")
    scan.skip(4)
    reader.pos = scan.pos
    return start, scan.pos


class ExactFrameworkReader(io.BytesIO):
    def read(self, size=-1):
        require(type(size) is int and 0 <= size <= MAX_TX_BYTES, "FRAMEWORK_READ_BOUND")
        result = super().read(size)
        require(len(result) == size, "FRAMEWORK_TRUNCATED")
        return result


def decode_mempool(raw, transaction_class, *, expected_txid=TARGET_TXID,
                   expected_raw_sha256=TARGET_RAW_SHA256):
    require(type(raw) is bytes and 8 <= len(raw) <= MAX_FILE_BYTES, "FILE_SIZE_BOUND")
    require(type(expected_txid) is str and type(expected_raw_sha256) is str and
            re.fullmatch("[0-9a-f]{64}", expected_txid) and
            re.fullmatch("[0-9a-f]{64}", expected_raw_sha256), "TARGET_BINDING")
    version = int.from_bytes(raw[:8], "little")
    require(version in (1, 2), "MEMPOOL_VERSION")
    if version == 2:
        require(len(raw) >= 17 and raw[8] == 8, "V2_CANONICAL_KEY_PREFIX")
        key = raw[9:17]
        data = bytearray(raw)
        # AutoFile::detail_fread applies Obfuscation at absolute file position.
        for absolute in range(17, len(data)):
            data[absolute] ^= key[absolute % 8]
        reader = Reader(data, 17)
    else:
        reader = Reader(raw, 8)
    count = int.from_bytes(reader.read(8), "little")
    require(count <= MAX_RECORDS, "RECORD_COUNT_BOUND")
    # Valid nonempty vin/vout transactions consume >=60 bytes, plus16 metadata.
    require(count * 76 + 2 <= reader.remaining, "TRUNCATED_RECORDS")
    selected = None
    seen = set()
    for _ in range(count):
        start, end = scan_transaction(reader)
        transaction_raw = reader.data[start:end].tobytes()
        framework_reader = ExactFrameworkReader(transaction_raw)
        try:
            tx = transaction_class()
            tx.deserialize(framework_reader)
            require(framework_reader.tell() == len(transaction_raw) and
                    tx.serialize_with_witness() == transaction_raw, "TX_ROUNDTRIP")
            txid = tx.txid_hex
        except Refusal:
            raise
        except (ValueError, IndexError, TypeError, OverflowError, struct.error, OSError):
            raise Refusal("FRAMEWORK_TX_DECODE") from None
        require(txid not in seen, "DUPLICATE_TRANSACTION_RECORD")
        seen.add(txid)
        timestamp, delta = struct.unpack("<qq", reader.read(16))
        if txid == expected_txid:
            require(selected is None, "TARGET_MATCH_COUNT")
            require(hashlib.sha256(transaction_raw).hexdigest() == expected_raw_sha256, "TARGET_RAW_SHA_MISMATCH")
            selected = {"selected_raw": transaction_raw, "selected_timestamp": timestamp,
                        "selected_fee_delta": delta}
    fee_count = reader.compact(MAX_FOOTER_ENTRIES, "FOOTER_COUNT_BOUND")
    require(fee_count * 40 + 1 <= reader.remaining, "TRUNCATED_FEE_MAP")
    previous = None
    for _ in range(fee_count):
        key = reader.read(32)
        require(previous is None or previous < key, "FEE_MAP_ORDER_OR_DUPLICATE")
        previous = key
        struct.unpack("<q", reader.read(8))
    unbroadcast_count = reader.compact(MAX_FOOTER_ENTRIES, "FOOTER_COUNT_BOUND")
    require(unbroadcast_count * 32 <= reader.remaining, "TRUNCATED_UNBROADCAST")
    previous = None
    for _ in range(unbroadcast_count):
        key = reader.read(32)
        require(previous is None or previous < key, "UNBROADCAST_ORDER_OR_DUPLICATE")
        previous = key
    require(reader.remaining == 0, "TRAILING_BYTES")
    require(selected is not None, "TARGET_MATCH_COUNT")
    return {"version": version, "record_count": count, "fee_delta_entries": fee_count,
            "unbroadcast_entries": unbroadcast_count, "txid": expected_txid,
            "selected_raw_sha256": expected_raw_sha256, **selected}


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_open_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        piece = os.read(fd, 1024 * 1024)
        if not piece:
            return digest.hexdigest()
        total += len(piece)
        require(total <= MAX_FILE_BYTES, "FILE_SIZE_BOUND")
        digest.update(piece)


def read_stable_public_file(path, *, expected_uid=1001, expected_gid=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refusal("SOURCE_OPEN_REFUSED") from None
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid and
                (expected_gid is None or before.st_gid == expected_gid) and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                0 <= before.st_size <= MAX_FILE_BYTES, "SOURCE_FILE_OWNERSHIP_SIZE")
        chunks, size = [], 0
        while size <= before.st_size:
            piece = os.read(fd, min(1024 * 1024, before.st_size + 1 - size))
            if not piece:
                break
            chunks.append(piece)
            size += len(piece)
        raw = b"".join(chunks)
        chunks.clear()
        digest = hashlib.sha256(raw).hexdigest()
        require(size == before.st_size and hash_open_fd(fd) == digest and
                snapshot(before) == snapshot(os.fstat(fd)) == snapshot(os.lstat(path)), "SOURCE_CHANGED")
        return raw, {"bytes": size, "sha256": digest, "uid": before.st_uid,
                     "gid": before.st_gid, "mode": "0600", "same_identity_metadata_and_second_digest": True}
    finally:
        os.close(fd)


def write_public_raw(path, raw):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise Refusal("OUTPUT_EXCLUSIVE_REFUSED") from None
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, "OUTPUT_WRITE_INTERRUPTED")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def parse_public_marker(raw):
    require(type(raw) is bytes and len(raw) <= 1024, "PUBLIC_MARKER_BOUND")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "PUBLIC_MARKER_DUPLICATE")
            value[key] = item
        return value
    try:
        marker = json.loads(raw, object_pairs_hook=pairs)
    except Refusal:
        raise
    except (ValueError, UnicodeError):
        raise Refusal("PUBLIC_MARKER_JSON") from None
    require(marker == {"volume_id": SENDER_VOLUME_ID, "profile_sha256": PROFILE}, "PUBLIC_MARKER_BINDING")
    return marker


def validate_decoder_uid(uid, euid):
    require(uid == euid == 1001, "GENERIC_CONTAINED_UID1001_REQUIRED")


def validate_output_directory(info, empty):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1001 and info.st_gid == 1000 and
            stat.S_IMODE(info.st_mode) == 0o700 and empty, "NEW_OWNED_OUTPUT_VOLUME_REQUIRED")


def mounted_sender_extract():
    require(__debug__ and sys.platform.startswith("linux"), "CONTAINED_LINUX_REQUIRED")
    validate_decoder_uid(os.getuid(), os.geteuid())
    root, output = Path("/sender"), Path("/out")
    for path in [root, root / "node", root / "node/chain", root / "node/chain/mldsa44-test-v1"]:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "SOURCE_PARENT_TYPE")
        require((path == root and info.st_uid == 0) or
                (path != root and info.st_uid == 1001 and info.st_gid == 1000 and
                 stat.S_IMODE(info.st_mode) == 0o700), "SOURCE_PARENT_OWNERSHIP")
    marker_path = root / "identity.json"
    marker_fd = os.open(marker_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(marker_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= 1024, "PUBLIC_MARKER_OWNERSHIP")
        parse_public_marker(os.read(marker_fd, 1025))
    finally:
        os.close(marker_fd)
    info = output.lstat()
    validate_output_directory(info, not any(output.iterdir()))
    raw, receipt = read_stable_public_file(root / "node/chain/mldsa44-test-v1/mempool.dat",
                                           expected_uid=1001, expected_gid=1000)
    framework = Path("/opt/pqbtc-runtime/seed/mldsa-demo-source/test/functional")
    require(framework.is_dir(), "QUALIFIED_IMAGE_FRAMEWORK_REQUIRED")
    sys.path.insert(0, str(framework))
    from test_framework.messages import CTransaction
    parsed = decode_mempool(raw, CTransaction)
    selected = parsed.pop("selected_raw")
    target = output / "pending-signed-transaction.raw"
    write_public_raw(target, selected)
    return {"schema": "PQBTC-L-SENDER-PUBLIC-MEMPOOL-EXTRACTION-1", "result": "PASS",
            "source_file": receipt, "public_volume_marker_verified": True,
            "decoded": parsed, "signed_raw_bytes": len(selected),
            "artifact": str(target), "no_raw_payload_stdout": True,
            "timestamps_are_saved_metadata_fee_delta_is_not_actual_fee": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract-mounted-sender-mempool", action="store_true", required=True)
    parser.parse_args()
    try:
        result = mounted_sender_extract()
    except Refusal as error:
        print(json.dumps({"result": "REFUSED", "guard": str(error)}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"result": "REFUSED", "guard": "UNCLASSIFIED_HELPER_FAILURE"}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
