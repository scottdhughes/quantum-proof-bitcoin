#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Valueless demo PUBLIC wallet companion. No root, passphrase or private key.

RPC observations are not an atomic Coin snapshot. The actual daemon independently
reconstructs/validates all Coins in CheckInputScripts; ordinary admission wins.
"""
import copy
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-production-contract"))
import ipc_v1  # noqa: E402
import protocol_v1 as protocol  # noqa: E402

SPEC = "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126"
SCHEMA = "PQBTC-MLDSA44-PUBLIC-DEMO-WALLET-1"
MAX_FILE = 16 * 1024 * 1024
MAX_ENTRIES = 4096


class WalletError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WalletError(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate public JSON member")
        result[key] = value
    return result


def number(value, maximum=2**31):
    require(type(value) is int and 0 <= value <= maximum, "public counter range")
    return value


def unhex(value, size=None, maximum=1048576):
    require(type(value) is str and len(value) <= 2 * maximum and len(value) % 2 == 0 and
            all(c in "0123456789abcdef" for c in value), "public hex grammar")
    data = bytes.fromhex(value)
    require(size is None or len(data) == size, "public byte length")
    return data


def parse_status(payload):
    require(type(payload) is bytes and len(payload) == 25 and payload[0] in (0, 1), "signer status shape")
    identity = payload[1:17]
    require(any(identity), "zero wallet identity")
    return {"locked": bool(payload[0]), "wallet_id": identity.hex(),
            "next_receive": number(int.from_bytes(payload[17:21], "little")),
            "next_change": number(int.from_bytes(payload[21:25], "little"))}


def validate_manifest(value):
    require(type(value) is dict and set(value) == {"schema", "spec_sha256", "network_binding", "wallet_id",
            "next_receive", "next_change", "entries"}, "public manifest members")
    require(value["schema"] == SCHEMA and value["spec_sha256"] == SPEC and
            value["network_binding"] == protocol.binding("regtest").hex(), "public manifest binding")
    require(any(unhex(value["wallet_id"], 16)), "zero wallet identity")
    floors = [number(value["next_receive"]), number(value["next_change"])]
    require(type(value["entries"]) is list and len(value["entries"]) <= MAX_ENTRIES, "public entry bound")
    paths, programs = set(), set()
    for entry in value["entries"]:
        require(type(entry) is dict and set(entry) == {"branch", "index", "public_key", "program"}, "public entry members")
        branch, index = number(entry["branch"], 1), number(entry["index"], 2**31 - 1)
        key, program = unhex(entry["public_key"], 1312), unhex(entry["program"], 32)
        require(program == protocol.key_commitment("regtest", key), "public key/program mismatch")
        require(index < floors[branch] and (branch, index) not in paths and program not in programs, "public path/high-water mismatch")
        paths.add((branch, index)); programs.add(program)
    return copy.deepcopy(value)


def validate_deployment(info):
    require(type(info) is dict and info.get("chain") == "regtest" and
            type(info.get("blocks")) is int and info["blocks"] >= 1, "demo activation not reached")
    context = info.get("valueless_mldsa44_demo")
    require(type(context) is dict and set(context) == {"scope", "active", "activation_height", "network_binding", "spec_sha256"},
            "explicit node demo context required")
    require(context["scope"] == "VALUELESS_EXPERIMENTAL_REGTEST_ONLY" and context["active"] is True and
            type(context["activation_height"]) is int and context["activation_height"] == 1 and
            context["network_binding"] == protocol.binding("regtest").hex() and context["spec_sha256"] == SPEC,
            "node demo identity/manifest mismatch")


class PublicStore:
    """Single writer, ciphertext-free PUBLIC metadata only; directory must be0700.

    An uncertain write poisons this instance. A retained .tmp needs explicit
    operator inspection/recovery; it is never silently deleted or overwritten.
    """
    def __init__(self, directory):
        self._directory = self._lock = None
        self._record, self._poisoned = None, False
        try:
            self._directory = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self._directory)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "public directory ownership/mode")
            self._lock = os.open("public-wallet.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 0o600, dir_fd=self._directory)
            self._owned(self._lock)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                fd = os.open("public-wallet.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=self._directory)
            except FileNotFoundError:
                return
            try:
                self._owned(fd)
                raw = bytearray()
                while True:
                    part = os.read(fd, min(65536, MAX_FILE + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                    require(len(raw) <= MAX_FILE, "public file bound")
                self._record = validate_manifest(json.loads(raw, object_pairs_hook=strict_object))
            finally:
                os.close(fd)
        except (OSError, ValueError, RecursionError) as error:
            self.close()
            raise WalletError("public wallet open/validation refused") from error

    @staticmethod
    def _owned(fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600, "public file ownership/type/mode")

    def _live(self):
        require(self._directory is not None and not self._poisoned, "public store requires recovery/reopen")

    def _save(self, value):
        self._live()
        value = validate_manifest(value)
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf8")
        require(len(raw) <= MAX_FILE, "public file bound")
        fd = None
        try:
            fd = os.open("public-wallet.tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self._directory)
            self._owned(fd)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                require(count > 0, "public file write failed")
                offset += count
            os.fsync(fd)
            os.close(fd); fd = None
            os.replace("public-wallet.tmp", "public-wallet.json", src_dir_fd=self._directory, dst_dir_fd=self._directory)
            os.fsync(self._directory)
        except (OSError, WalletError) as error:
            self._poisoned = True
            raise WalletError("public durable write uncertain; inspect retained files") from error
        finally:
            if fd is not None:
                os.close(fd)
        self._record = value

    def observe_status(self, payload):
        self._live()
        status = parse_status(payload)
        if self._record is None:
            value = {"schema": SCHEMA, "spec_sha256": SPEC, "network_binding": protocol.binding("regtest").hex(),
                     "wallet_id": status["wallet_id"], "next_receive": status["next_receive"],
                     "next_change": status["next_change"], "entries": []}
        else:
            value = copy.deepcopy(self._record)
            require(value["wallet_id"] == status["wallet_id"], "signer wallet identity mismatch")
            for field in ("next_receive", "next_change"):
                require(status[field] >= value[field], "restore signer with retained public high-water floors")
                value[field] = status[field]
        if value != self._record:
            self._save(value)
        return status

    def accept_address(self, payload, branch):
        self._live()
        require(self._record is not None, "observe signer identity before address")
        number(branch, 1)
        require(type(payload) is bytes and len(payload) == 1349 and payload[0] == branch, "address response shape/branch")
        index = number(int.from_bytes(payload[1:5], "little"), 2**31 - 1)
        key, program = payload[5:1317], payload[1317:]
        require(program == protocol.key_commitment("regtest", key), "address key/program mismatch")
        field = "next_receive" if branch == 0 else "next_change"
        require(index >= self._record[field], "replayed address index")
        value = copy.deepcopy(self._record)
        value[field] = index + 1
        entry = {"branch": branch, "index": index, "public_key": key.hex(), "program": program.hex()}
        value["entries"].append(entry)
        self._save(value)
        return {**entry, "address": protocol.encode_address("regtest", program),
                "script_pubkey": protocol.script_pubkey(program).hex()}

    def import_manifest(self, manifest, status_payload):
        self._live()
        require(self._record is None, "public import requires an empty store")
        value, status = validate_manifest(manifest), parse_status(status_payload)
        require(value["wallet_id"] == status["wallet_id"], "restore wallet identity mismatch")
        for field in ("next_receive", "next_change"):
            require(status[field] >= value[field], "restore signer high-water floor too low")
            value[field] = status[field]
        self._save(value)

    def export(self):
        self._live()
        require(self._record is not None, "public wallet not initialized")
        return copy.deepcopy(self._record)

    def close(self):
        for field in ("_lock", "_directory"):
            value = getattr(self, field, None)
            if value is not None:
                os.close(value); setattr(self, field, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class NativeSigner:
    """Uses the already authenticated native AF_UNIX Client, not a new codec.

    stdin/stdout contain PUBLIC request metadata and signatures only. Operator
    unlock/password descriptors never enter this process or the node RPC.
    """
    def __init__(self, binary, socket, signer_uid):
        require(os.uname().sysname == "Linux" and os.geteuid() != 0, "contained non-root Linux client required")
        require(Path(binary).is_absolute() and type(socket) is str and socket.startswith("/"), "absolute client/socket paths required")
        require(type(signer_uid) is int and 0 < signer_uid < 2**32 - 1 and signer_uid != os.geteuid(), "distinct signer UID required")
        self.binary, self.socket, self.uid = str(binary), socket, signer_uid

    def call(self, kind, body=b""):
        require(type(kind) is int and 2 <= kind <= 5 and type(body) is bytes and len(body) <= 1048576, "client request bound")
        command = [self.binary, "--valueless-demo", self.socket, str(self.uid), SPEC, str(kind)]
        result = subprocess.run(command, input=(body.hex() + "\n").encode("ascii"), capture_output=True, timeout=75,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            close_fds=True)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 2097300, "authenticated signer transport refused")
        try:
            response = json.loads(result.stdout, object_pairs_hook=strict_object)
            require(type(response) is dict and set(response) == {"status", "payload"}, "client response shape")
            status, payload = number(response["status"], 13), unhex(response["payload"])
        except (ValueError, RecursionError) as error:
            raise WalletError("signer response refused") from error
        require(status == 0, "signer refused status " + str(status))
        return payload


def satoshis(value):
    require(type(value) in (int, Decimal), "RPC amount must be exact decimal")
    amount = Decimal(value) * 100000000
    require(amount.is_finite() and amount == amount.to_integral_value() and 0 <= amount <= protocol.MAX_MONEY, "RPC amount range")
    return int(amount)


def attach_witnesses(model, paths, manifest, payload):
    """Byte/key/path joins only. Signature validity is checked by ACTUAL node."""
    require(type(payload) is bytes and 1 <= len(paths) <= 100 and len(payload) == 1 + len(paths) * 3732 and
            payload[0] == len(paths), "signer witness response shape")
    entries = {(entry["branch"], entry["index"]): entry for entry in validate_manifest(manifest)["entries"]}
    witnesses = []
    for i, path in enumerate(paths):
        entry = entries.get(tuple(path)); require(entry is not None, "signer path is absent from public recovery record")
        offset = 1 + i * 3732
        signature, key = payload[offset:offset + 2420], payload[offset + 2420:offset + 3732]
        require(key.hex() == entry["public_key"] and protocol.key_commitment("regtest", key).hex() == entry["program"], "signer key/path substitution")
        witnesses.append((signature, key))
    return protocol.encode_signed(model, witnesses)


class NodeWallet:
    """PUBLIC wallet adapter over ordinary RPC; confirmed owned inputs only.

    Individual RPC reads are observations, not a cs_main-held snapshot. Actual
    CheckInputScripts always reconstructs the authoritative all-input snapshot.
    Recheck Coins after IPC and require testmempoolaccept, then normal broadcast.
    """
    def __init__(self, rpc, signer, store):
        self.rpc, self.signer, self.store = rpc, signer, store

    def _ready(self):
        validate_deployment(self.rpc.getblockchaininfo())

    def status(self):
        self._ready()
        return self.store.observe_status(self.signer.call(5))

    def reserve(self, branch=0):
        number(branch, 1)
        status = self.status()
        require(not status["locked"], "signer locked")
        return self.store.accept_address(self.signer.call(2, bytes([branch])), branch)

    def import_manifest(self, value):
        self._ready()
        self.store.import_manifest(value, self.signer.call(5))

    def _coin(self, txid, index):
        coin = self.rpc.gettxout(txid, index, True)
        require(type(coin) is dict and type(coin.get("confirmations")) is int and coin["confirmations"] >= 1,
                "confirmed Coin missing, spent or unconfirmed")
        require(type(coin.get("coinbase")) is bool and (not coin["coinbase"] or coin["confirmations"] > 100), "immature coinbase")
        amount, script = satoshis(coin["value"]), coin["scriptPubKey"]["hex"]
        unhex(script)
        return amount, script, coin["coinbase"]

    def prepare(self, unsigned_hex):
        self._ready()
        wire = unhex(unsigned_hex)
        decoded = self.rpc.decoderawtransaction(unsigned_hex)
        require(type(decoded["vin"]) is list and 1 <= len(decoded["vin"]) <= 100, "wallet input bound")
        manifest = self.store.export()
        owned = {protocol.script_pubkey(unhex(entry["program"], 32)).hex(): entry for entry in manifest["entries"]}
        model = {"version": decoded["version"], "inputs": [], "outputs": [], "lock_time": decoded["locktime"]}
        if model["version"] >= 2**31:
            model["version"] -= 2**32
        paths, observed = [], []
        for entry in decoded["vin"]:
            require("coinbase" not in entry and not entry.get("txinwitness") and entry["scriptSig"]["hex"] == "", "wallet requires unsigned native inputs")
            txid, index = entry["txid"], entry["vout"]
            amount, script, coinbase = self._coin(txid, index)
            owner = owned.get(script); require(owner is not None, "Coin not in retained public wallet manifest")
            paths.append((owner["branch"], owner["index"]))
            observed.append((amount, script, coinbase))
            model["inputs"].append({"prev_txid": txid, "prev_index": index, "sequence": entry["sequence"],
                                    "amount": amount, "script_pubkey": script})
        for entry in decoded["vout"]:
            model["outputs"].append({"amount": satoshis(entry["value"]), "script_pubkey": entry["scriptPubKey"]["hex"]})
        require(protocol.encode_unsigned(model) == wire, "noncanonical or witnessed unsigned transaction")
        return model, paths, observed

    def sign(self, unsigned_hex):
        require(not self.status()["locked"], "signer locked")
        model, paths, observed = self.prepare(unsigned_hex)
        manifest = self.store.export()
        body = ipc_v1.encode_sign_request(unhex(manifest["wallet_id"], 16), model, paths)
        payload = self.signer.call(3, body)
        wire = attach_witnesses(model, paths, manifest, payload)
        self._ready()
        fresh = [self._coin(entry["prev_txid"], entry["prev_index"]) for entry in model["inputs"]]
        require(fresh == observed, "Coin metadata changed during signer operation")
        admission = self.rpc.testmempoolaccept([wire.hex()])
        require(type(admission) is list and len(admission) == 1 and admission[0].get("allowed") is True,
                "actual node rejected signed transaction")
        txid = hashlib.sha256(hashlib.sha256(protocol.encode_unsigned(model)).digest()).digest()[::-1].hex()
        require(admission[0]["txid"] == txid, "actual node transaction identity mismatch")
        return {"hex": wire.hex(), "txid": txid, "broadcast": False, "scope": "VALUELESS_EXPERIMENTAL_REGTEST_ONLY"}

    def scan(self):
        self._ready()
        manifest = self.store.export()
        owned = {protocol.script_pubkey(unhex(entry["program"], 32)).hex(): entry for entry in manifest["entries"]}
        if not owned:
            return []
        result = self.rpc.scantxoutset("start", [{"desc": "raw(" + script + ")"} for script in owned])
        require(result.get("success") is True, "explicit public wallet scan incomplete")
        found = []
        for item in result["unspents"]:
            entry = owned.get(item["scriptPubKey"]); require(entry is not None, "scan returned an unrequested script")
            found.append({**item, "branch": entry["branch"], "index": entry["index"],
                          "address": protocol.encode_address("regtest", unhex(entry["program"], 32))})
        return found

    def lock(self):
        self._ready()
        require(self.signer.call(4) == b"", "signer LOCK response shape")
        return self.status()
