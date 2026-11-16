#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Serial PUBLIC-test node/wallet worker; operator secrets never enter it."""
import argparse
from decimal import Decimal
import hashlib
import importlib.util
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("public_offline_helpers", HERE / "runtime.py")
offline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offline)
require, integer, directory = offline.require, offline.integer, offline.directory
GENESIS = "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979"
SCOPE = "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
PEER_CHECK_SECONDS = 2
PEER_RETRY_SECONDS = 5
PEER_OPERATION_SECONDS = 2
PEER_RPC_SECONDS = 0.5


def peer_endpoint(value):
    require(type(value) is str and value.isascii() and 3 <= len(value) <= 255,
            "invalid public peer endpoint")
    match = re.fullmatch(r"(\[[0-9a-f:]+\]|[a-z0-9.-]+):([1-9][0-9]{0,4})", value)
    require(match is not None and 1024 <= int(match[2]) <= 65535, "invalid public peer endpoint")
    host = match[1]
    if host.startswith("["):
        require("[" + str(ipaddress.IPv6Address(host[1:-1])) + "]" == host,
                "noncanonical public peer address")
    elif all(c in "0123456789." for c in host):
        require(str(ipaddress.IPv4Address(host)) == host, "noncanonical public peer address")
    else:
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")), "invalid public peer hostname")
    return value


class PeerPolicy:
    """Small public reconnect intent; never contains operator material."""
    def __init__(self, state):
        self.directory = directory(state)
        self.path, self.temporary = self.directory / "peer-policy.json", self.directory / "peer-policy.tmp"
        self.poisoned = False
        canonical = self._read_bytes(self.path) if os.path.lexists(self.path) else None
        self.record = self._decode(canonical) if canonical is not None else {
            "schema": "PQBTC-MLDSA44-PUBLIC-PEER-POLICY-1", "profile_sha256": PROFILE, "network": "test",
            "network_active": True, "endpoints": []}
        if os.path.lexists(self.temporary):
            # PublicRuntime already holds the PublicStore writer lock. An
            # interrupted reconnect intent is evidence, never a new endpoint.
            self.record = self._recover_orphan(canonical)

    @staticmethod
    def validate(value):
        require(type(value) is dict and set(value) == {"schema", "profile_sha256", "network", "network_active", "endpoints"} and
                value["schema"] == "PQBTC-MLDSA44-PUBLIC-PEER-POLICY-1" and value["profile_sha256"] == PROFILE and value["network"] == "test" and
                type(value["network_active"]) is bool and type(value["endpoints"]) is list and len(value["endpoints"]) <= 4,
                "public peer policy schema or bounds refused")
        endpoints = [peer_endpoint(item) for item in value["endpoints"]]
        require(len(set(endpoints)) == len(endpoints), "duplicate public peer policy endpoint")
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))

    def _read_bytes(self, path, *, flush=False):
        fd = os.open(path, (os.O_RDWR if flush else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096,
                    "public peer policy ownership/type/mode/size refused")
            raw = os.read(fd, 4097)
            current = path.lstat()
            require((info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_mode, info.st_nlink) ==
                    (current.st_dev, current.st_ino, current.st_size, current.st_uid, current.st_mode, current.st_nlink) and
                    len(raw) == info.st_size <= 4096, "public peer policy changed while reading")
            if flush:
                os.fsync(fd)
        finally:
            os.close(fd)
        return raw

    def _decode(self, raw):
        def pairs(items):
            value = {}
            for key, item in items:
                require(key not in value, "duplicate public peer policy member")
                value[key] = item
            return value
        return self.validate(json.loads(raw, object_pairs_hook=pairs))

    def _read(self):
        return self._decode(self._read_bytes(self.path))

    @staticmethod
    def _write_new(path, raw):
        require(len(raw) <= 4096, "public peer recovery file bound")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                require(written > 0, "public peer recovery write interrupted")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)

    def _recover_orphan(self, canonical):
        partial = self._read_bytes(self.temporary, flush=True)
        value = self.validate({**self.record, "network_active": False})
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        evidence = self.directory / ("peer-policy.orphan-" + secrets.token_hex(16))
        evidence.mkdir(mode=0o700)
        os.chmod(evidence, 0o700)
        parent = saved = None
        archived = False
        try:
            parent = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            saved = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            os.fsync(parent)
            if canonical is not None:
                self._write_new(evidence / "peer-policy.json", canonical)
            candidate = evidence / "network-off-candidate.json"
            self._write_new(candidate, raw)
            os.fsync(saved)
            require((self._read_bytes(self.path) == canonical if canonical is not None else not os.path.lexists(self.path)) and
                    self._read_bytes(self.temporary) == partial, "public peer policy changed during recovery")
            os.replace(candidate, self.path)
            os.fsync(saved)
            # This barrier MUST precede moving the root uncertainty marker.
            # Before it a restart sees the marker; after it the policy is off.
            os.fsync(parent)
            os.rename(self.temporary, evidence / "peer-policy.tmp")
            archived = True
            os.fsync(saved)
            os.fsync(parent)
        except BaseException:
            self.poisoned = True
            if archived and not os.path.lexists(self.temporary):
                os.rename(evidence / "peer-policy.tmp", self.temporary)
                os.fsync(saved)
                os.fsync(parent)
            raise
        finally:
            if saved is not None:
                os.close(saved)
            if parent is not None:
                os.close(parent)
        return value

    def save(self, *, endpoint=None, network_active=None):
        require(not self.poisoned, "public peer policy requires recovery")
        value = self.validate(self.record)
        if endpoint is not None and peer_endpoint(endpoint) not in value["endpoints"]:
            value["endpoints"].append(endpoint)
        if network_active is not None:
            require(type(network_active) is bool, "network active must be boolean")
            value["network_active"] = network_active
        value = self.validate(value)
        if value == self.record:
            return
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(len(raw) <= 4096, "public peer policy size bound")
        fd = parent = None
        try:
            if os.path.lexists(self.path):
                require(self._read() == self.record, "public peer policy changed outside its owner")
            fd = os.open(self.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                require(written > 0, "public peer policy write interrupted")
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(self.temporary, self.path)
            parent = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            os.fsync(parent)
        except BaseException:
            self.poisoned = True
            raise
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)
        self.record = value


class PublicNode:
    def __init__(self, binary, state, authproxy):
        self.binary, self.directory = str(binary), directory(state)
        self.proxy, self.process, self.output = authproxy, None, None

    def rpc(self, *, timeout=90):
        # This cookie is generated by this task's daemon in its dedicated
        # datadir. No existing user credential or configuration is consulted.
        fd = os.open(self.directory / "mldsa44-test-v1/.cookie", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 512, "scoped node cookie ownership/mode refused")
            auth = os.read(fd, 513).decode("ascii").strip()
            require(auth.startswith("__cookie__:") and len(auth) <= 512 and all(c.isalnum() or c in "_:" for c in auth),
                    "scoped node cookie shape refused")
        finally:
            os.close(fd)
        return self.proxy("http://" + auth + "@127.0.0.1:23832", timeout=timeout)

    def start(self, reindex=False, *, network_active=True):
        require(type(network_active) is bool, "network active must be boolean")
        offline.preflight_ports((23832, 23833))
        self.output = (self.directory / ("process-" + str(time.monotonic_ns()) + ".log")).open("xb")
        args = [self.binary, "-chain=test", "-mldsa44test", "-nosettings", "-server=1",
                "-datadir=" + str(self.directory), "-listen=1", "-bind=0.0.0.0:23833", "-port=23833",
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=23832", "-dnsseed=0", "-fixedseeds=0", "-discover=0",
                "-listenonion=0", "-natpmp=0", "-connect=0", "-acceptnonstdtxn=0", "-dbcache=32",
                "-maxmempool=32", "-par=2", "-debuglogfile=0", "-printtoconsole=0"]
        if not network_active:
            args.append("-networkactive=0")
        if reindex:
            args.append("-reindex-chainstate=1")
        self.process = subprocess.Popen(args, stdout=self.output, stderr=subprocess.STDOUT, close_fds=True)
        deadline = time.monotonic() + 180
        while True:
            require(self.process.poll() is None, "public node exited; inspect its retained process log")
            try:
                info = self.rpc().getblockchaininfo()
                require(self.rpc().getblockhash(0) == GENESIS, "public genesis mismatch")
                require("valueless_mldsa44_test" in info, "dedicated public deployment context missing")
                return
            except OSError:
                pass
            # AuthServiceProxy errors include warmup JSON-RPC errors. Inspect
            # only liveness here; the complete profile is checked by NodeWallet.
            except Exception as error:
                if isinstance(error, ValueError):
                    raise
            require(time.monotonic() < deadline, "public node startup deadline")
            time.sleep(0.05)

    def stop(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                self.rpc().stop()
                self.process.wait(timeout=45)
            require(self.process.returncode == 0, "public node did not stop cleanly")
        finally:
            if self.process.poll() is not None:
                self.process = None
                self.output.close()
                self.output = None


class PublicRuntime:
    def __init__(self, source, build, state, socket, *, bootstrap=False):
        require(sys.platform.startswith("linux") and os.geteuid() == 1001,
                "public native worker requires contained Linux UID1001")
        self.source, self.build, self.state = Path(source), Path(build), directory(state)
        sys.path.insert(0, str(self.source / "contrib/ml-dsa-signer"))
        sys.path.insert(0, str(self.source / "test/functional"))
        import node_wallet
        from test_framework.authproxy import AuthServiceProxy
        self.module, self.protocol = node_wallet, node_wallet.protocol
        self.store = offline.open_public_store(node_wallet, directory(self.state / "public"), network="test")
        self.signer = node_wallet.NativeSigner(self.build / "bin/pqbtc-mldsa-client", socket, 1000, network="test")
        self.node = PublicNode(self.build / "bin/pqbtcd", self.state / "chain", AuthServiceProxy)
        self.wallet, self.running, self.bootstrap = None, False, bootstrap
        self._emitted_manifest = None
        self.peer_policy = PeerPolicy(self.state)
        self._peer_last_check, self._peer_retry_at, self._peer_targets, self._peer_cache = float("-inf"), {}, {}, None

    def _policy(self):
        if self.peer_policy is None:
            self.peer_policy = PeerPolicy(self.state)
            self._peer_last_check, self._peer_retry_at, self._peer_targets, self._peer_cache = float("-inf"), {}, {}, None
        require(not self.peer_policy.poisoned, "public peer policy requires recovery")
        return self.peer_policy

    def _peer_rpc(self, deadline, method, *params):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "public peer operation deadline")
        return getattr(self.node.rpc(timeout=min(PEER_RPC_SECONDS, remaining)), method)(*params)

    def _added_peer(self, endpoint, deadline):
        from test_framework.authproxy import JSONRPCException
        try:
            values = self._peer_rpc(deadline, "getaddednodeinfo", endpoint)
        except JSONRPCException as error:
            if error.error.get("code") == -24:
                return None
            raise
        require(type(values) is list and len(values) == 1 and type(values[0]) is dict and
                values[0].get("addednode") == endpoint and type(values[0].get("connected")) is bool,
                "exact maintained public peer refused")
        addresses = values[0].get("addresses", [])
        require(type(addresses) is list and len(addresses) <= 16, "public peer address bound")
        for item in addresses:
            require(type(item) is dict and set(item) == {"address", "connected"} and
                    item["connected"] in ("inbound", "outbound"), "public peer address metadata refused")
            peer_endpoint(item["address"])
        return values[0]

    def _maintain_peers(self, *, observe=False, force=False):
        from test_framework.authproxy import JSONRPCException
        policy = self._policy().record
        now, deadline = time.monotonic(), time.monotonic() + PEER_OPERATION_SECONDS
        due = force or now - self._peer_last_check >= PEER_CHECK_SECONDS
        if not due and not observe:
            return self._peer_cache
        network = self._peer_rpc(deadline, "getnetworkinfo")
        require(type(network) is dict and type(network.get("networkactive")) is bool, "public network-active metadata refused")
        peers = self._peer_rpc(deadline, "getpeerinfo")
        require(type(peers) is list and len(peers) <= 256, "public peer inventory bound")
        transaction_addresses = set()
        for item in peers:
            require(type(item) is dict and type(item.get("version")) is int and item["version"] >= 0 and
                    type(item.get("relaytxes", False)) is bool and type(item.get("connection_type")) is str,
                    "public peer readiness metadata refused")
            peer_endpoint(item.get("addr"))
            ping = item.get("pingtime")
            finite_ping = (type(ping) is Decimal and ping.is_finite() or
                           type(ping) in (int, float) and math.isfinite(ping))
            if (item["version"] > 0 and item.get("relaytxes") is True and finite_ping and 0 < ping <= 60 and
                    item["connection_type"] in ("manual", "inbound", "outbound-full-relay")):
                transaction_addresses.add(item["addr"])
        attempted, limited, uncertain = [], [], []
        suppressed = None if network["networkactive"] and policy["network_active"] else "NETWORK_INACTIVE"
        if due:
            self._peer_last_check = now
            if not policy["network_active"] and network["networkactive"]:
                require(self._peer_rpc(deadline, "setnetworkactive", False) is False, "public partition suppression failed")
                network["networkactive"] = False
            if suppressed is None:
                for endpoint in policy["endpoints"]:
                    added = self._added_peer(endpoint, deadline)
                    if added is None:
                        try:
                            self._peer_rpc(deadline, "addnode", endpoint, "add")
                        except JSONRPCException as error:
                            if error.error.get("code") != -23:
                                raise
                        added = self._added_peer(endpoint, deadline)
                        require(added is not None, "maintained public peer registration was not proved")
                    self._peer_targets[endpoint] = {endpoint} | {row["address"] for row in added.get("addresses", [])}
                    if not self._peer_targets[endpoint] & transaction_addresses:
                        if now - self._peer_retry_at.get(endpoint, float("-inf")) >= PEER_RETRY_SECONDS:
                            self._peer_retry_at[endpoint] = now
                            attempted.append(endpoint)
                            try:
                                self._peer_rpc(deadline, "addnode", endpoint, "onetry")
                            except JSONRPCException as error:
                                if error.error.get("code") != -344:
                                    raise
                                uncertain.append(endpoint)
                            except OSError:
                                # The exact known peer attempt may already be
                                # underway. Observe it again; never replay a
                                # payment or bypass the per-target retry clock.
                                uncertain.append(endpoint)
                        else:
                            limited.append(endpoint)
        if not network["networkactive"] or not policy["network_active"]:
            transaction_addresses.clear()
        connected = [endpoint for endpoint in policy["endpoints"] if self._peer_targets.get(endpoint, set()) & transaction_addresses]
        self._peer_cache = {"network_active": network["networkactive"], "peers": len(peers),
                            "transaction_peers": len(transaction_addresses), "declared_endpoints": list(policy["endpoints"]),
                            "connected_endpoints": connected, "maintenance": {"checked": due, "attempted_endpoints": attempted,
                            "uncertain_endpoints": uncertain, "suppressed": suppressed, "rate_limited": limited}}
        return self._peer_cache

    def rebroadcast(self, txid):
        require(type(txid) is str and re.fullmatch("[0-9a-f]{64}", txid), "Invalid transaction ID")
        deadline = time.monotonic() + PEER_OPERATION_SECONDS
        entry = self._peer_rpc(deadline, "getmempoolentry", txid)
        require(type(entry) is dict and type(entry.get("vsize")) is int and 1 <= entry["vsize"] <= 1000000,
                "known sender mempool transaction required")
        raw = self._peer_rpc(deadline, "getrawtransaction", txid, False)
        require(type(raw) is str and 2 <= len(raw) <= 2000000 and len(raw) % 2 == 0 and
                re.fullmatch("[0-9a-f]+", raw), "known public transaction bytes refused")
        decoded = self._peer_rpc(deadline, "decoderawtransaction", raw)
        require(type(decoded) is dict and decoded.get("txid") == txid, "known transaction identity changed")
        require(self._peer_rpc(deadline, "sendrawtransaction", raw) == txid, "rebroadcast transaction identity changed")
        return {"txid": txid, "known_in_mempool": True, "rebroadcast": True, "reissued_payment": False,
                "raw_transaction_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest()}

    def manifest(self):
        try:
            return self.store.export()
        except self.module.WalletError as error:
            if str(error) == "public wallet not initialized":
                return None
            raise

    def start(self, reindex=False):
        if not self.running:
            self.node.start(reindex, network_active=self._policy().record["network_active"])
            if self.bootstrap and self.node.rpc().getblockcount() == 0:
                self.node.rpc().generatetodescriptor(1, "raw(5220" + "00" * 32 + ")")
            self.wallet = self.module.NodeWallet(self.node.rpc(), self.signer, self.store, network="test")
            self.running = True
            self._peer_last_check = float("-inf")
            self._maintain_peers(force=True)
        return self.status(observe=False)

    def stop(self):
        self.node.stop()
        self.running, self.wallet = False, None
        return {"stopped": True}

    def close(self):
        try:
            self.stop()
        finally:
            self.store.close()

    def _coins(self):
        manifest = self.manifest()
        if manifest is None or not manifest["entries"]:
            return []
        rpc = self.node.rpc()
        owned = {self.protocol.script_pubkey(bytes.fromhex(item["program"])).hex(): item for item in manifest["entries"]}
        candidates = {(item["txid"], item["vout"]): item for item in self.wallet.scan()}
        for txid in rpc.getrawmempool():
            for output in rpc.getrawtransaction(txid, True)["vout"]:
                if output["scriptPubKey"]["hex"] in owned:
                    candidates[txid, output["n"]] = output
        result = []
        for txid, vout in sorted(candidates):
            coin = rpc.gettxout(txid, vout, True)
            if coin is None:
                continue
            owner = owned.get(coin["scriptPubKey"]["hex"])
            require(owner is not None and type(coin["coinbase"]) is bool, "owned Coin metadata mismatch")
            confirmations = integer(coin["confirmations"])
            result.append({"txid": txid, "vout": vout, "amount_sats": self.module.satoshis(coin["value"]),
                           "confirmations": confirmations, "coinbase": coin["coinbase"],
                           "spendable": confirmations >= 1 and (not coin["coinbase"] or confirmations > 100),
                           "branch": owner["branch"], "index": owner["index"],
                           "address": self.protocol.encode_address("test", bytes.fromhex(owner["program"]))})
        return result

    def status(self, observe=True):
        observed, nodes, coins = None, [], []
        network_active = None
        if self.running:
            if self.peer_policy is not None:
                maintained = self._maintain_peers()
                require(type(maintained) is dict and type(maintained.get("network_active")) is bool,
                        "public network-active status evidence missing")
                network_active = maintained["network_active"]
            rpc = self.node.rpc()
            # Wallet observations must not reuse an HTTP connection that the
            # daemon may have closed while this worker was idle.
            self.wallet.rpc = rpc
            info, inventory = rpc.getblockchaininfo(), rpc.gettxoutsetinfo()
            nodes = [{"name": "public-test", "height": info["blocks"], "tip": info["bestblockhash"],
                      "peers": len(rpc.getpeerinfo()), "network_active": network_active, "utxo_hash": inventory["hash_serialized_3"],
                      "utxo_count": inventory["txouts"], "context": info["valueless_mldsa44_test"]}]
            if observe and info["valueless_mldsa44_test"]["active"]:
                try:
                    observed = self.wallet.status()
                except self.module.WalletError as error:
                    if str(error) != "authenticated signer transport refused":
                        raise
            coins = self._coins()
        manifest = self.manifest()
        addresses = [{"address": self.protocol.encode_address("test", bytes.fromhex(item["program"])),
                      "branch": item["branch"], "index": item["index"]} for item in (manifest or {}).get("entries", [])]
        confirmed = sum(item["amount_sats"] for item in coins if item["confirmations"])
        pending = sum(item["amount_sats"] for item in coins if not item["confirmations"])
        spendable = sum(item["amount_sats"] for item in coins if item["spendable"])
        return {"phase": "running" if self.running else "stopped", "ready": self.running and manifest is not None,
                "scope": SCOPE, "nodes": nodes, "wallet": {"wallet_id": (manifest or {}).get("wallet_id"),
                "locked": observed is None or observed["locked"], "signer_connected": observed is not None,
                "balance_sats": confirmed + pending, "confirmed_sats": confirmed, "pending_sats": pending,
                "spendable_sats": spendable, "immature_sats": confirmed - spendable, "utxos": coins,
                "next_receive": (manifest or {}).get("next_receive", 0), "next_change": (manifest or {}).get("next_change", 0),
                "addresses": addresses}, "backups": [], "activity": []}

    def send(self, params):
        address = self.protocol.decode_address("test", params.get("address"))
        amount, fee = integer(params.get("amount_sats"), 1), integer(params.get("fee_sats", 5000), 1, 20000)
        require(amount + fee <= self.protocol.MAX_MONEY, "amount plus fee exceeds money range")
        require(not self.wallet.status()["locked"], "signer locked")
        selected, total = [], 0
        for coin in self._coins():
            if coin["spendable"]:
                selected.append(coin)
                total += coin["amount_sats"]
                if total >= amount + fee:
                    break
        require(total >= amount + fee and len(selected) <= 25, "insufficient mature coins within the 25-input policy limit")
        outputs = [{"amount": amount, "script_pubkey": self.protocol.script_pubkey(address).hex()}]
        # Every send consumes one change path, even for an exact-value payment.
        # This matches the host's durable pre-issuance floor reservation.
        change = self.wallet.reserve(1)
        if total > amount + fee:
            outputs.append({"amount": total - amount - fee, "script_pubkey": change["script_pubkey"]})
        entries = {(item["branch"], item["index"]): item for item in self.manifest()["entries"]}
        model = {"version": 2, "lock_time": 0, "inputs": [{"prev_txid": coin["txid"], "prev_index": coin["vout"],
                 "sequence": 0xffffffff, "amount": coin["amount_sats"], "script_pubkey": self.protocol.script_pubkey(
                 bytes.fromhex(entries[coin["branch"], coin["index"]]["program"])).hex()} for coin in selected], "outputs": outputs}
        signed = self.wallet.sign(self.protocol.encode_unsigned(model).hex())
        txid = self.node.rpc().sendrawtransaction(signed["hex"])
        require(txid == signed["txid"], "broadcast transaction identity mismatch")
        return {"txid": txid, "broadcast": True, "amount_sats": amount, "fee_sats": fee, "scope": SCOPE}

    def mine(self, params):
        blocks = integer(params.get("blocks", 1), 1, 101)
        address = params.get("address")
        if address is None:
            entries = (self.manifest() or {}).get("entries", [])
            require(entries, "reserve a receive address or specify a test address before mining")
            program = bytes.fromhex(entries[0]["program"])
        else:
            program = self.protocol.decode_address("test", address)
        result = self.node.rpc().generatetodescriptor(blocks, "raw(" + self.protocol.script_pubkey(program).hex() + ")")
        return {"blocks": result, "height": self.node.rpc().getblockcount(), "scope": SCOPE}

    def bootstrap_chain(self):
        require(self.node.rpc().getblockcount() == 0, "Activation bootstrap is available only for an empty dedicated test chain")
        require(self.node.rpc().getblockhash(0) == GENESIS, "Activation bootstrap genesis mismatch")
        result = self.node.rpc().generatetodescriptor(1, "raw(5220" + "00" * 32 + ")")
        return {"blocks": result, "height": 1, "activation_bootstrap": True, "scope": SCOPE}

    def adverse(self):
        """Bounded controls against this owned node; no broadcast or issuance."""
        coins = [coin for coin in self._coins() if coin["spendable"] and coin["amount_sats"] > 5000]
        require(coins, "Adverse controls require a mature owned Coin")
        coin = coins[0]
        owner = next(item for item in self.manifest()["entries"] if (item["branch"], item["index"]) == (coin["branch"], coin["index"]))
        script = self.protocol.script_pubkey(bytes.fromhex(owner["program"])).hex()
        model = {"version": 2, "lock_time": 0, "inputs": [{"prev_txid": coin["txid"], "prev_index": coin["vout"],
                 "sequence": 0xffffffff, "amount": coin["amount_sats"], "script_pubkey": script}],
                 "outputs": [{"amount": coin["amount_sats"] - 5000, "script_pubkey": script}]}
        signed = self.wallet.sign(self.protocol.encode_unsigned(model).hex())
        from test_framework.messages import CTransaction
        tx = CTransaction()
        tx.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
        signature = bytearray(tx.wit.vtxinwit[0].scriptWitness.stack[0])
        signature[0] ^= 1
        tx.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(signature)
        admission = self.node.rpc().testmempoolaccept([tx.serialize().hex()])
        require(len(admission) == 1 and admission[0].get("allowed") is False,
                "TERMINAL: owned node accepted the invalid-signature control")
        wrong = self.module.NativeSigner(self.build / "bin/pqbtc-mldsa-client", self.signer.socket, 1000, network="regtest")
        try:
            wrong.call(5)
        except self.module.WalletError:
            refused = True
        else:
            refused = False
        require(refused, "TERMINAL: public signer accepted a regtest HELLO")
        return {"baseline_accepted": True, "invalid_signature_allowed": False, "wrong_network_refused": True,
                "reject_reason": admission[0].get("reject-reason", ""), "broadcast": False,
                "baseline_source": "NodeWallet.sign.testmempoolaccept"}

    def dispatch(self, action, params):
        allowed = {"start": set(), "stop": set(), "status": set(), "manifest": set(), "receive": set(),
                   "send": {"address", "amount_sats", "fee_sats"}, "mine": {"blocks", "address"},
                   "fund": {"address"}, "lock": set(), "import_manifest": {"manifest"},
                   "peer": {"endpoint"}, "network": {"active"}, "reindex": set(), "adverse": set(), "bootstrap": set(),
                   "clear_bans": set(), "transaction": {"txid", "block_hash"}, "sample": set(),
                   "peer_status": set(), "rebroadcast": {"txid"}}
        require(type(action) is str and type(params) is dict and action in allowed and set(params) <= allowed[action],
                "unsupported public action or parameters")
        if action == "start":
            return self.start()
        if action == "stop":
            return self.stop()
        if action == "manifest":
            return self.manifest()
        if action == "status":
            return self.status()
        require(self.running, "start the public test node first")
        if action == "peer_status":
            return self._maintain_peers(observe=True)
        if action == "rebroadcast":
            return self.rebroadcast(params.get("txid"))
        if self.peer_policy is not None and action not in ("peer", "network", "reindex"):
            self._maintain_peers()
        if action not in ("peer", "network"):
            self.wallet.rpc = self.node.rpc()
        if action == "bootstrap":
            return self.bootstrap_chain()
        if action == "clear_bans":
            self.node.rpc().clearbanned()
            return {"cleared": True}
        if action == "sample":
            value = self.node.rpc().getmempoolinfo()
            return {"mempool_usage_bytes": integer(value["usage"]), "maxmempool_bytes": integer(value["maxmempool"]),
                    "mempool_size": integer(value["size"])}
        if action == "transaction":
            txid, block_hash = params.get("txid"), params.get("block_hash")
            require(type(txid) is str and len(txid) == 64 and all(c in "0123456789abcdef" for c in txid), "Invalid transaction ID")
            require(block_hash is None or type(block_hash) is str and len(block_hash) == 64 and
                    all(c in "0123456789abcdef" for c in block_hash), "Invalid block hash")
            rpc, confirmations, confirmed = self.node.rpc(), 0, False
            if block_hash is not None:
                from test_framework.authproxy import JSONRPCException
                try:
                    header = rpc.getblockheader(block_hash)
                    confirmations = max(0, header.get("confirmations", 0))
                    integer(confirmations)
                    confirmed = confirmations > 0 and txid in rpc.getblock(block_hash, 1)["tx"]
                except JSONRPCException as error:
                    require(error.error.get("code") == -5, "Transaction membership query failed")
            return {"txid": txid, "block_hash": block_hash, "confirmed": confirmed,
                    "confirmations": confirmations, "in_mempool": txid in rpc.getrawmempool()}
        if action == "receive":
            return self.wallet.reserve(0)
        if action == "send":
            return self.send(params)
        if action in ("mine", "fund"):
            return self.mine({**params, **({"blocks": 101} if action == "fund" else {})})
        if action == "lock":
            return self.wallet.lock()
        if action == "import_manifest":
            self.wallet.import_manifest(params["manifest"])
            return self.manifest()
        if action == "peer":
            endpoint = peer_endpoint(params.get("endpoint"))
            self._policy().save(endpoint=endpoint)
            evidence = self._maintain_peers(force=True)
            return {"peer": endpoint, "registered": endpoint in self._peer_targets, "maintenance": evidence["maintenance"]}
        if action == "network":
            require(type(params.get("active")) is bool, "network active must be boolean")
            self._policy().save(network_active=params["active"])
            active = self._peer_rpc(time.monotonic() + PEER_OPERATION_SECONDS, "setnetworkactive", params["active"])
            require(type(active) is bool and active == params["active"], "network activation acknowledgment refused")
            self._peer_last_check = float("-inf")
            if active:
                self._maintain_peers(force=True)
            return {"active": active}
        if action == "reindex":
            self.stop()
            return self.start(reindex=True)
        if action == "adverse":
            return self.adverse()
        raise ValueError("unsupported public action")

    def response(self, request):
        value = offline.Runtime.response(self, request)
        if not value["ok"]:
            return value
        try:
            # The host already retained the last complete successful snapshot.
            # Keep the full response shape while avoiding repeated multi-MB
            # validation, merges and durable journal writes for read-only polls.
            # Canonical JSON distinguishes values such as True and 1; a Python
            # dict comparison could hide a malformed changed manifest.
            snapshot = json.dumps(value["manifest"], sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as error:
            return {"ok": False, "error": str(error)[:1000] or type(error).__name__}
        if snapshot == self._emitted_manifest:
            value["manifest"] = None
        else:
            # A fresh worker starts without a snapshot and resends complete
            # state. Failed requests never acknowledge an unretained change.
            self._emitted_manifest = snapshot
        return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--bootstrap", action="store_true")
    args = parser.parse_args()
    offline.serve(PublicRuntime(args.source, args.build, args.state, args.socket, bootstrap=args.bootstrap))


if __name__ == "__main__":
    main()
