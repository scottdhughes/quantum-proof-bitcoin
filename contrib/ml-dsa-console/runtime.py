#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Serial PUBLIC wallet worker. Native processes run only in the Linux fixture.

This process never opens the signer record or operator descriptors. It uses the
existing authenticated client and public wallet adapter. The host controller
owns the separate UID1000 signer and all encrypted backup operations.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time

GENESIS = "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"
MAX_BLOCKS = 5000
MAX_CHAIN_BYTES = 32 * 1024 * 1024
MAX_LINE = 2 * MAX_CHAIN_BYTES + 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0, maximum=2100000000000000):
    require(type(value) is int and minimum <= value <= maximum, "integer amount/count out of range")
    return value


def directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "public state directory ownership/type/mode refused")
    return path


def double_hash(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def open_public_store(module, path):
    """Preserve interrupted public writes while holding the actual writer lock.

    Partial metadata is diagnostic evidence, never an alternative manifest.
    A private new directory gives each orphan a destination that cannot replace
    an older diagnostic. PublicStore subsequently validates the canonical file
    and reacquires its normal single-writer lock before any wallet operation.
    """
    directory_fd = lock_fd = temporary_fd = diagnostic_fd = None
    try:
        directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(directory_fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "public directory ownership/mode refused")
        lock_fd = os.open("public-wallet.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          0o600, dir_fd=directory_fd)
        module.PublicStore._owned(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            temporary_fd = os.open("public-wallet.tmp", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                   dir_fd=directory_fd)
        except FileNotFoundError:
            temporary_fd = None
        if temporary_fd is not None:
            module.PublicStore._owned(temporary_fd)
            opened = os.fstat(temporary_fd)
            current = os.stat("public-wallet.tmp", dir_fd=directory_fd, follow_symlinks=False)
            require((opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino),
                    "public orphan changed while opening")
            os.fsync(temporary_fd)
            for _ in range(8):
                diagnostic = "public-wallet.orphan-" + secrets.token_hex(16)
                try:
                    os.mkdir(diagnostic, mode=0o700, dir_fd=directory_fd)
                    break
                except FileExistsError:
                    continue
            else:
                raise ValueError("could not reserve a unique public orphan diagnostic")
            diagnostic_fd = os.open(diagnostic, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory_fd)
            # Destination is inside our newly created, empty private directory;
            # no existing uncertain file is ever selected for replacement.
            os.rename("public-wallet.tmp", "public-wallet.tmp", src_dir_fd=directory_fd, dst_dir_fd=diagnostic_fd)
            os.fsync(diagnostic_fd)
            os.fsync(directory_fd)
    except (OSError, ValueError) as error:
        raise module.WalletError("public orphan reconciliation refused; inspect retained public files") from error
    finally:
        for fd in (diagnostic_fd, temporary_fd, lock_fd, directory_fd):
            if fd is not None:
                os.close(fd)
    # A competing opener can win this lock transition. PublicStore then refuses
    # the open; reconciliation never touches another active writer's temp file.
    return module.PublicStore(path)


def preflight_ports(ports):
    """Refuse occupied fixture ports without sending RPC to another process."""
    listeners = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind(("127.0.0.1", port))
                listener.listen(1)
            except OSError as error:
                raise ValueError("fixture port " + str(port) + " is occupied; preserve the existing lab") from error
    finally:
        for listener in listeners:
            listener.close()


class PersistentNode:
    """Persistent datadir adapter retaining DemoNode startup identity checks."""
    def __init__(self, binary, location, port, rpcport, name, demo):
        self.binary, self.directory = str(binary), directory(location)
        self.port, self.rpcport, self.name, self.demo = port, rpcport, name, demo
        self.process = self.output = None
        # A disposable fixture nonce keeps a startup race from authenticating to
        # another lab's RPC endpoint. No user credential is read or accepted.
        self.rpc_nonce = secrets.token_hex(24)

    def rpc(self):
        return self.demo.AuthServiceProxy("http://demo:" + self.rpc_nonce + "@127.0.0.1:" + str(self.rpcport), timeout=60)

    def start(self, extra=()):
        self.demo.DemoNode.start(self, [*extra, "-rpcpassword=" + self.rpc_nonce])

    def stop(self):
        forced = False
        try:
            if self.process is None:
                return
            code = self.process.poll()
            if code is None:
                try:
                    self.rpc().stop()
                    code = self.process.wait(timeout=30)
                except Exception:
                    forced = True
                    self.process.terminate()
                    try:
                        code = self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        code = self.process.wait(timeout=5)
            if code is not None:
                self.process = None
            require(code == 0 and not forced, "owned node shutdown failed or required forced cleanup")
        finally:
            if self.output is not None:
                self.output.close()
                self.output = None


class Runtime:
    def __init__(self, source, build, state, socket, signer_uid, *, signer=None, nodes=None):
        self.source, self.build = Path(source).resolve(), Path(build).resolve()
        self.state = directory(state)
        self.socket, self.signer_uid = str(socket), signer_uid
        sys.path.insert(0, str(self.source / "contrib/ml-dsa-signer"))
        sys.path.insert(0, str(self.source / "test/functional"))
        import node_wallet
        self.module, self.protocol = node_wallet, node_wallet.protocol
        self.store = open_public_store(node_wallet, directory(self.state / "public"))
        self.signer = signer
        self.nodes = list(nodes) if nodes is not None else []
        self.running = nodes is not None
        self.wallet = None
        if self.running:
            self.wallet = node_wallet.NodeWallet(self.nodes[0].rpc(), self.signer, self.store)

    def manifest(self):
        try:
            return self.store.export()
        except self.module.WalletError as error:
            if str(error) == "public wallet not initialized":
                return None
            raise

    def _require_running(self):
        require(self.running and self.nodes and self.wallet is not None, "start the test nodes first")

    def _sync(self, timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            tips = [node.rpc().getbestblockhash() for node in self.nodes]
            if len(set(tips)) == 1:
                return tips[0]
            require(time.monotonic() < deadline, "test node synchronization deadline")
            time.sleep(0.05)

    def start(self, bootstrap=True):
        if self.running:
            return self.status(observe_signer=False)
        require(not self.nodes, "previous owned node cleanup remains incomplete")
        require(sys.platform.startswith("linux") and os.geteuid() == 1001,
                "native console execution requires prepared Linux UID1001")
        spec = importlib.util.spec_from_file_location("console_native_demo", self.source / "test/functional/feature_mldsa44_demo.py")
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        demo.TIMEOUT_FACTOR = 4

        preflight_ports((24843, 24844, 24853, 24854))
        self.nodes = [PersistentNode(self.build / "bin/pqbtcd", self.state / ("node" + str(i)),
            24843 + i, 24853 + i, "node" + str(i), demo) for i in range(2)]
        try:
            for node in self.nodes:
                node.start(["-debuglogfile=0", "-printtoconsole=0"])
            self.nodes[0].rpc().addnode("127.0.0.1:" + str(self.nodes[1].port), "onetry")
            self._sync()
            if bootstrap and self.nodes[0].rpc().getblockcount() == 0:
                self.nodes[0].rpc().generatetodescriptor(101, "raw(51)")
                self._sync()
            self.signer = self.module.NativeSigner(self.build / "bin/pqbtc-mldsa-client", self.socket, self.signer_uid)
            self.wallet = self.module.NodeWallet(self.nodes[0].rpc(), self.signer, self.store)
            self.running = True
            # Recovery must import public metadata before the first observation
            # of signer status. Starting nodes never initializes the store.
            return self.status(observe_signer=False)
        except Exception as startup_error:
            failures = []
            for node in self.nodes:
                try:
                    node.stop()
                except Exception as error:
                    failures.append(str(error))
            self.nodes = [node for node in self.nodes if node.process is not None]
            self.wallet = None
            if failures:
                raise ValueError(str(startup_error) + "; node cleanup: " + "; ".join(failures)) from startup_error
            raise

    def stop(self):
        errors = []
        for node in self.nodes:
            try:
                if hasattr(node, "stop"):
                    node.stop()
            except Exception as error:
                errors.append(str(error))
        self.running, self.wallet = False, None
        self.nodes = [node for node in self.nodes if getattr(node, "process", None) is not None]
        require(not errors, "node shutdown failed: " + "; ".join(errors))
        return self.status(observe_signer=False)

    def close(self):
        try:
            self.stop()
        finally:
            self.store.close()

    def _observe(self):
        self.wallet._ready()
        try:
            payload = self.signer.call(5)
        except self.module.WalletError as error:
            # A connected signer's malformed identity or lower counters are
            # fatal. Only the external transport being absent is disconnected.
            if str(error) == "authenticated signer transport refused":
                return None
            raise
        return self.store.observe_status(payload)

    def _coins(self):
        """Real UTXO scan plus mempool outputs; exclude mempool-spent Coins."""
        rpc, manifest = self.nodes[0].rpc(), self.manifest()
        if manifest is None:
            return []
        owned = {self.protocol.script_pubkey(bytes.fromhex(entry["program"])).hex(): entry for entry in manifest["entries"]}
        if not owned:
            return []
        candidates = {(item["txid"], item["vout"]): item for item in self.wallet.scan()}
        for txid in rpc.getrawmempool():
            decoded = rpc.getrawtransaction(txid, True)
            for output in decoded["vout"]:
                script = output["scriptPubKey"]["hex"]
                if script in owned:
                    candidates[txid, output["n"]] = {"txid": txid, "vout": output["n"], "scriptPubKey": script}
        coins = []
        for (txid, vout), item in sorted(candidates.items()):
            coin = rpc.gettxout(txid, vout, True)
            if coin is None:
                continue
            confirmations, coinbase = coin["confirmations"], coin["coinbase"]
            integer(confirmations)
            require(type(coinbase) is bool, "RPC Coin coinbase flag refused")
            script = coin["scriptPubKey"]["hex"]
            owner = owned.get(script)
            require(owner is not None and script == item["scriptPubKey"], "RPC Coin owned script mismatch")
            amount = self.module.satoshis(coin["value"])
            coins.append({"txid": txid, "vout": vout, "amount_sats": amount,
                "confirmations": confirmations, "coinbase": coinbase,
                "spendable": confirmations >= 1 and (not coinbase or confirmations > 100),
                "address": self.protocol.encode_address("regtest", bytes.fromhex(owner["program"])),
                "branch": owner["branch"], "index": owner["index"]})
        return coins

    def status(self, observe_signer=True):
        manifest, observed = self.manifest(), None
        nodes, coins = [], []
        if self.running:
            for index, node in enumerate(self.nodes):
                rpc = node.rpc()
                inventory = rpc.gettxoutsetinfo()
                nodes.append({"name": getattr(node, "name", "node" + str(index)), "height": rpc.getblockcount(),
                    "peers": len(rpc.getpeerinfo()), "tip": rpc.getbestblockhash(),
                    "utxo_hash": inventory["hash_serialized_3"], "utxo_count": inventory["txouts"]})
            if observe_signer:
                observed = self._observe()
                manifest = self.manifest()
            coins = self._coins()
        addresses = [{"address": self.protocol.encode_address("regtest", bytes.fromhex(entry["program"])),
            "index": entry["index"], "branch": entry["branch"]} for entry in (manifest or {}).get("entries", [])]
        confirmed = sum(coin["amount_sats"] for coin in coins if coin["confirmations"] > 0)
        pending = sum(coin["amount_sats"] for coin in coins if coin["confirmations"] == 0)
        spendable = sum(coin["amount_sats"] for coin in coins if coin["spendable"])
        return {"phase": "running" if self.running else "stopped", "ready": self.running and manifest is not None,
            "nodes": nodes, "wallet": {"wallet_id": (manifest or {}).get("wallet_id"),
                "locked": observed["locked"] if observed else True, "signer_connected": observed is not None,
                "balance_sats": confirmed + pending, "confirmed_sats": confirmed, "pending_sats": pending,
                "immature_sats": confirmed - spendable, "spendable_sats": spendable, "utxos": coins,
                "next_receive": (manifest or {}).get("next_receive", 0), "next_change": (manifest or {}).get("next_change", 0),
                "addresses": addresses}, "backups": [], "activity": []}

    def send(self, params):
        self._require_running()
        address = params.get("address")
        program = self.protocol.decode_address("regtest", address)
        amount = integer(params.get("amount_sats"), 1)
        fee = integer(params.get("fee_sats", 1000), 1, 20000)
        require(amount + fee <= self.protocol.MAX_MONEY, "transaction amount plus fee out of range")
        require(not self.wallet.status()["locked"], "signer locked")
        coins, total = [], 0
        for coin in self._coins():
            if coin["spendable"]:
                coins.append(coin)
                total += coin["amount_sats"]
                if total >= amount + fee:
                    break
        require(total >= amount + fee and len(coins) <= 100, "insufficient mature confirmed test coins")
        # Validation and input selection precede permanent change issuance.
        change = total - amount - fee
        outputs = [{"amount": amount, "script_pubkey": self.protocol.script_pubkey(program).hex()}]
        if change:
            reserved = self.wallet.reserve(1)
            outputs.append({"amount": change, "script_pubkey": reserved["script_pubkey"]})
        manifest = self.manifest()
        owned = {(entry["branch"], entry["index"]): entry for entry in manifest["entries"]}
        model = {"version": 2, "lock_time": 0, "inputs": [{"prev_txid": coin["txid"], "prev_index": coin["vout"],
            "sequence": 0xffffffff, "amount": coin["amount_sats"], "script_pubkey": self.protocol.script_pubkey(
                bytes.fromhex(owned[coin["branch"], coin["index"]]["program"])).hex()} for coin in coins], "outputs": outputs}
        signed = self.wallet.sign(self.protocol.encode_unsigned(model).hex())
        txid = self.nodes[0].rpc().sendrawtransaction(signed["hex"])
        require(txid == signed["txid"], "node broadcast identity mismatch; inspect mempool")
        return {"txid": txid, "broadcast": True, "amount_sats": amount, "fee_sats": fee,
            "scope": "VALUELESS_EXPERIMENTAL_REGTEST_ONLY"}

    def fund(self, params):
        self._require_running()
        amount = integer(params.get("amount_sats", 2000000), 1)
        address = params.get("address")
        # Reject invalid supplied addresses and amounts before address issuance.
        program = self.protocol.decode_address("regtest", address) if address is not None else None
        require(not self.wallet.status()["locked"], "signer locked")
        rpc = self.nodes[0].rpc()
        result = rpc.scantxoutset("start", [{"desc": "raw(51)"}])
        require(result.get("success") is True, "test coin faucet scan incomplete")
        selected = None
        for item in result["unspents"]:
            coin = rpc.gettxout(item["txid"], item["vout"], True)
            if coin is not None and coin["confirmations"] >= 1 and (not coin["coinbase"] or coin["confirmations"] > 100):
                total = self.module.satoshis(coin["value"])
                if total >= amount + 1000 and coin["scriptPubKey"]["hex"] == "51":
                    selected = item, total
                    break
        require(selected is not None, "no mature test coin faucet output; mine more blocks")
        if address is None:
            entry = self.wallet.reserve(0)
            address, program = entry["address"], bytes.fromhex(entry["program"])
        item, total = selected
        model = {"version": 2, "lock_time": 0, "inputs": [{"prev_txid": item["txid"], "prev_index": item["vout"],
            "sequence": 0xffffffff, "amount": total, "script_pubkey": "51"}],
            "outputs": [{"amount": amount, "script_pubkey": self.protocol.script_pubkey(program).hex()}]}
        if total > amount + 1000:
            model["outputs"].append({"amount": total - amount - 1000, "script_pubkey": "51"})
        wire = self.protocol.encode_unsigned(model).hex()
        txid = double_hash(bytes.fromhex(wire))
        block = rpc.generateblock("raw(51)", [wire])["hash"]
        self._sync()
        return {"txid": txid, "address": address, "amount_sats": amount,
            "mined": True, "block": block, "height": rpc.getblockcount()}

    def mine(self, params):
        self._require_running()
        count = integer(params.get("blocks", 1), 1, 101)
        blocks = self.nodes[0].rpc().generatetodescriptor(count, "raw(51)")
        tip = self._sync()
        return {"blocks": blocks, "height": self.nodes[0].rpc().getblockcount(), "tip": tip}

    def export_chain(self):
        self._require_running()
        rpc = self.nodes[0].rpc()
        height = integer(rpc.getblockcount(), 0, MAX_BLOCKS)
        require(rpc.getblockhash(0) == GENESIS, "test chain genesis mismatch")
        tip, blocks, size = rpc.getbestblockhash(), [], 0
        for index in range(1, height + 1):
            raw = rpc.getblock(rpc.getblockhash(index), 0)
            data = self.module.unhex(raw, maximum=MAX_CHAIN_BYTES)
            size += len(data)
            require(size <= MAX_CHAIN_BYTES, "public chain snapshot byte bound")
            blocks.append(raw)
        require(rpc.getbestblockhash() == tip, "chain changed during snapshot; retry")
        return {"genesis": GENESIS, "tip": tip, "blocks": blocks}

    def import_chain(self, params):
        require(set(params) == {"genesis", "tip", "blocks"} and params["genesis"] == GENESIS,
                "public chain snapshot identity/members refused")
        blocks = params["blocks"]
        require(type(blocks) is list and len(blocks) <= MAX_BLOCKS, "public chain snapshot block bound")
        hashes, size, previous = [], 0, GENESIS
        for raw in blocks:
            data = self.module.unhex(raw, maximum=MAX_CHAIN_BYTES)
            require(len(data) >= 80, "public block header truncated")
            size += len(data)
            require(size <= MAX_CHAIN_BYTES, "public chain snapshot byte bound")
            require(data[4:36][::-1].hex() == previous, "public block header chain link mismatch")
            hashes.append(double_hash(data[:80]))
            previous = hashes[-1]
        require(params["tip"] == (hashes[-1] if hashes else GENESIS), "public chain tip/header mismatch")
        if not self.running:
            self.start(bootstrap=False)
        # Fully check every existing prefix before mutating either chain. A
        # longer retained local chain is valid when restoring an older backup.
        for node in self.nodes:
            rpc = node.rpc()
            require(rpc.getblockhash(0) == GENESIS, "test chain genesis mismatch")
            height = rpc.getblockcount()
            for index in range(1, min(height, len(blocks)) + 1):
                require(rpc.getblockhash(index) == hashes[index - 1], "retained chain does not match backup prefix")
        for node in self.nodes:
            rpc = node.rpc()
            for index in range(rpc.getblockcount(), len(blocks)):
                result = rpc.submitblock(blocks[index])
                require(result in (None, "duplicate"), "actual node refused public block replay: " + str(result))
                require(rpc.getblockhash(index + 1) == hashes[index], "actual node block replay identity mismatch")
        tip = self._sync()
        return {"height": self.nodes[0].rpc().getblockcount(), "tip": tip}

    def dispatch(self, action, params):
        require(type(action) is str and type(params) is dict, "request action/params shape refused")
        allowed = {"start": set(), "stop": set(), "status": set(), "receive": set(),
            "fund": {"address", "amount_sats"}, "send": {"address", "amount_sats", "fee_sats"},
            "mine": {"blocks"}, "manifest": set(), "import_manifest": {"manifest"},
            "export_chain": set(), "import_chain": {"genesis", "tip", "blocks"}, "lock": set()}
        require(action in allowed and set(params) <= allowed[action], "unsupported action or parameters")
        if self.running and self.wallet is not None:
            # AuthServiceProxy owns a persistent HTTP connection. An idle node
            # can close it; replace it between actions, never retry a mutation.
            self.wallet.rpc = self.nodes[0].rpc()
        if action == "start":
            return self.start()
        if action == "stop":
            return self.stop()
        if action == "status":
            return self.status()
        if action == "manifest":
            return self.manifest()
        if action == "import_chain":
            return self.import_chain(params)
        self._require_running()
        if action == "receive":
            return self.wallet.reserve(0)
        if action == "send":
            return self.send(params)
        if action == "fund":
            return self.fund(params)
        if action == "mine":
            return self.mine(params)
        if action == "lock":
            return self.wallet.lock()
        if action == "import_manifest":
            self.wallet.import_manifest(params.get("manifest"))
            return self.manifest()
        if action == "export_chain":
            return self.export_chain()
        raise ValueError("unsupported action")

    def response(self, request):
        try:
            require(type(request) is dict and set(request) <= {"action", "params"} and "action" in request,
                    "request object members refused")
            result = self.dispatch(request["action"], request.get("params", {}))
            return {"ok": True, "result": result, "manifest": self.manifest()}
        except Exception as error:
            return {"ok": False, "error": str(error)[:1000] or type(error).__name__}


def serve(runtime):
    def terminate(_signum, _frame):
        # Finish owned cleanup even if another TERM arrives during RPC shutdown.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise SystemExit(0)

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_LINE + 1)
            if not raw:
                break
            if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                print(json.dumps({"ok": False, "error": "request line bound/framing refused"}), flush=True)
                break
            try:
                request = json.loads(raw, object_pairs_hook=runtime.module.strict_object)
                response = runtime.response(request)
            except (ValueError, RecursionError):
                response = {"ok": False, "error": "request JSON refused"}
            print(json.dumps(response, separators=(",", ":")), flush=True)
    finally:
        try:
            runtime.close()
        finally:
            signal.signal(signal.SIGTERM, previous)


def main():
    require(__debug__, "optimized Python is not permitted for console evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--signer-uid", type=int, default=1000)
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and os.geteuid() == 1001,
            "native console execution requires prepared Linux UID1001")
    runtime = Runtime(args.source, args.build, args.state, args.socket, args.signer_uid)
    serve(runtime)


if __name__ == "__main__":
    main()
