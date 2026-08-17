#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Persistent, zero-value PQBTC-SHRINCS-v0 regtest labnet controller.

This tool intentionally targets only the repository's private regtest profile.
It builds and operates two local nodes, mines spendable regtest coins, and
funds/signs/broadcasts/mines genuine witness-v2 SHRINCS transactions.

The stateful signer burns a state counter in a FULL-synchronous SQLite
transaction *before* computing or returning a signature. A crash after the
reservation therefore loses a leaf rather than reusing it.
"""

from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from types import ModuleType
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_FRAMEWORK_ROOT = REPO_ROOT / "test" / "functional"
TX_MODEL_PATH = REPO_ROOT / "contrib" / "shrincs-tx" / "tx_model.py"
UPSTREAM_REPOSITORY = "https://github.com/SHRINCS/shrincs-bip.git"
UPSTREAM_COMMIT = "acc6bda51dc3b94848d118967247ad0f3cd7a80e"
SIGNER_PROFILE = "pqbtc-shrincs-v0-unbalanced-depth-4"
SIGNER_STRUCTURE = bytes([0, 4])
SIGNER_CONTEXT = b"PQBTC/SHRINCS/TXSIG/v0"
WALLET_NAME = "shrincs-labnet"
COIN = 100_000_000
DEFAULT_FUNDING = Decimal("0.01000000")
DEFAULT_FEE_SATS = 20_000
MARKER_NAME = ".pqbtc-shrincs-labnet"


class LabnetError(RuntimeError):
    """Raised when a labnet operation cannot be completed safely."""


class CommandError(LabnetError):
    """Raised when an external command fails."""

    def __init__(self, command: Sequence[str], returncode: int, stdout: str, stderr: str):
        rendered = " ".join(command)
        message = f"command failed ({returncode}): {rendered}"
        if stderr.strip():
            message += f"\n{stderr.strip()}"
        elif stdout.strip():
            message += f"\n{stdout.strip()}"
        super().__init__(message)
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"cannot encode {type(value).__name__}")


def emit(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=json_default))


def run_command(
    command: Sequence[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    argv = [str(part) for part in command]
    result = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=capture,
        check=False,
    )
    if check and result.returncode != 0:
        raise CommandError(argv, result.returncode, result.stdout or "", result.stderr or "")
    return result


def parse_cli_output(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped, parse_float=Decimal)
    except json.JSONDecodeError:
        return stripped


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise LabnetError(f"cannot load Python module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def git_head(path: Path) -> str:
    return run_command(["git", "-C", path, "rev-parse", "HEAD"]).stdout.strip()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sats(value: Decimal | str | int) -> int:
    decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
    integral = decimal_value * COIN
    if integral != integral.to_integral_value():
        raise LabnetError(f"amount has sub-satoshi precision: {value}")
    return int(integral)


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


@dataclass(frozen=True)
class Layout:
    state_dir: Path
    build_dir: Path

    @property
    def marker(self) -> Path:
        return self.state_dir / MARKER_NAME

    @property
    def upstream_dir(self) -> Path:
        override = os.environ.get("SHRINCS_BIP_DIR")
        return Path(override).expanduser().resolve() if override else self.state_dir / "upstream" / "shrincs-bip"

    @property
    def signer_db(self) -> Path:
        return self.state_dir / "signer" / "state.sqlite3"

    @property
    def node0(self) -> "NodeLayout":
        return NodeLayout(self, index=0, p2p_port=19444, rpc_port=19443)

    @property
    def node1(self) -> "NodeLayout":
        return NodeLayout(self, index=1, p2p_port=19445, rpc_port=19453)

    @property
    def daemon(self) -> Path:
        return self.build_dir / "bin" / "pqbtcd"

    @property
    def cli(self) -> Path:
        return self.build_dir / "bin" / "pqbtc-cli"

    @property
    def unit_tests(self) -> Path:
        return self.build_dir / "bin" / "test_pqbtc"


@dataclass(frozen=True)
class NodeLayout:
    layout: Layout
    index: int
    p2p_port: int
    rpc_port: int

    @property
    def datadir(self) -> Path:
        return self.layout.state_dir / f"node{self.index}"

    @property
    def config(self) -> Path:
        return self.datadir / "pqbtc.conf"

    @property
    def wallet(self) -> str:
        return WALLET_NAME

    def config_text(self) -> str:
        return "\n".join(
            [
                "regtest=1",
                "server=1",
                "listen=1",
                "discover=0",
                "dnsseed=0",
                "fixedseeds=0",
                "listenonion=0",
                "upnp=0",
                "natpmp=0",
                "txindex=1",
                "acceptnonstdtxn=1",
                "fallbackfee=0.00010000",
                "persistmempool=1",
                "printtoconsole=0",
                "",
                "[regtest]",
                f"port={self.p2p_port}",
                f"rpcport={self.rpc_port}",
                "rpcbind=127.0.0.1",
                "rpcallowip=127.0.0.1",
                "",
            ]
        )


class Node:
    def __init__(self, node_layout: NodeLayout):
        self.paths = node_layout

    def cli(
        self,
        *arguments: str | int | Decimal,
        wallet: bool = False,
        check: bool = True,
    ) -> Any:
        command: list[str | Path] = [
            self.paths.layout.cli,
            "-regtest",
            f"-datadir={self.paths.datadir}",
        ]
        if wallet:
            command.append(f"-rpcwallet={self.paths.wallet}")
        command.extend(str(argument) for argument in arguments)
        result = run_command(command, check=check)
        if not check:
            return result
        return parse_cli_output(result.stdout)

    def is_running(self) -> bool:
        if not self.paths.layout.cli.exists() or not self.paths.datadir.exists():
            return False
        result = self.cli("getblockchaininfo", check=False)
        return isinstance(result, subprocess.CompletedProcess) and result.returncode == 0

    def wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            result = self.cli("getblockchaininfo", check=False)
            if isinstance(result, subprocess.CompletedProcess):
                if result.returncode == 0:
                    return
                last_error = result.stderr.strip()
            time.sleep(0.25)
        raise LabnetError(f"node {self.paths.index} did not become RPC-ready: {last_error}")

    def ensure_wallet(self) -> None:
        loaded = self.cli("listwallets")
        if isinstance(loaded, list) and self.paths.wallet in loaded:
            return
        wallet_dir = self.cli("listwalletdir")
        names = {
            entry.get("name")
            for entry in (wallet_dir or {}).get("wallets", [])
            if isinstance(entry, dict)
        }
        if self.paths.wallet in names:
            self.cli("loadwallet", self.paths.wallet)
        else:
            self.cli("createwallet", self.paths.wallet)

    def height(self) -> int:
        return int(self.cli("getblockcount"))

    def balance(self) -> Decimal:
        value = self.cli("getbalance", wallet=True)
        return value if isinstance(value, Decimal) else Decimal(str(value))


class SignerStore:
    """Crash-safe state allocator and labnet secret-key store."""

    SCHEMA_VERSION = "1"

    def __init__(self, path: Path):
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        finally:
            os.umask(old_umask)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        with contextlib.suppress(FileNotFoundError):
            os.chmod(self.path, 0o600)
        return connection

    @staticmethod
    def stateful_capacity(structure: bytes) -> int:
        if len(structure) != 2:
            raise LabnetError("SHRINCS structure must be two bytes")
        shape, depth = structure
        if depth == 0:
            return 0
        if shape == 0:
            return depth + 1
        if shape == 1:
            return 1 << depth
        raise LabnetError(f"unsupported FXMSS shape {shape}")

    def exists(self) -> bool:
        return self.path.is_file()

    def create(self, secret_key: bytes, public_key: bytes, structure: bytes) -> None:
        if self.exists():
            raise LabnetError(f"signer database already exists: {self.path}")
        if len(secret_key) != 82 or len(public_key) != 48:
            raise LabnetError("unexpected pinned-profile key length")
        capacity = self.stateful_capacity(structure)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE reservations (
                    state_counter INTEGER PRIMARY KEY,
                    message_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('reserved', 'signed', 'broadcast', 'failed')),
                    signature_sha256 TEXT,
                    txid TEXT,
                    error TEXT,
                    reserved_at TEXT NOT NULL,
                    finalized_at TEXT
                );
                CREATE TABLE stateless_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_sha256 TEXT NOT NULL,
                    signature_sha256 TEXT NOT NULL,
                    txid TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            values = {
                "schema_version": self.SCHEMA_VERSION,
                "profile": SIGNER_PROFILE,
                "secret_key_hex": secret_key.hex(),
                "public_key_hex": public_key.hex(),
                "structure_hex": structure.hex(),
                "next_state": "0",
                "capacity": str(capacity),
                "created_at": utc_now(),
                "upstream_commit": UPSTREAM_COMMIT,
            }
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES(?, ?)", values.items()
            )
            connection.execute("COMMIT")
            connection.execute("PRAGMA wal_checkpoint(FULL)")
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

    def _metadata(self, connection: sqlite3.Connection) -> dict[str, str]:
        rows = connection.execute("SELECT key, value FROM metadata").fetchall()
        data = {str(row["key"]): str(row["value"]) for row in rows}
        if data.get("schema_version") != self.SCHEMA_VERSION:
            raise LabnetError("unsupported signer database schema")
        return data

    def metadata(self) -> dict[str, str]:
        if not self.exists():
            raise LabnetError("signer database is not initialized")
        connection = self._connect()
        try:
            return self._metadata(connection)
        finally:
            connection.close()

    def public_key(self) -> bytes:
        return bytes.fromhex(self.metadata()["public_key_hex"])

    def status(self) -> dict[str, Any]:
        if not self.exists():
            raise LabnetError("signer database is not initialized")
        connection = self._connect()
        try:
            metadata = self._metadata(connection)
            counts = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM reservations GROUP BY status"
                )
            }
            stateless_count = int(
                connection.execute("SELECT COUNT(*) FROM stateless_events").fetchone()[0]
            )
            return {
                "profile": metadata["profile"],
                "upstream_commit": metadata["upstream_commit"],
                "public_key": metadata["public_key_hex"],
                "output_commitment": None,
                "next_state": int(metadata["next_state"]),
                "stateful_capacity": int(metadata["capacity"]),
                "stateful_remaining": max(
                    0, int(metadata["capacity"]) - int(metadata["next_state"])
                ),
                "reservations": counts,
                "stateless_signatures": stateless_count,
                "database": str(self.path),
            }
        finally:
            connection.close()

    def _reserve_state(self, message: bytes) -> tuple[int, bytes, bytes]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata(connection)
            state_counter = int(metadata["next_state"])
            capacity = int(metadata["capacity"])
            if state_counter >= capacity:
                connection.execute("ROLLBACK")
                raise LabnetError(
                    "stateful signer exhausted; use stateless recovery or initialize a new labnet key"
                )
            connection.execute(
                """
                INSERT INTO reservations(
                    state_counter, message_sha256, status, reserved_at
                ) VALUES(?, ?, 'reserved', ?)
                """,
                (state_counter, sha256_hex(message), utc_now()),
            )
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='next_state'",
                (str(state_counter + 1),),
            )
            connection.execute("COMMIT")
            return (
                state_counter,
                bytes.fromhex(metadata["secret_key_hex"]),
                bytes.fromhex(metadata["public_key_hex"]),
            )
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _finish_reservation(
        self,
        state_counter: int,
        *,
        status: str,
        signature: bytes | None = None,
        error: str | None = None,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE reservations
                   SET status=?, signature_sha256=?, error=?, finalized_at=?
                 WHERE state_counter=?
                """,
                (
                    status,
                    sha256_hex(signature) if signature is not None else None,
                    error,
                    utc_now(),
                    state_counter,
                ),
            )
            connection.execute("COMMIT")
        finally:
            connection.close()

    def sign_stateful(
        self, reference: ModuleType, message: bytes, context: bytes
    ) -> tuple[bytes, int]:
        state_counter, secret_key, public_key = self._reserve_state(message)
        try:
            structure = bytes.fromhex(self.metadata()["structure_hex"])
            if reference.shrincs_sf_leaf_select(structure, state_counter) is None:
                raise LabnetError("reserved counter does not select a stateful leaf")
            signature = reference.shrincs_sign(
                message, context, secret_key, state_counter, None
            )
            if signature is None:
                raise LabnetError("pinned SHRINCS signer returned no signature")
            if not reference.shrincs_verify(message, signature, context, public_key):
                raise LabnetError("self-verification rejected the generated stateful signature")
            self._finish_reservation(
                state_counter, status="signed", signature=signature
            )
            return signature, state_counter
        except Exception as exc:
            self._finish_reservation(
                state_counter, status="failed", error=str(exc)
            )
            raise

    def sign_stateless(
        self, reference: ModuleType, message: bytes, context: bytes
    ) -> bytes:
        metadata = self.metadata()
        secret_key = bytes.fromhex(metadata["secret_key_hex"])
        public_key = bytes.fromhex(metadata["public_key_hex"])
        randomizer = secrets.token_bytes(16)
        signature = reference.shrincs_sign(
            message, context, secret_key, None, randomizer
        )
        if signature is None:
            raise LabnetError("pinned SHRINCS stateless signer returned no signature")
        if not reference.shrincs_verify(message, signature, context, public_key):
            raise LabnetError("self-verification rejected the generated stateless signature")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO stateless_events(
                    message_sha256, signature_sha256, created_at
                ) VALUES(?, ?, ?)
                """,
                (sha256_hex(message), sha256_hex(signature), utc_now()),
            )
            connection.execute("COMMIT")
        finally:
            connection.close()
        return signature

    def record_broadcast(self, *, state_counter: int | None, signature: bytes, txid: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if state_counter is None:
                cursor = connection.execute(
                    """
                    UPDATE stateless_events
                       SET txid=?
                     WHERE id=(
                         SELECT id FROM stateless_events
                          WHERE signature_sha256=? AND txid IS NULL
                          ORDER BY id DESC LIMIT 1
                     )
                    """,
                    (txid, sha256_hex(signature)),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE reservations
                       SET status='broadcast', txid=?, finalized_at=?
                     WHERE state_counter=? AND signature_sha256=?
                    """,
                    (txid, utc_now(), state_counter, sha256_hex(signature)),
                )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise LabnetError("could not bind signer record to broadcast transaction")
            connection.execute("COMMIT")
        finally:
            connection.close()


class Labnet:
    def __init__(self, layout: Layout):
        self.layout = layout
        self.nodes = [Node(layout.node0), Node(layout.node1)]

    def require_build(self) -> None:
        missing = [path for path in (self.layout.daemon, self.layout.cli) if not path.is_file()]
        if missing:
            raise LabnetError(
                "labnet binaries are missing; run the build command first: "
                + ", ".join(str(path) for path in missing)
            )

    def build(self, jobs: int) -> dict[str, Any]:
        configure = [
            "cmake",
            "-S",
            REPO_ROOT,
            "-B",
            self.layout.build_dir,
            "-G",
            "Ninja",
            "-DBUILD_GUI=OFF",
            "-DBUILD_GUI_TESTS=OFF",
            "-DBUILD_BENCH=OFF",
            "-DBUILD_FUZZ_BINARY=OFF",
            "-DBUILD_KERNEL_LIB=OFF",
            "-DENABLE_WALLET=ON",
            "-DENABLE_IPC=OFF",
            "-DENABLE_EXTERNAL_SIGNER=OFF",
            "-DWITH_ZMQ=OFF",
            "-DWITH_USDT=OFF",
            "-DBUILD_TESTS=ON",
        ]
        run_command(configure, cwd=REPO_ROOT, capture=False)
        run_command(
            ["cmake", "--build", self.layout.build_dir, "--parallel", str(jobs)],
            cwd=REPO_ROOT,
            capture=False,
        )
        self.require_build()
        return {
            "result": "PASS",
            "build_dir": self.layout.build_dir,
            "daemon": self.layout.daemon,
            "cli": self.layout.cli,
        }

    def _initialize_state_root(self) -> None:
        self.layout.state_dir.mkdir(parents=True, exist_ok=True)
        if not self.layout.marker.exists():
            atomic_write(
                self.layout.marker,
                json.dumps(
                    {
                        "profile": "pqbtc-shrincs-v0-private-regtest-labnet",
                        "created_at": utc_now(),
                        "zero_value_only": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
            )

    def _fresh_reset(self) -> None:
        if not self.layout.state_dir.exists():
            return
        if not self.layout.marker.is_file():
            raise LabnetError(
                f"refusing to remove unmarked state directory: {self.layout.state_dir}"
            )
        self.stop()
        shutil.rmtree(self.layout.state_dir)

    def start(self, *, fresh: bool = False) -> dict[str, Any]:
        self.require_build()
        if fresh:
            self._fresh_reset()
        self._initialize_state_root()
        for node in self.nodes:
            node.paths.datadir.mkdir(parents=True, exist_ok=True)
            atomic_write(node.paths.config, node.paths.config_text())
            if not node.is_running():
                run_command(
                    [
                        self.layout.daemon,
                        "-regtest",
                        f"-datadir={node.paths.datadir}",
                        "-daemonwait",
                    ]
                )
            node.wait_ready()
            node.ensure_wallet()

        self.nodes[0].cli(
            "addnode", f"127.0.0.1:{self.layout.node1.p2p_port}", "onetry"
        )
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if int(self.nodes[0].cli("getconnectioncount")) >= 1:
                break
            time.sleep(0.25)
        else:
            raise LabnetError("the two private nodes did not connect")
        self._wait_height(self.nodes[0].height(), timeout=60.0)
        return self.status()

    def stop(self) -> dict[str, Any]:
        stopped: list[int] = []
        for node in reversed(self.nodes):
            if node.is_running():
                node.cli("stop")
                stopped.append(node.paths.index)
        deadline = time.monotonic() + 30.0
        for node in self.nodes:
            while node.is_running() and time.monotonic() < deadline:
                time.sleep(0.2)
        return {"result": "PASS", "stopped_nodes": stopped}

    def _wait_height(self, height: int, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(node.height() >= height for node in self.nodes):
                return
            time.sleep(0.25)
        raise LabnetError(f"nodes did not synchronize to height {height}")

    def mine(self, blocks: int, node_index: int = 0) -> dict[str, Any]:
        if blocks <= 0:
            raise LabnetError("block count must be positive")
        node = self.nodes[node_index]
        address = node.cli("getnewaddress", wallet=True)
        hashes = node.cli("generatetoaddress", blocks, address)
        height = node.height()
        self._wait_height(height)
        return {
            "result": "PASS",
            "miner": node_index,
            "blocks_mined": blocks,
            "height": height,
            "tip": hashes[-1] if hashes else None,
        }

    def ensure_mature_balance(self) -> dict[str, Any]:
        height = self.nodes[0].height()
        if height < 101:
            return self.mine(101 - height)
        if self.nodes[0].balance() <= 0:
            return self.mine(101)
        return {"result": "PASS", "height": height, "balance": self.nodes[0].balance()}

    def fetch_upstream(self, *, refresh: bool = False) -> dict[str, Any]:
        path = self.layout.upstream_dir
        controlled_default = path == self.layout.state_dir / "upstream" / "shrincs-bip"
        if refresh and path.exists():
            if not controlled_default:
                raise LabnetError("refusing to delete SHRINCS_BIP_DIR override")
            shutil.rmtree(path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            run_command(["git", "init", path])
            run_command(["git", "-C", path, "remote", "add", "origin", UPSTREAM_REPOSITORY])
            run_command(
                ["git", "-C", path, "fetch", "--depth", "1", "origin", UPSTREAM_COMMIT]
            )
            run_command(["git", "-C", path, "checkout", "--detach", "FETCH_HEAD"])
        head = git_head(path)
        if head != UPSTREAM_COMMIT:
            raise LabnetError(
                f"upstream signer checkout mismatch: expected {UPSTREAM_COMMIT}, found {head}"
            )
        return {"result": "PASS", "path": path, "commit": head}

    def reference(self) -> ModuleType:
        self.fetch_upstream()
        return load_module(
            self.layout.upstream_dir / "impl" / "shrincs.py",
            "pqbtc_shrincs_labnet_reference",
        )

    def tx_model(self) -> ModuleType:
        return load_module(TX_MODEL_PATH, "pqbtc_shrincs_labnet_tx_model")

    def initialize_signer(self, *, force: bool = False) -> dict[str, Any]:
        store = SignerStore(self.layout.signer_db)
        if force and store.exists():
            for suffix in ("", "-wal", "-shm"):
                with contextlib.suppress(FileNotFoundError):
                    Path(str(store.path) + suffix).unlink()
        if not store.exists():
            reference = self.reference()
            seed = secrets.token_bytes(48)
            secret_key, public_key = reference.shrincs_keygen(seed, SIGNER_STRUCTURE)
            store.create(secret_key, public_key, SIGNER_STRUCTURE)
        status = store.status()
        model = self.tx_model()
        status["output_commitment"] = model.output_commitment(store.public_key()).hex()
        status["result"] = "PASS"
        return status

    def signer_status(self) -> dict[str, Any]:
        store = SignerStore(self.layout.signer_db)
        status = store.status()
        status["output_commitment"] = self.tx_model().output_commitment(store.public_key()).hex()
        status["result"] = "PASS"
        return status

    def status(self) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        for node in self.nodes:
            running = node.is_running()
            entry: dict[str, Any] = {
                "index": node.paths.index,
                "running": running,
                "datadir": node.paths.datadir,
                "p2p_port": node.paths.p2p_port,
                "rpc_port": node.paths.rpc_port,
            }
            if running:
                entry.update(
                    {
                        "height": node.height(),
                        "connections": int(node.cli("getconnectioncount")),
                        "balance": node.balance(),
                        "wallet": node.paths.wallet,
                    }
                )
            nodes.append(entry)
        result: dict[str, Any] = {
            "profile": "pqbtc-shrincs-v0-private-regtest-labnet",
            "zero_value_only": True,
            "state_dir": self.layout.state_dir,
            "build_dir": self.layout.build_dir,
            "nodes": nodes,
        }
        if self.layout.signer_db.exists():
            result["signer"] = self.signer_status()
        return result

    def _funding_output(
        self, node: Node, *, script_hex: str, address: str, amount: Decimal
    ) -> dict[str, Any]:
        txid = str(node.cli("sendtoaddress", address, format(amount, "f"), wallet=True))
        self.mine(1, node_index=node.paths.index)
        transaction = node.cli("getrawtransaction", txid, "true")
        for output in transaction.get("vout", []):
            script = output.get("scriptPubKey", {})
            if script.get("hex") == script_hex:
                return {
                    "txid": txid,
                    "vout": int(output["n"]),
                    "amount_sats": sats(output["value"]),
                    "script_hex": script_hex,
                }
        raise LabnetError("funding transaction did not contain the SHRINCS output")

    def _build_signed_spend(
        self,
        *,
        funding: dict[str, Any],
        destination_script: bytes,
        mode: str,
    ) -> tuple[Any, bytes, int | None]:
        if str(TEST_FRAMEWORK_ROOT) not in sys.path:
            sys.path.insert(0, str(TEST_FRAMEWORK_ROOT))
        from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut

        model = self.tx_model()
        reference = self.reference()
        store = SignerStore(self.layout.signer_db)
        public_key = store.public_key()
        amount_sats = int(funding["amount_sats"])
        if amount_sats <= DEFAULT_FEE_SATS:
            raise LabnetError("funding output is too small for the fixed labnet fee")
        sequence = 0xFFFFFFFD

        transaction = CTransaction()
        transaction.version = 2
        transaction.vin = [
            CTxIn(
                COutPoint(int(funding["txid"], 16), int(funding["vout"])),
                scriptSig=b"",
                nSequence=sequence,
            )
        ]
        transaction.vout = [CTxOut(amount_sats - DEFAULT_FEE_SATS, destination_script)]
        transaction.nLockTime = 0

        model_transaction = model.Transaction(
            version=transaction.version,
            inputs=(
                model.SpentInput(
                    prevout=model.OutPoint(bytes.fromhex(funding["txid"])[::-1], int(funding["vout"])),
                    amount=amount_sats,
                    script_pubkey=bytes.fromhex(funding["script_hex"]),
                    sequence=sequence,
                ),
            ),
            outputs=(model.TxOutput(amount_sats - DEFAULT_FEE_SATS, destination_script),),
            lock_time=transaction.nLockTime,
        )
        digest = model.transaction_sighash(model_transaction, 0, model.TEST_CHAIN_ID)
        if mode == "stateful":
            signature, state_counter = store.sign_stateful(reference, digest, model.SHRINCS_CONTEXT)
        elif mode == "stateless":
            signature = store.sign_stateless(reference, digest, model.SHRINCS_CONTEXT)
            state_counter = None
        else:
            raise LabnetError(f"unknown signing mode: {mode}")

        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [signature, public_key]
        return transaction, signature, state_counter

    def shrincs_demo(self, mode: str, amount: Decimal = DEFAULT_FUNDING) -> dict[str, Any]:
        if mode not in {"stateful", "stateless", "both"}:
            raise LabnetError("mode must be stateful, stateless, or both")
        self.ensure_mature_balance()
        if not self.layout.signer_db.exists():
            self.initialize_signer()

        if str(TEST_FRAMEWORK_ROOT) not in sys.path:
            sys.path.insert(0, str(TEST_FRAMEWORK_ROOT))
        from test_framework.address import address_to_scriptpubkey, program_to_witness

        node = self.nodes[0]
        store = SignerStore(self.layout.signer_db)
        model = self.tx_model()
        public_key = store.public_key()
        program = model.output_commitment(public_key)
        shrincs_address = program_to_witness(2, program, main=False)
        shrincs_script = model.script_pubkey(public_key)
        modes = ["stateful", "stateless"] if mode == "both" else [mode]
        results: list[dict[str, Any]] = []

        for current_mode in modes:
            funding = self._funding_output(
                node,
                script_hex=shrincs_script.hex(),
                address=shrincs_address,
                amount=amount,
            )
            destination_address = str(node.cli("getnewaddress", wallet=True))
            destination_script = bytes(address_to_scriptpubkey(destination_address))
            transaction, signature, state_counter = self._build_signed_spend(
                funding=funding,
                destination_script=destination_script,
                mode=current_mode,
            )
            raw = transaction.serialize().hex()
            accepted = node.cli("testmempoolaccept", json.dumps([raw]))[0]
            if not accepted.get("allowed"):
                raise LabnetError(
                    f"node rejected valid {current_mode} spend: {accepted.get('reject-reason', accepted)}"
                )

            mutated = type(transaction)(transaction)
            bad_signature = bytearray(mutated.wit.vtxinwit[0].scriptWitness.stack[0])
            bad_signature[len(bad_signature) // 2] ^= 1
            mutated.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(bad_signature)
            rejected = node.cli(
                "testmempoolaccept", json.dumps([mutated.serialize().hex()])
            )[0]
            if rejected.get("allowed"):
                raise LabnetError("node accepted a bit-mutated SHRINCS signature")

            txid = str(node.cli("sendrawtransaction", raw))
            if txid != transaction.txid_hex:
                raise LabnetError("node txid disagrees with local transaction serialization")
            block = self.mine(1)["tip"]
            block_txids = node.cli("getblock", block).get("tx", [])
            if txid not in block_txids:
                raise LabnetError("mined block did not contain the SHRINCS spend")
            store.record_broadcast(
                state_counter=state_counter, signature=signature, txid=txid
            )
            results.append(
                {
                    "mode": current_mode,
                    "address": shrincs_address,
                    "funding_txid": funding["txid"],
                    "funding_vout": funding["vout"],
                    "spend_txid": txid,
                    "block": block,
                    "signature_bytes": len(signature),
                    "state_counter": state_counter,
                    "mutated_signature_rejected": True,
                }
            )

        return {
            "result": "PASS",
            "profile": SIGNER_PROFILE,
            "zero_value_only": True,
            "height": node.height(),
            "transactions": results,
            "signer": self.signer_status(),
        }

    def quickstart(self, *, fresh: bool, build: bool, jobs: int, mode: str) -> dict[str, Any]:
        phases: dict[str, Any] = {}
        if build:
            phases["build"] = self.build(jobs)
        phases["start"] = self.start(fresh=fresh)
        phases["maturity"] = self.ensure_mature_balance()
        phases["upstream"] = self.fetch_upstream()
        phases["signer"] = self.initialize_signer()
        phases["shrincs"] = self.shrincs_demo(mode)
        phases["status"] = self.status()
        return {"result": "PASS", "phases": phases}


def default_jobs() -> int:
    return max(1, min(4, os.cpu_count() or 2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=REPO_ROOT / ".shrincs-labnet",
        help="persistent private labnet state directory",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=REPO_ROOT / "build-shrincs-labnet",
        help="CMake build directory",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="configure and compile node, CLI, wallet, and tests")
    build.add_argument("--jobs", type=int, default=default_jobs())

    start = subparsers.add_parser("start", help="start and connect two persistent private nodes")
    start.add_argument("--fresh", action="store_true", help="erase only a marked labnet state directory")

    subparsers.add_parser("stop", help="stop both private nodes")
    subparsers.add_parser("status", help="show node, wallet, and signer state")

    mine = subparsers.add_parser("mine", help="mine blocks and synchronize both nodes")
    mine.add_argument("blocks", type=int)
    mine.add_argument("--node", type=int, choices=(0, 1), default=0)

    fetch = subparsers.add_parser("fetch-upstream", help="fetch and verify the exact executable signer model")
    fetch.add_argument("--refresh", action="store_true")

    signer_init = subparsers.add_parser("signer-init", help="initialize the crash-safe labnet signer")
    signer_init.add_argument("--force", action="store_true", help="replace only the labnet signer database")
    subparsers.add_parser("signer-status", help="show state reservations and remaining stateful leaves")

    demo = subparsers.add_parser("shrincs-demo", help="fund, sign, broadcast, reject mutation, and mine")
    demo.add_argument("--mode", choices=("stateful", "stateless", "both"), default="both")
    demo.add_argument("--amount", type=Decimal, default=DEFAULT_FUNDING)

    quickstart = subparsers.add_parser("quickstart", help="build and execute the complete private labnet workflow")
    quickstart.add_argument("--fresh", action="store_true")
    quickstart.add_argument("--no-build", action="store_true")
    quickstart.add_argument("--jobs", type=int, default=default_jobs())
    quickstart.add_argument("--mode", choices=("stateful", "stateless", "both"), default="both")
    return parser


def main() -> int:
    os.umask(0o077)
    args = build_parser().parse_args()
    layout = Layout(
        state_dir=args.state_dir.expanduser().resolve(),
        build_dir=args.build_dir.expanduser().resolve(),
    )
    labnet = Labnet(layout)
    try:
        if args.command == "build":
            result = labnet.build(args.jobs)
        elif args.command == "start":
            result = labnet.start(fresh=args.fresh)
        elif args.command == "stop":
            result = labnet.stop()
        elif args.command == "status":
            result = labnet.status()
        elif args.command == "mine":
            result = labnet.mine(args.blocks, node_index=args.node)
        elif args.command == "fetch-upstream":
            result = labnet.fetch_upstream(refresh=args.refresh)
        elif args.command == "signer-init":
            result = labnet.initialize_signer(force=args.force)
        elif args.command == "signer-status":
            result = labnet.signer_status()
        elif args.command == "shrincs-demo":
            result = labnet.shrincs_demo(args.mode, args.amount)
        elif args.command == "quickstart":
            result = labnet.quickstart(
                fresh=args.fresh,
                build=not args.no_build,
                jobs=args.jobs,
                mode=args.mode,
            )
        else:
            raise AssertionError(args.command)
        emit(result)
        return 0
    except (LabnetError, CommandError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
