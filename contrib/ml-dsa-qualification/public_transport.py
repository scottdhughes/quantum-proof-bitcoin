#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded loopback P2P-to-public-TLS bridge for the valueless TEST profile.

No RPC, wallet operation, Tailscale authentication or private destination is
accepted here. Peers need only Python's TLS trust store and the published public
endpoint. Resolve its public IP independently, then pass that numeric address.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
import json
import re
import select
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAGIC = bytes.fromhex("a7e29cf7")
MAX_PAYLOAD = 4_000_000
MAX_CONNECTION_BYTES = 256 * 1024 * 1024
MAX_LIFETIME = 27 * 3600
# A guarded 30-second native renewal still needs time to negotiate P2P and ping.
BRIDGE_CONNECT_SECONDS = 25


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class PublicEndpoint:
    hostname: str
    port: int
    addresses: tuple

    def __post_init__(self):
        require(type(self.hostname) is str and len(self.hostname) <= 253 and
                re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", self.hostname) and
                "." in self.hostname and all(part and len(part) <= 63 for part in self.hostname.split(".")),
                "A public TLS DNS hostname is required")
        require(type(self.port) is int and self.port in (443, 8443, 10000), "Unsupported public TLS port")
        require(type(self.addresses) is tuple and 1 <= len(self.addresses) <= 8 and
                len(set(self.addresses)) == len(self.addresses), "Provide one to eight distinct numeric public IPs")
        for address in self.addresses:
            require(type(address) is str, "Public IP must be numeric")
            parsed = ipaddress.ip_address(address)
            require(parsed.is_global and not parsed.is_multicast and not parsed.is_reserved and
                    not parsed.is_unspecified and not parsed.is_loopback and not parsed.is_link_local,
                    "Private, overlay, multicast and reserved destinations are refused")


def _connect_verified(context, endpoint, address, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TCP connect deadline")
    with socket.create_connection((address, endpoint.port), timeout=remaining) as raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS handshake deadline")
        raw.settimeout(remaining)
        connection = context.wrap_socket(raw, server_hostname=endpoint.hostname)
    try:
        require(ipaddress.ip_address(connection.getpeername()[0]) == ipaddress.ip_address(address),
                "TLS peer differs from declared public route")
        if time.monotonic() >= deadline:
            raise TimeoutError("TLS handshake deadline")
    except BaseException:
        connection.close()
        raise
    return connection


def open_public_tls(endpoint, timeout=10, *, retry_transient=False, failures=None):
    """Use numeric public routing, with normal CA and DNS-name verification."""
    deadline = time.monotonic() + timeout
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    failures = [] if failures is None else failures
    pause = 0.5
    while time.monotonic() < deadline:
        for index, address in enumerate(endpoint.addresses):
            now = time.monotonic()
            # Leave time for each remaining declared ingress address.
            address_deadline = now + (deadline - now) / (len(endpoint.addresses) - index)
            try:
                return _connect_verified(context, endpoint, address, address_deadline)
            except (ssl.SSLEOFError, ConnectionError, TimeoutError) as error:
                reason = type(error).__name__
            except OSError as error:
                # Other TLS errors (including untrusted certificates) and
                # unexpected local errors remain terminal.
                if isinstance(error, ssl.SSLError) or error.errno not in (errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH):
                    raise
                reason = errno.errorcode[error.errno]
            failures.append({"address": address, "reason": reason})
        remaining = deadline - time.monotonic()
        if not retry_transient or remaining <= 0:
            break
        time.sleep(min(pause, remaining))
        pause = min(2, 2 * pause)
    raise ConnectionError("Public TLS ingress unavailable before P2P handshake: " + json.dumps(failures))


def frame(command, payload=b""):
    require(type(command) is bytes and re.fullmatch(b"[a-z0-9]{1,12}", command), "Invalid P2P command")
    require(type(payload) is bytes and len(payload) <= MAX_PAYLOAD, "P2P payload bound")
    return MAGIC + command.ljust(12, b"\0") + struct.pack("<I", len(payload)) + hashlib.sha256(
        hashlib.sha256(payload).digest()).digest()[:4] + payload


def read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        require(time.monotonic() < deadline, "Public P2P handshake deadline")
        connection.settimeout(max(0.01, min(5, deadline - time.monotonic())))
        part = connection.recv(count - len(result))
        require(part, "Public P2P connection closed before handshake")
        result.extend(part)
    return bytes(result)


def read_frame(connection, deadline):
    header = read_exact(connection, 24, deadline)
    require(header[:4] == MAGIC, "Wrong native P2P network magic")
    command = header[4:16].rstrip(b"\0")
    require(re.fullmatch(b"[a-z0-9]{1,12}", command) and header[4:16] == command.ljust(12, b"\0"),
            "Malformed native P2P command")
    size = struct.unpack("<I", header[16:20])[0]
    require(size <= MAX_PAYLOAD, "Public P2P payload bound")
    payload = read_exact(connection, size, deadline)
    require(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == header[20:24],
            "Public P2P checksum mismatch")
    return command, payload


@dataclass(frozen=True)
class RemoteVersion:
    """Lossless modern version; addrv1's two 26-byte addresses stay opaque.

    The functional framework deliberately decodes only IPv4 addrv1 addresses;
    it cannot round-trip a node's canonical unspecified or other IPv6 address.
    These advertised bytes are never used as public connection destinations.
    """
    nVersion: int
    nServices: int
    nTime: int
    addrTo: bytes
    addrFrom: bytes
    nNonce: int
    strSubVer: str
    nStartingHeight: int
    relay: int

    def serialize(self):
        subversion = self.strSubVer.encode("ascii")
        size = len(subversion)
        prefix = bytes([size]) if size < 253 else b"\xfd" + struct.pack("<H", size)
        return (struct.pack("<iQq", self.nVersion, self.nServices, self.nTime) + self.addrTo + self.addrFrom +
                struct.pack("<Q", self.nNonce) + prefix + subversion + struct.pack("<iB", self.nStartingHeight, self.relay))


def parse_remote_version(payload):
    """Strict canonical modern version grammar with complete address bytes."""
    require(type(payload) is bytes and 86 <= len(payload) <= 344, "Incomplete or oversized peer version")
    protocol = struct.unpack("<i", payload[:4])[0]
    require(protocol >= 70001, "Unsupported peer protocol version")
    marker = payload[80]
    prefix = 1 if marker < 253 else 3 if marker == 253 else 5 if marker == 254 else 9
    size = marker if prefix == 1 else int.from_bytes(payload[81:80 + prefix], "little")
    require((prefix == 1 or (prefix == 3 and size >= 253)) and size <= 256,
            "Noncanonical or oversized peer subversion")
    end = 80 + prefix + size
    require(len(payload) == end + 5 and payload[-1] in (0, 1), "Truncated, extended or malformed peer version")
    require(all(32 <= byte <= 126 for byte in payload[80 + prefix:end]), "Peer subversion must be printable ASCII")
    version = RemoteVersion(protocol, struct.unpack_from("<Q", payload, 4)[0], struct.unpack_from("<q", payload, 12)[0],
                            payload[20:46], payload[46:72], struct.unpack_from("<Q", payload, 72)[0],
                            payload[80 + prefix:end].decode("ascii"), struct.unpack_from("<i", payload, end)[0], payload[-1])
    require(version.serialize() == payload, "Peer version is not an exact canonical wire round-trip")
    return version


def probe(endpoint, *, timeout=20, owned_oversize_control=False, tls_failures=None):
    """Complete a native v1 P2P version/verack over certificate-checked TLS."""
    sys.path.insert(0, str(ROOT / "test/functional"))
    from test_framework.messages import msg_version
    version = msg_version()
    version.nVersion = 70016
    version.nTime = int(time.time())
    version.strSubVer = "/PQBTC-public-route-probe:1/"
    version.nStartingHeight = 0
    version.relay = 0
    started = time.monotonic()
    deadline = started + timeout
    commands, remote_version = [], None
    tls_failures = [] if tls_failures is None else tls_failures
    with open_public_tls(endpoint, timeout=min(10, timeout), retry_transient=True, failures=tls_failures) as connection:
        certificate = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
        peer = connection.getpeername()[0]
        tls_version = connection.version()
        connection.sendall(frame(b"version", version.serialize()))
        got_verack = False
        while not (remote_version is not None and got_verack):
            require(len(commands) < 32, "Public P2P handshake message bound")
            command, payload = read_frame(connection, deadline)
            commands.append(command.decode("ascii"))
            if command == b"version":
                require(remote_version is None, "Duplicate public peer version")
                remote_version = parse_remote_version(payload)
                connection.sendall(frame(b"verack"))
            elif command == b"verack":
                require(remote_version is not None and not got_verack and not payload,
                        "Out-of-order, duplicate or nonempty verack")
                got_verack = True
            elif command == b"ping":
                require(remote_version is not None, "P2P version must precede ping")
                require(len(payload) == 8, "Malformed ping")
                connection.sendall(frame(b"pong", payload))
            else:
                require(remote_version is not None, "P2P version must precede negotiation")
        result = {"result": "PASS", "scope": "ANONYMOUS_PUBLIC_TLS_NATIVE_P2P_HANDSHAKE_ONLY",
                "hostname": endpoint.hostname, "port": endpoint.port, "public_peer_ip": peer,
                "certificate_sha256": certificate, "tls_version": tls_version, "tls_transient_failures": tls_failures,
                "native_magic": MAGIC.hex(), "remote_protocol": remote_version.nVersion,
                "remote_subversion": remote_version.strSubVer,
                "remote_height": remote_version.nStartingHeight, "commands": commands,
                "elapsed_seconds": time.monotonic() - started}
        if not owned_oversize_control:
            return result
        # Only a 24-byte header is sent. The actual node's transport must reject
        # its declared size before allocating/reading any oversized block body.
        oversized = MAGIC + b"block".ljust(12, b"\0") + struct.pack("<I", MAX_PAYLOAD + 1) + bytes(4)
        connection.sendall(oversized)
        received, disconnected = 0, False
        while time.monotonic() < deadline:
            connection.settimeout(max(0.01, min(1, deadline - time.monotonic())))
            try:
                data = connection.recv(65536)
            except socket.timeout:
                continue
            except (ConnectionResetError, ssl.SSLEOFError):
                disconnected = True
                break
            if not data:
                disconnected = True
                break
            received += len(data)
            require(received <= 65536, "Owned P2P disconnect-control response bound")
        require(disconnected, "Owned public peer did not disconnect the oversized P2P header")
        return {"result": "PASS", "scope": "BOUNDED_PUBLIC_P2P_OVERSIZED_HEADER_CONTROL",
                "disconnect_observed": True, "invalid_accepted": False, "header_sha256": hashlib.sha256(oversized).hexdigest(),
                "sent_bytes": len(oversized), "handshake": result, "elapsed_seconds": time.monotonic() - started}


def relay(left, right, deadline, *, byte_limit=MAX_CONNECTION_BYTES, idle_seconds=900):
    """Forward opaque bytes with bounded memory, idle time, total bytes and life."""
    counts = [0, 0]
    last_activity = time.monotonic()
    connections = (left, right)
    wants_write = [False, False]

    def finished(reason, side="bridge"):
        return {"reason": reason, "bytes": counts, "close_side": side}

    left.settimeout(5)
    right.settimeout(5)
    while time.monotonic() < deadline:
        now = time.monotonic()
        idle_remaining = last_activity + idle_seconds - now
        if idle_remaining <= 0:
            return finished("idle_deadline")
        pending = [item for index, item in enumerate(connections)
                   if not wants_write[index] and isinstance(item, ssl.SSLSocket) and item.pending()]
        readable, writable, _ = select.select(
            [item for index, item in enumerate(connections) if not wants_write[index]],
            [item for index, item in enumerate(connections) if wants_write[index]], [],
            0 if pending else min(1, max(0, deadline - now), idle_remaining))
        for index, source in enumerate(connections):
            if source not in pending + readable + writable:
                continue
            # A readable TLS fd may hold only control records. SSL recv must
            # not block the opposite direction while waiting for application
            # data; a WANT result instead selects its required I/O direction.
            receive_failed = False
            try:
                source.settimeout(0)
                data = source.recv(min(65536, byte_limit - sum(counts) + 1))
            except ssl.SSLWantWriteError:
                wants_write[index] = True
                continue
            except (ssl.SSLWantReadError, BlockingIOError):
                wants_write[index] = False
                continue
            except (OSError, ValueError) as error:
                receive_failed = True
                error._pqbtc_close_side = "local" if index == 0 else "public_tls"
                raise
            finally:
                try:
                    source.settimeout(5)
                except (OSError, ValueError) as error:
                    # An owned concurrent close must not replace an already
                    # propagating receive error or erase its side/class.
                    if not receive_failed:
                        error._pqbtc_close_side = "local" if index == 0 else "public_tls"
                        raise
            wants_write[index] = False
            if not data:
                return finished("peer_closed", "local" if index == 0 else "public_tls")
            counts[index] += len(data)
            require(sum(counts) <= byte_limit, "P2P bridge connection byte bound")
            now = time.monotonic()
            if now >= deadline:
                return finished("lifetime_deadline")
            if now >= last_activity + idle_seconds:
                return finished("idle_deadline")
            target = connections[1 - index]
            try:
                target.settimeout(min(5, deadline - now, last_activity + idle_seconds - now))
                # A failed sendall may have partially written this chunk.
                # Propagate it; replaying the whole chunk can duplicate bytes.
                target.sendall(data)
            except (OSError, ValueError) as error:
                error._pqbtc_close_side = "public_tls" if index == 0 else "local"
                raise
            last_activity = time.monotonic()
    return finished("lifetime_deadline")


class Bridge(socketserver.ThreadingTCPServer):
    # Permit an owned listener to restart while its closed connections remain
    # in TIME_WAIT. This does not permit replacing another live TCP listener.
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, port, endpoint, deadline):
        require(type(port) is int and 1024 <= port <= 65535, "Loopback port range")
        require(time.monotonic() < deadline <= time.monotonic() + MAX_LIFETIME, "Bridge must have a bounded future deadline")
        self.endpoint, self.deadline = endpoint, deadline
        self.slots = threading.BoundedSemaphore(8)
        self.output_lock = threading.Lock()
        self.connections_lock = threading.Lock()
        self.connections = set()
        super().__init__(("127.0.0.1", port), BridgeHandler)
        self.timeout = 1

    def event(self, value):
        with self.output_lock:
            print(json.dumps(value, sort_keys=True), flush=True)

    def connection_event(self, value):
        # The initial bridge_started readiness schema is deliberately unchanged.
        self.event({**value, "utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    "monotonic_ns": time.monotonic_ns()})

    def verify_request(self, request, client_address):
        return client_address[0] == "127.0.0.1" and self.slots.acquire(blocking=False)

    def close_connections(self):
        with self.connections_lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def handle_error(self, request, client_address):
        # No request bytes, traceback, or uncontrolled exception text in logs.
        error = sys.exc_info()[1]
        side = getattr(error, "_pqbtc_close_side", "bridge")
        self.connection_event({"event": "bridge_connection_failed", "error_class": type(error).__name__[:80],
                               "close_side": side if side in ("local", "public_tls", "bridge") else "bridge"})


class BridgeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        remote = None
        try:
            with self.server.connections_lock:
                self.server.connections.add(self.request)
            failures = []
            try:
                remaining = self.server.deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Public bridge lifetime deadline")
                # No native bytes have been forwarded yet. After relay starts,
                # a lost connection must end this native stream.
                remote = open_public_tls(self.server.endpoint, timeout=min(BRIDGE_CONNECT_SECONDS, remaining),
                                         retry_transient=True, failures=failures)
            except (OSError, ValueError) as error:
                error._pqbtc_close_side = "public_tls"
                raise
            finally:
                if failures:
                    self.server.connection_event({"event": "public_tls_connect_failures", "failures": failures})
            with self.server.connections_lock:
                self.server.connections.add(remote)
            self.server.connection_event({"event": "public_tls_connected", "public_ip": remote.getpeername()[0],
                                          "hostname": self.server.endpoint.hostname, "tls": remote.version(),
                                          "close_side": None, "error_class": None})
            result = relay(self.request, remote, self.server.deadline)
            self.server.connection_event({"event": "public_tls_disconnected", **result, "error_class": None})
        finally:
            with self.server.connections_lock:
                self.server.connections.discard(self.request)
                self.server.connections.discard(remote)
            if remote is not None:
                remote.close()
            self.server.slots.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("probe", "bridge", "hostile-probe"))
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--public-ip", action="append", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--listen-port", type=int, default=23834)
    parser.add_argument("--until-utc", help="Required bridge shutdown time, ISO 8601 with UTC offset")
    parser.add_argument("--instance-id", help="Public process marker used for exact-instance teardown")
    parser.add_argument("--owned-public-test-control", action="store_true", help="explicitly authorize one oversized-header disconnect test on an owned endpoint")
    args = parser.parse_args()
    endpoint = PublicEndpoint(args.hostname, args.port, tuple(args.public_ip))
    if args.mode in ("probe", "hostile-probe"):
        require(args.mode != "hostile-probe" or args.owned_public_test_control,
                "A hostile probe requires explicit owned public-test control")
        print(json.dumps(probe(endpoint, owned_oversize_control=args.mode == "hostile-probe"), sort_keys=True))
        return
    require(args.until_utc, "An independent bridge shutdown time is required")
    if args.instance_id is not None:
        require(re.fullmatch(r"[0-9a-f]{32}", args.instance_id), "Bridge instance marker must be 32 lowercase hex characters")
    end = datetime.fromisoformat(args.until_utc)
    require(end.tzinfo is not None and end.utcoffset().total_seconds() == 0, "Bridge end must be UTC")
    remaining = end.timestamp() - datetime.now(timezone.utc).timestamp()
    require(0 < remaining <= MAX_LIFETIME, "Bridge duration must be positive and at most 27 hours")
    with Bridge(args.listen_port, endpoint, time.monotonic() + remaining) as server:
        server.event({"event": "bridge_started", "loopback_port": args.listen_port,
                      "hostname": endpoint.hostname, "public_ips": endpoint.addresses,
                      "until_utc": end.isoformat()})
        try:
            while time.monotonic() < server.deadline:
                server.handle_request()
        finally:
            server.close_connections()
            server.event({"event": "bridge_stopped"})


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit("Public transport refused: " + str(error)) from error
