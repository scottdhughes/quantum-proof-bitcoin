"""Bounds and actual byte forwarding for the explicit public P2P adapter."""
import importlib.util
import errno
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[2] / "contrib/ml-dsa-qualification/public_transport.py"
SPEC = importlib.util.spec_from_file_location("mldsa_public_transport", PATH)
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)


class PublicTransportTests(unittest.TestCase):
    def tls_pair(self, tickets=0):
        """Real certificate-checked localhost TLS, using only a disposable key."""
        temporary = tempfile.TemporaryDirectory(prefix="pqbtc-tls-unit-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        config, certificate, key = (directory / name for name in ("localhost.cnf", "certificate.pem", "key.pem"))
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                          "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n"
                          "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                        "-config", str(config), "-keyout", str(key), "-out", str(certificate)],
                       check=True, capture_output=True, timeout=10,
                       env={"PATH": os.environ["PATH"], "LANG": "C", "OPENSSL_CONF": "/dev/null"})
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = server_context.maximum_version = ssl.TLSVersion.TLSv1_3
        server_context.load_cert_chain(certificate, key)
        server_context.num_tickets = tickets
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_3
        client_context.load_verify_locations(cafile=certificate)

        class ObservedTLS(ssl.SSLSocket):
            def recv(inner, size=1024, flags=0):
                if hasattr(inner, "recv_entered"):
                    inner.recv_entered.set()
                return super().recv(size, flags)

        client_context.sslsocket_class = ObservedTLS
        accepted = queue.Queue()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)

        def accept():
            try:
                raw, _address = listener.accept()
                raw.settimeout(2)
                accepted.put(server_context.wrap_socket(raw, server_side=True))
            except BaseException as error:
                accepted.put(error)

        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        raw = socket.create_connection(listener.getsockname(), timeout=2)
        remote = client_context.wrap_socket(raw, server_hostname="localhost")
        server = accepted.get(timeout=2)
        listener.close()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        if isinstance(server, BaseException):
            raise server
        self.addCleanup(remote.close)
        self.addCleanup(server.close)
        remote.recv_entered = threading.Event()
        server.settimeout(1.5)
        return remote, server

    @staticmethod
    def exact(connection, count):
        data = bytearray()
        while len(data) < count:
            part = connection.recv(count - len(data))
            if not part:
                break
            data.extend(part)
        return bytes(data)

    def relay_thread(self, local, remote, peers, *, lifetime=4, **kwargs):
        state = {}

        def run():
            try:
                state["result"] = transport.relay(local, remote, time.monotonic() + lifetime, **kwargs)
            except BaseException as error:
                state["error"] = type(error).__name__
            finally:
                local.close()
                remote.close()

        worker = threading.Thread(target=run, daemon=True)
        worker.start()

        def cleanup():
            for peer in peers:
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                peer.close()
            worker.join(2)
            self.assertFalse(worker.is_alive(), "Owned relay fixture failed to stop")
        self.addCleanup(cleanup)
        return state, worker

    def test_tls13_control_records_do_not_block_opposite_direction(self):
        remote, server = self.tls_pair(tickets=2)
        self.assertEqual(remote.pending(), 0)
        self.assertTrue(transport.select.select([remote], [], [], 1)[0], "TLS session tickets were not queued")
        client, local = socket.socketpair()
        client.settimeout(1.5)
        state, worker = self.relay_thread(local, remote, (client, server))
        self.assertTrue(remote.recv_entered.wait(1))
        outbound = transport.frame(b"inv", b"\x01" + (5).to_bytes(4, "little") + bytes([51]) * 32)
        client.sendall(outbound)
        try:
            observed = self.exact(server, len(outbound))
        except TimeoutError:
            self.fail("TLS control-only readability blocked the queued local INV")
        self.assertEqual(observed, outbound)
        inbound = b"reply spanning TLS records" * 2200
        server.sendall(inbound)
        self.assertEqual(self.exact(client, len(inbound)), inbound)
        client.shutdown(socket.SHUT_WR)
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("error", state)
        self.assertEqual(state["result"]["bytes"], [len(outbound), len(inbound)])

    def test_tls_pending_plaintext_is_drained_without_kernel_readability(self):
        remote, server = self.tls_pair()
        payload = b"already decrypted plaintext" * 300
        server.sendall(payload)
        first = remote.recv(1)
        self.assertGreater(remote.pending(), 0)
        self.assertFalse(transport.select.select([remote], [], [], 0)[0])
        client, local = socket.socketpair()
        client.settimeout(1.5)
        state, worker = self.relay_thread(local, remote, (client, server))
        self.assertEqual(first + self.exact(client, len(payload) - 1), payload)
        client.shutdown(socket.SHUT_WR)
        worker.join(2)
        self.assertNotIn("error", state)

    def test_tls_multirecord_chunks_are_written_completely_in_both_directions(self):
        remote, server = self.tls_pair()
        client, local = socket.socketpair()
        client.settimeout(1.5)
        state, worker = self.relay_thread(local, remote, (client, server))
        for sender, receiver, payload in ((client, server, b"outbound opaque bytes" * 12000),
                                           (server, client, b"inbound opaque bytes" * 11000)):
            errors = []

            def send():
                try:
                    sender.sendall(payload)
                except BaseException as error:
                    errors.append(type(error).__name__)

            writer = threading.Thread(target=send, daemon=True)
            writer.start()
            self.assertEqual(self.exact(receiver, len(payload)), payload)
            writer.join(2)
            self.assertFalse(writer.is_alive())
            self.assertEqual(errors, [])
        client.shutdown(socket.SHUT_WR)
        worker.join(2)
        self.assertNotIn("error", state)
        self.assertEqual(state["result"]["bytes"], [252000, 220000])

    def test_tls_control_only_traffic_preserves_idle_and_lifetime_bounds(self):
        for lifetime, idle, reason in ((2, 0.1, "idle_deadline"), (0.1, 2, "lifetime_deadline")):
            with self.subTest(reason=reason):
                remote, server = self.tls_pair(tickets=2)
                self.assertTrue(transport.select.select([remote], [], [], 1)[0])
                client, local = socket.socketpair()
                began = time.monotonic()
                state, worker = self.relay_thread(local, remote, (client, server), lifetime=lifetime, idle_seconds=idle)
                worker.join(0.6)
                self.assertFalse(worker.is_alive(), "TLS control records defeated the declared close bound")
                self.assertLess(time.monotonic() - began, 0.6)
                self.assertEqual(state.get("result", {}).get("reason"), reason)
                self.assertEqual(state["result"]["bytes"], [0, 0])

    def test_tls_want_write_read_retries_on_write_readiness(self):
        client, local = socket.socketpair()
        remote, peer = socket.socketpair()
        payload = b"plaintext after TLS write readiness"

        class WantWriteSocket:
            buffered = None
            def fileno(inner): return remote.fileno()
            def settimeout(inner, timeout): remote.settimeout(timeout)
            def close(inner): remote.close()
            def sendall(inner, value): remote.sendall(value)
            def recv(inner, size):
                if inner.buffered is None:
                    inner.buffered = remote.recv(size)
                    raise ssl.SSLWantWriteError(ssl.SSL_ERROR_WANT_WRITE, "TLS read requires write readiness")
                if inner.buffered:
                    result, inner.buffered = inner.buffered[:size], inner.buffered[size:]
                    return result
                return remote.recv(size)

        peer.sendall(payload)
        client.settimeout(1.5)
        state, worker = self.relay_thread(local, WantWriteSocket(), (client, peer))
        self.assertEqual(self.exact(client, len(payload)), payload)
        client.shutdown(socket.SHUT_WR)
        worker.join(2)
        self.assertNotIn("error", state)
        self.assertEqual(state["result"]["bytes"], [0, len(payload)])

    def test_repeated_want_write_cannot_evade_idle_or_lifetime_close(self):
        for lifetime, idle, reason in ((2, 0.1, "idle_deadline"), (0.1, 2, "lifetime_deadline")):
            with self.subTest(reason=reason):
                client, local = socket.socketpair()
                remote, peer = socket.socketpair()

                class StillWantsWrite:
                    first = True
                    def fileno(inner): return remote.fileno()
                    def settimeout(inner, timeout): remote.settimeout(timeout)
                    def close(inner): remote.close()
                    def recv(inner, size):
                        if inner.first:
                            remote.recv(size)
                            inner.first = False
                        raise ssl.SSLWantWriteError(ssl.SSL_ERROR_WANT_WRITE, "TLS operation remains write-ready")

                peer.sendall(b"control")
                state, worker = self.relay_thread(local, StillWantsWrite(), (client, peer),
                                                  lifetime=lifetime, idle_seconds=idle)
                worker.join(0.6)
                self.assertFalse(worker.is_alive(), "Repeated WANT_WRITE escaped its close bound")
                self.assertEqual(state.get("result", {}).get("reason"), reason)
                self.assertEqual(state["result"]["bytes"], [0, 0])

    def test_timeout_restoration_does_not_mask_the_original_receive_error(self):
        client, local = socket.socketpair()
        remote, peer = socket.socketpair()
        for connection in (client, local, remote, peer):
            self.addCleanup(connection.close)

        class ResetThenClosed:
            failed = False
            def fileno(inner): return remote.fileno()
            def settimeout(inner, timeout):
                if inner.failed:
                    raise OSError(errno.EBADF, "Concurrent close during timeout restoration")
                remote.settimeout(timeout)
            def recv(inner, size):
                remote.recv(size)
                inner.failed = True
                raise ConnectionResetError("Original receive failure")

        peer.sendall(b"control")
        with self.assertRaises(OSError) as error:
            transport.relay(local, ResetThenClosed(), time.monotonic() + 2)
        self.assertIs(type(error.exception), ConnectionResetError)
        self.assertEqual(getattr(error.exception, "_pqbtc_close_side", None), "public_tls")

    def test_ambiguous_partial_sendall_is_not_replayed_and_logs_only_side_and_class(self):
        client, local = socket.socketpair()
        remote, peer = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(local.close)
        self.addCleanup(remote.close)
        self.addCleanup(peer.close)

        class PartialWrite:
            def fileno(inner): return remote.fileno()
            def settimeout(inner, timeout): remote.settimeout(timeout)
            def recv(inner, size): return remote.recv(size)
            def sendall(inner, value):
                remote.sendall(value[:3])
                raise TimeoutError("uncontrolled private exception text")

        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        output = io.StringIO()
        client.sendall(b"abcdef")
        with transport.Bridge(self.bridge_port(), endpoint, time.monotonic() + 3) as bridge, redirect_stdout(output):
            try:
                transport.relay(local, PartialWrite(), time.monotonic() + 2)
            except TimeoutError:
                bridge.handle_error(local, ("127.0.0.1", 1))
            else:
                self.fail("Ambiguous partial write was accepted")
        remote.shutdown(socket.SHUT_WR)
        self.assertEqual(self.exact(peer, 100), b"abc")
        value = json.loads(output.getvalue())
        self.assertEqual(value.get("close_side"), "public_tls")
        self.assertEqual(value.get("error_class"), "TimeoutError")
        self.assertNotIn("uncontrolled private exception text", output.getvalue())
        self.assertLessEqual(len(value["utc"]), 40)
        self.assertEqual(datetime.fromisoformat(value["utc"]).utcoffset(), timezone.utc.utcoffset(None))
        self.assertIs(type(value["monotonic_ns"]), int)

    def test_connection_events_are_timed_but_initial_readiness_schema_is_unchanged(self):
        remote, server = self.tls_pair()
        client, local = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(local.close)
        client.shutdown(socket.SHUT_WR)
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        readiness = {"event": "bridge_started", "loopback_port": 23834, "hostname": endpoint.hostname,
                     "public_ips": endpoint.addresses, "until_utc": "2026-11-17T00:00:00+00:00"}
        output = io.StringIO()
        with transport.Bridge(self.bridge_port(), endpoint, time.monotonic() + 3) as bridge, redirect_stdout(output):
            bridge.event(readiness)
            self.assertTrue(bridge.verify_request(local, ("127.0.0.1", 1)))
            with mock.patch.object(transport, "open_public_tls", return_value=remote):
                transport.BridgeHandler(local, ("127.0.0.1", 1), bridge)
        values = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(values[0], {**readiness, "public_ips": ["1.1.1.1"]})
        self.assertEqual([v["event"] for v in values[1:]], ["public_tls_connected", "public_tls_disconnected"])
        for value in values[1:]:
            self.assertIs(type(value.get("monotonic_ns")), int)
            self.assertLessEqual(len(value["utc"]), 40)
            self.assertEqual(datetime.fromisoformat(value["utc"]).utcoffset(), timezone.utc.utcoffset(None))
            self.assertIsNone(value["error_class"])
        self.assertEqual(values[-1]["close_side"], "local")

    def bridge_port(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            return reserved.getsockname()[1]

    def test_bridge_restarts_after_an_owned_connection_actively_closes(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        port = self.bridge_port()
        with transport.Bridge(port, endpoint, time.monotonic() + 5) as first:
            first.socket.settimeout(1)
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                accepted, _ = first.socket.accept()
                # The accepted side closes first, leaving this local server
                # port in TIME_WAIT after the client completes its close.
                accepted.close()
                self.assertEqual(client.recv(1), b"")
        with transport.Bridge(port, endpoint, time.monotonic() + 5) as restarted:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                restarted.socket.settimeout(1)
                accepted, address = restarted.socket.accept()
                accepted.close()
                self.assertEqual(address[0], "127.0.0.1")

    def test_bridge_restart_never_replaces_a_live_foreign_listener(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        with socket.socket() as foreign:
            foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            foreign.bind(("127.0.0.1", 0))
            foreign.listen(1)
            port = foreign.getsockname()[1]
            with self.assertRaises(OSError) as refused:
                transport.Bridge(port, endpoint, time.monotonic() + 5)
            self.assertEqual(refused.exception.errno, errno.EADDRINUSE)
            # The attempted replacement did not disturb the original owner.
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                foreign.settimeout(1)
                accepted, _ = foreign.accept()
                accepted.close()

    def test_canonical_native_ipv6_version_addresses_round_trip_losslessly(self):
        sys.path.insert(0, str(PATH.parents[2] / "test/functional"))
        from test_framework.messages import msg_version
        version = msg_version()
        version.nVersion = 70016
        version.strSubVer = "/PQBTC-native-version-control/"
        original = version.serialize()
        for address in (bytes(16), bytes(range(16))):
            raw = original[:28] + address + original[44:54] + address[::-1] + original[70:]
            with self.subTest(address=address.hex()):
                parsed = transport.parse_remote_version(raw)
                self.assertEqual(parsed.serialize(), raw)
                self.assertEqual(parsed.addrTo, raw[20:46])
                self.assertEqual(parsed.addrFrom, raw[46:72])
                self.assertEqual(parsed.nVersion, version.nVersion)
                self.assertEqual(parsed.nServices, version.nServices)
                self.assertEqual(parsed.nTime, version.nTime)
                self.assertEqual(parsed.nNonce, version.nNonce)
                self.assertEqual(parsed.strSubVer, version.strSubVer)
                self.assertEqual(parsed.nStartingHeight, version.nStartingHeight)
                self.assertEqual(parsed.relay, version.relay)

    def test_probe_refuses_unsupported_truncated_or_noncanonical_version(self):
        sys.path.insert(0, str(PATH.parents[2] / "test/functional"))
        from test_framework.messages import msg_version
        version = msg_version()
        version.nVersion = 70016
        version.strSubVer = "/PQBTC-version-control/"
        raw = version.serialize()
        self.assertEqual(transport.parse_remote_version(raw).nVersion, 70016)
        version.nVersion = 0
        bad = [version.serialize(), raw[:72], raw[:-1], raw + b'\x00',
               raw[:80] + b'\xfd' + bytes([raw[80], 0]) + raw[81:]]
        for payload in bad:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                transport.parse_remote_version(payload)

    def test_version_compact_size_boundaries_and_relay_are_strict(self):
        sys.path.insert(0, str(PATH.parents[2] / "test/functional"))
        from test_framework.messages import msg_version
        version = msg_version()
        version.nVersion = 70001
        for size in (0, 1, 252, 253, 256):
            version.strSubVer = "x" * size
            for relay in (0, 1):
                version.relay = relay
                raw = version.serialize()
                with self.subTest(size=size, relay=relay):
                    parsed = transport.parse_remote_version(raw)
                    self.assertEqual(parsed.serialize(), raw)
                    self.assertEqual(parsed.strSubVer, "x" * size)
                    self.assertEqual(parsed.relay, relay)
        version.strSubVer = "abc"
        raw = version.serialize()
        bad = [raw[:-1], raw + b"\0", raw[:-1] + b"\x02", raw[:84],
               raw[:80] + b"\xfd" + struct.pack("<H", 3) + raw[81:],
               raw[:80] + b"\xfe" + struct.pack("<I", 3) + raw[81:],
               raw[:80] + b"\xff" + struct.pack("<Q", 3) + raw[81:]]
        for subversion in ("x" * 257, "control\n", "nul\0", "nonascii\u00e9"):
            version.strSubVer = subversion
            bad.append(version.serialize())
        version.nVersion = 70000
        version.strSubVer = "abc"
        bad.append(version.serialize())
        for payload in bad:
            with self.subTest(payload=payload.hex()), self.assertRaises(ValueError):
                transport.parse_remote_version(payload)

    def probe_exchange(self, hostile=False):
        sys.path.insert(0, str(PATH.parents[2] / "test/functional"))
        from test_framework.messages import msg_version
        import io
        client, peer = socket.socketpair()
        errors = []

        class TLSConnection:
            def __enter__(self): return self
            def __exit__(self, *args): client.close()
            def getpeercert(self, **kwargs): return b"synthetic-unit-test-certificate"
            def getpeername(self): return ("1.1.1.1", 443)
            def version(self): return "TLSv1.3"
            def settimeout(self, value): client.settimeout(value)
            def recv(self, size): return client.recv(size)
            def sendall(self, value): client.sendall(value)

        def native_peer():
            try:
                command, payload = transport.read_frame(peer, time.monotonic() + 2)
                self.assertEqual(command, b"version")
                version = msg_version()
                version.deserialize(io.BytesIO(payload))
                self.assertGreaterEqual(version.nVersion, 70001)
                self.assertEqual(version.strSubVer, "/PQBTC-public-route-probe:1/")
                version.nVersion = 70016
                version.strSubVer = "/PQBTC-native-unit-peer/"
                version.nStartingHeight = 123
                wire = version.serialize()
                # Actual nodes send unspecified IPv6 addrv1 addresses here;
                # the framework serializer only constructs IPv4-mapped ones.
                wire = wire[:28] + bytes(16) + wire[44:54] + bytes(16) + wire[70:]
                peer.sendall(transport.frame(b"version", wire) + transport.frame(b"verack"))
                self.assertEqual(transport.read_frame(peer, time.monotonic() + 2), (b"verack", b""))
                if hostile:
                    header = transport.read_exact(peer, 24, time.monotonic() + 2)
                    self.assertEqual(header[:16], transport.MAGIC + b'block'.ljust(12, b'\0'))
                    self.assertEqual(struct.unpack('<I', header[16:20])[0], transport.MAX_PAYLOAD + 1)
            except Exception as error:
                errors.append(error)
            finally:
                peer.close()

        worker = threading.Thread(target=native_peer, daemon=True)
        worker.start()
        try:
            with mock.patch.object(transport, "open_public_tls", return_value=TLSConnection()):
                result = transport.probe(transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",)),
                                         owned_oversize_control=hostile)
            handshake = result["handshake"] if hostile else result
            self.assertEqual(handshake["remote_subversion"], "/PQBTC-native-unit-peer/")
            self.assertEqual(handshake["remote_height"], 123)
        finally:
            client.close()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        if errors:
            raise errors[0]
        return result

    def test_probe_sends_a_valid_version_and_completes_native_handshake(self):
        self.probe_exchange()

    def test_tls_transient_retry_records_failures_and_uses_original_deadline(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1", "8.8.8.8"))
        clock, failures = [100.0], []
        outcomes = [ConnectionResetError(), ssl.SSLEOFError(), object()]
        with mock.patch.object(transport.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(transport.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
             mock.patch.object(transport, "_connect_verified", side_effect=outcomes) as connect:
            result = transport.open_public_tls(endpoint, timeout=10, retry_transient=True, failures=failures)
        self.assertIs(result, outcomes[-1])
        self.assertEqual(failures, [{"address": "1.1.1.1", "reason": "ConnectionResetError"},
                                    {"address": "8.8.8.8", "reason": "SSLEOFError"}])
        self.assertEqual([c.args[2] for c in connect.call_args_list], ["1.1.1.1", "8.8.8.8", "1.1.1.1"])
        self.assertTrue(all(100 < c.args[3] <= 110 for c in connect.call_args_list))

    def test_tls_security_failures_do_not_retry_or_try_another_ingress(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1", "8.8.8.8"))
        for error in (ssl.SSLCertVerificationError("untrusted"), ssl.SSLError("invalid TLS"), ValueError("wrong peer")):
            with self.subTest(error=type(error)), mock.patch.object(transport, "_connect_verified", side_effect=error) as connect:
                with self.assertRaises(type(error)):
                    transport.open_public_tls(endpoint, retry_transient=True)
                self.assertEqual(connect.call_count, 1)

    def test_unavailable_tls_exhausts_one_budget_and_never_sends_p2p(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        clock = [100.0]
        with mock.patch.object(transport.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(transport.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
             mock.patch.object(transport, "_connect_verified", side_effect=ConnectionRefusedError()) as connect, \
             mock.patch.object(transport, "frame") as frame:
            with self.assertRaisesRegex(ConnectionError, "ConnectionRefusedError"):
                transport.probe(endpoint, timeout=2)
            self.assertGreater(connect.call_count, 1)
            self.assertEqual(clock[0], 102)
            frame.assert_not_called()

    def test_verified_socket_checks_hostname_and_numeric_peer(self):
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        context, connection = mock.MagicMock(), mock.MagicMock()
        context.wrap_socket.return_value = connection
        connection.getpeername.return_value = ("8.8.8.8", 443)
        with mock.patch.object(transport.socket, "create_connection") as create:
            with self.assertRaisesRegex(ValueError, "peer differs"):
                transport._connect_verified(context, endpoint, "1.1.1.1", time.monotonic() + 10)
        context.wrap_socket.assert_called_once_with(create.return_value.__enter__.return_value, server_hostname=endpoint.hostname)
        connection.close.assert_called_once()

    def test_owned_oversized_header_control_observes_native_disconnect(self):
        result = self.probe_exchange(hostile=True)
        self.assertTrue(result["disconnect_observed"])
        self.assertFalse(result["invalid_accepted"])
        self.assertEqual(result["sent_bytes"], 24)
        self.assertEqual(result["scope"], "BOUNDED_PUBLIC_P2P_OVERSIZED_HEADER_CONTROL")

    def test_public_endpoint_refuses_overlay_and_private_routes(self):
        for address in ("127.0.0.1", "100.79.33.18", "10.150.150.95", "::1", "fc00::1",
                        "192.0.2.1", "224.0.0.1", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                transport.PublicEndpoint("public.example.org", 443, (address,))
        endpoint = transport.PublicEndpoint("public.example.org", 443, ("1.1.1.1",))
        self.assertEqual(endpoint.addresses, ("1.1.1.1",))

    def test_endpoint_requires_tls_port_and_dns_name(self):
        for hostname, port in (("localhost", 443), ("-invalid.example", 443),
                               ("bad..example", 443), ("public.example.org", 23833)):
            with self.subTest(hostname=hostname, port=port), self.assertRaises(ValueError):
                transport.PublicEndpoint(hostname, port, ("1.1.1.1",))

    def parse(self, raw):
        left, right = socket.socketpair()
        try:
            left.sendall(raw)
            left.shutdown(socket.SHUT_WR)
            return transport.read_frame(right, time.monotonic() + 2)
        finally:
            left.close()
            right.close()

    def test_native_handshake_frame_checksum_and_network(self):
        raw = transport.frame(b"ping", bytes(8))
        self.assertEqual(self.parse(raw), (b"ping", bytes(8)))
        for changed in (b"nope" + raw[4:], raw[:20] + b"nope" + raw[24:],
                        raw[:16] + struct.pack("<I", transport.MAX_PAYLOAD + 1) + raw[20:24],
                        raw[:-1]):
            with self.assertRaises(ValueError):
                self.parse(changed)

    def test_actual_bidirectional_relay_and_eof(self):
        client, local = socket.socketpair()
        remote, peer = socket.socketpair()
        result = []
        worker = threading.Thread(target=lambda: result.append(transport.relay(
            local, remote, time.monotonic() + 5)), daemon=True)
        worker.start()
        try:
            client.settimeout(2)
            peer.settimeout(2)
            outbound = transport.frame(b"version", b"synthetic-public-handshake")
            client.sendall(outbound)
            self.assertEqual(peer.recv(4096), outbound)
            inbound = transport.frame(b"verack")
            peer.sendall(inbound)
            self.assertEqual(client.recv(4096), inbound)
            client.shutdown(socket.SHUT_WR)
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [{"reason": "peer_closed", "bytes": [len(outbound), len(inbound)], "close_side": "local"}])
        finally:
            for connection in (client, local, remote, peer):
                connection.close()

    def test_relay_byte_bound_and_idle_deadline(self):
        client, local = socket.socketpair()
        remote, peer = socket.socketpair()
        try:
            client.sendall(b"too much data")
            with self.assertRaisesRegex(ValueError, "byte bound"):
                transport.relay(local, remote, time.monotonic() + 2, byte_limit=3)
            self.assertEqual(transport.relay(local, remote, time.monotonic() + 2, idle_seconds=0),
                             {"reason": "idle_deadline", "bytes": [0, 0], "close_side": "bridge"})
        finally:
            for connection in (client, local, remote, peer):
                connection.close()


if __name__ == "__main__":
    unittest.main()
