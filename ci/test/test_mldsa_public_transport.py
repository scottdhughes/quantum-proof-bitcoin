"""Bounds and actual byte forwarding for the explicit public P2P adapter."""
import importlib.util
from pathlib import Path
import socket
import struct
import sys
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
            self.assertEqual(result, [{"reason": "peer_closed", "bytes": [len(outbound), len(inbound)]}])
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
                             {"reason": "idle_deadline", "bytes": [0, 0]})
        finally:
            for connection in (client, local, remote, peer):
                connection.close()


if __name__ == "__main__":
    unittest.main()
