#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Bounded private INV-loss and zero-peer gate; no wallet material is handled."""
import argparse
import collections
import hashlib
import json
import ipaddress
import os
import selectors
import socket
import stat
import struct
import time

MAGIC = bytes.fromhex("a7e29cf7")
MAX_PAYLOAD = 4 * 1024 * 1024
MAX_BUFFER = MAX_PAYLOAD + 24 + 65536
MAX_QUEUE = 2 * MAX_BUFFER
CONTROL_LIMIT = 512


def check(condition, label):
    if not condition:
        raise ValueError(label)


def checksum(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]


def inventory(payload):
    check(bool(payload), "INV_COUNT")
    lead = payload[0]
    size = 1 if lead < 253 else {253: 3, 254: 5, 255: 9}[lead]
    check(len(payload) >= size, "INV_COUNT")
    count = lead if size == 1 else int.from_bytes(payload[1:size], "little")
    check(size == 1 or count >= {3: 253, 5: 65536, 9: 4294967296}[size], "INV_NONCANONICAL")
    check(count <= 50000 and len(payload) == size + count * 36, "INV_LENGTH")
    return [(struct.unpack_from("<I", payload, size + i * 36)[0],
             payload[size + i * 36 + 4:size + (i + 1) * 36][::-1].hex()) for i in range(count)]


class Framer:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        check(len(self.buffer) + len(data) <= MAX_BUFFER, "FRAME_BUFFER_BOUND")
        self.buffer.extend(data)
        frames = []
        while len(self.buffer) >= 24:
            header = self.buffer[:24]
            check(header[:4] == MAGIC, "FRAME_MAGIC")
            command = bytes(header[4:16])
            bare = command.rstrip(b"\0")
            check(bare and b"\0" not in bare and all(32 <= b <= 126 for b in bare), "FRAME_COMMAND")
            length = struct.unpack_from("<I", header, 16)[0]
            check(length <= MAX_PAYLOAD, "FRAME_PAYLOAD_BOUND")
            if len(self.buffer) < 24 + length:
                break
            frame = bytes(self.buffer[:24 + length])
            del self.buffer[:24 + length]
            payload = frame[24:]
            check(checksum(payload) == header[20:24], "FRAME_CHECKSUM")
            frames.append((bare.decode("ascii"), payload, frame))
        return frames


class DropOnce:
    def __init__(self):
        self.armed = False
        self.ever_armed = False
        self.dropped = []
        self.counts = collections.Counter()

    def arm(self):
        check(not self.ever_armed, "CONTROL_ALREADY_ARMED")
        self.armed = self.ever_armed = True

    def forward(self, direction, command, payload):
        key = direction + ":" + command
        check(key in self.counts or len(self.counts) < 128, "PROXY_COMMAND_COUNT_BOUND")
        self.counts[key] += 1
        entries = inventory(payload) if command == "inv" else []
        if direction == "sender_to_receiver" and self.armed and len(entries) == 1 and entries[0][0] in (1, 5):
            self.dropped.append({"type": entries[0][0], "hash": entries[0][1], "monotonic_ns": time.monotonic_ns()})
            self.armed = False
            return False
        return True

    def status(self):
        return {"armed": self.armed, "ever_armed": self.ever_armed, "dropped": self.dropped,
                "message_counts": dict(self.counts)}


class PreissuanceGate:
    def __init__(self):
        self.mode, self.releases, self.rejected = "framed", 0, 0

    def hold(self, drop, connections):
        check(self.mode == "framed" and connections == 2 and drop.ever_armed and
              not drop.armed and len(drop.dropped) == 1, "CONTROL_HOLD_ORDER")
        self.mode = "held"

    def release(self, active):
        check(self.mode == "held" and active == 0 and self.releases == 0, "CONTROL_RELEASE_ORDER")
        self.mode, self.releases = "opaque", 1

    def accept(self, connections):
        if self.mode == "held":
            check(self.rejected < 32, "PROXY_HELD_ATTEMPT_BOUND")
            self.rejected += 1
            return False
        check(connections < (2 if self.mode == "framed" else 3), "PROXY_EXTRA_CONNECTION")
        return True

    def status(self):
        return {"mode": self.mode, "release_count": self.releases, "held_rejections": self.rejected}


def parse_control(raw):
    check(len(raw) <= CONTROL_LIMIT and raw.endswith(b"\n"), "CONTROL_BOUND")
    def pairs(items):
        check(len(dict(items)) == len(items), "CONTROL_DUPLICATE")
        return dict(items)
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("CONTROL_JSON") from None
    check(type(value) is dict and set(value) == {"op"} and value["op"] in ("status", "arm", "hold", "release", "stop"), "CONTROL_OPERATION")
    return value["op"]


def control_permissions(path):
    value = os.lstat(path)
    check(stat.S_ISSOCK(value.st_mode) and value.st_uid == os.geteuid() and
          stat.S_IMODE(value.st_mode) == 0o600, "CONTROL_OWNERSHIP")


def serve(path, upstream, *, listen_port=23834):
    address = ipaddress.IPv4Address(upstream)
    check(address.is_private and not address.is_unspecified and not address.is_multicast and
          not address.is_link_local, "PROXY_PRIVATE_UPSTREAM")
    check(type(listen_port) is int and 1024 <= listen_port <= 65535, "PROXY_LISTEN_PORT")
    check(not os.path.lexists(path), "PROXY_OWNERSHIP")
    os.umask(0o077)
    selector = selectors.DefaultSelector()
    listener = socket.socket()
    control = socket.socket(socket.AF_UNIX)
    control_bound = False
    drop, peers, connections, stopped = DropOnce(), {}, 0, False
    gate = PreissuanceGate()
    deadline = time.monotonic() + 590
    pending, pending_deadline = None, None

    def close_pair():
        for sock in list(peers):
            try:
                selector.unregister(sock)
            except KeyError:
                pass
            sock.close()
        peers.clear()

    def activate(client):
        nonlocal connections
        try:
            target = socket.create_connection((str(address), 23833), timeout=2)
        except BaseException:
            client.close()
            raise
        connections += 1
        for sock, other, direction in ((client, target, "sender_to_receiver"), (target, client, "receiver_to_sender")):
            sock.setblocking(False)
            peers[sock] = {"other": other, "direction": direction, "framer": Framer(), "queue": bytearray()}
            selector.register(sock, selectors.EVENT_READ, peers[sock])

    def close_pending():
        nonlocal pending, pending_deadline
        if pending is not None:
            pending.close()
            pending, pending_deadline = None, None

    def update(sock):
        state = peers[sock]
        events = (selectors.EVENT_READ if len(peers[state["other"]]["queue"]) < MAX_BUFFER else 0)
        if state["queue"]:
            events |= selectors.EVENT_WRITE
        # Queue throttling can only suppress reads while the opposite queue has writes.
        if events:
            selector.modify(sock, events, state)
        else:
            selector.unregister(sock)

    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        listener.setblocking(False)
        control.bind(path)
        control_bound = True
        # Unix sockets begin at 0777 masked by umask, which leaves 0700 here.
        os.chmod(path, 0o600)
        control.listen(1)
        control.setblocking(False)
        control_permissions(path)
        selector.register(listener, selectors.EVENT_READ, "listen")
        selector.register(control, selectors.EVENT_READ, "control")
        while not stopped:
            check(time.monotonic() < deadline, "PROXY_DEADLINE")
            check(pending is None or time.monotonic() < pending_deadline, "PROXY_HANDOFF_DEADLINE")
            for key, mask in selector.select(0.2):
                if key.data == "control":
                    client, _ = control.accept()
                    with client:
                        client.settimeout(1)
                        raw = bytearray()
                        while b"\n" not in raw and len(raw) <= CONTROL_LIMIT:
                            data = client.recv(CONTROL_LIMIT + 1 - len(raw))
                            if not data:
                                break
                            raw.extend(data)
                        try:
                            op = parse_control(bytes(raw))
                            if op == "arm":
                                check(gate.mode == "framed" and len(peers) == 2, "CONTROL_NO_CONNECTION")
                                drop.arm()
                            elif op == "hold":
                                gate.hold(drop, connections)
                                close_pair()
                                close_pending()
                            elif op == "release":
                                gate.release(len(peers) // 2 + int(pending is not None))
                            stopped = op == "stop"
                            if stopped:
                                close_pair()
                                close_pending()
                            result = {"ok": True, **drop.status(), **gate.status(), "connections": connections,
                                      "active_connections": len(peers) // 2 + int(pending is not None)}
                        except ValueError:
                            result = {"ok": False, "error": "CONTROL_REFUSED"}
                        client.sendall(json.dumps(result, sort_keys=True).encode() + b"\n")
                elif key.data == "listen":
                    client, _ = listener.accept()
                    try:
                        if not gate.accept(connections):
                            client.close()
                            continue
                        check(pending is None, "PROXY_EXTRA_CONNECTION")
                    except BaseException:
                        client.close()
                        raise
                    if peers:
                        # A replacement may be accepted before the selector
                        # delivers the old socket's EOF. Buffer nothing here:
                        # one pending socket retains TCP backpressure until EOF.
                        pending, pending_deadline = client, time.monotonic() + 2
                    else:
                        activate(client)
                else:
                    sock = key.fileobj
                    if sock not in peers:
                        continue
                    state = peers[sock]
                    if mask & selectors.EVENT_WRITE:
                        try:
                            sent = sock.send(state["queue"])
                        except (BrokenPipeError, ConnectionResetError):
                            close_pair()
                            continue
                        del state["queue"][:sent]
                    if mask & selectors.EVENT_READ:
                        try:
                            data = sock.recv(65536)
                        except ConnectionResetError:
                            close_pair()
                            continue
                        if not data:
                            close_pair()
                            continue
                        frames = ([(None, None, data)] if gate.mode == "opaque" else state["framer"].feed(data))
                        for command, payload, frame in frames:
                            if gate.mode == "opaque" or drop.forward(state["direction"], command, payload):
                                queue = peers[state["other"]]["queue"]
                                check(len(queue) + len(frame) <= MAX_QUEUE, "PROXY_QUEUE_BOUND")
                                queue.extend(frame)
                    for item in list(peers):
                        # Re-register an endpoint paused by queue backpressure.
                        if item not in selector.get_map():
                            selector.register(item, selectors.EVENT_READ, peers[item])
                        update(item)
            if not stopped and not peers and pending is not None:
                client, pending, pending_deadline = pending, None, None
                activate(client)
    finally:
        close_pending()
        close_pair()
        listener.close()
        control.close()
        selector.close()
        if control_bound and os.path.lexists(path):
            control_permissions(path)
            os.unlink(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", required=True)
    parser.add_argument("--upstream", required=True)
    args = parser.parse_args()
    try:
        check(os.geteuid() == 1001, "PROXY_UID")
        serve(args.control, args.upstream)
    except Exception:
        print('{"ok":false,"error":"PROXY_FAILED"}', flush=True)
        raise SystemExit(1)
