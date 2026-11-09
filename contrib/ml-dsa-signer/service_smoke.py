#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Run INSIDE contained Linux under configured client UID; PUBLIC socket controls."""
import array
import json
import os
import socket
import struct
import sys
import time

socket_path, uid, spec_hex, role = sys.argv[1:]
expected_uid = int(uid)
checks = 0
def check(value):
    global checks
    if not value:
        raise AssertionError('service fixture assertion')
    checks += 1
def connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(7)
    s.connect(socket_path)
    peer = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    check(peer[1] == expected_uid)
    return s
def frame(kind, identity, body=b''):
    return b'PQMSIPC1' + struct.pack('<HBB', 1, kind, 0) + identity.to_bytes(16,'little') + len(body).to_bytes(4,'little') + body
def exact(s, size):
    value = b''
    while len(value) < size:
        block = s.recv(size-len(value))
        if not block:
            raise ConnectionError('closed response')
        value += block
    return value
def response(s, kind, identity):
    h = exact(s,32)
    check(h[:12] == b'PQMSIPC1' + struct.pack('<HBB',1,kind|128,0))
    check(h[12:28] == identity.to_bytes(16,'little'))
    length = int.from_bytes(h[28:32],'little')
    check(2 <= length <= 1048576)
    body = exact(s,length)
    status = int.from_bytes(body[:2],'little')
    check(status <= 13 and (status == 0 or len(body) == 2))
    return status, body[2:]
def closed(s):
    try:
        check(s.recv(1) == b'')
    except (ConnectionResetError, BrokenPipeError):
        check(True)
def hello(s, identity=1):
    # Frozen target regtest B, not inherited active node parameters.
    b = bytes.fromhex('96bd879ee215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36') + bytes.fromhex(spec_hex)
    s.sendall(frame(1,identity,b))
    check(response(s,1,identity) == (0,b))

if role == 'unauthorized':
    with connect() as s:
        try:
            s.sendall(frame(5,1))
        except (BrokenPipeError, ConnectionResetError):
            pass
        closed(s)
elif role == 'controls':
    for bad in [frame(133,1), b'X' + frame(5,1)[1:], frame(5,0), frame(5,1)[:11] + b'\x01' + frame(5,1)[12:],
                frame(5,1)[:28] + (1048577).to_bytes(4,'little')]:
        with connect() as s:
            s.sendall(bad)
            closed(s)
    with connect() as s:
        s.sendall(frame(5,1))
        check(response(s,5,1)[0] == 4)
        hello(s,2)
        s.sendall(frame(5,2))
        check(response(s,5,2)[0] == 8)
    with connect() as s:
        hello(s)
        fd = os.open('/dev/null',os.O_RDONLY)
        try:
            s.sendmsg([frame(5,2)], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            closed(s)
        finally:
            os.close(fd)
    with connect() as s:
        s.sendall(b'PQ')
        started = time.monotonic()
        closed(s)
        check(4 <= time.monotonic() - started <= 7)
    with connect() as s:
        hello(s)
        for identity in range(2,65):
            s.sendall(frame(5,identity))
            check(response(s,5,identity)[0] == 0)
        closed(s)
else:
    raise AssertionError('unknown fixture role')
print(json.dumps({'result':'PASS','role':role,'checks':checks,'client_uid':os.geteuid(),'server_uid':expected_uid}))
