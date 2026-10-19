#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""PUBLIC FIXTURE ONLY. Independent libgcrypt AES-GCM + hashlib.scrypt oracle.

Run only in the contained Linux proof, never for user secrets. Importing this
module is data-only; native libgcrypt is loaded only by explicit oracle calls.
Official API: https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-cipher-handles.html
"""

import ctypes
import ctypes.util
import hashlib
import struct
import sys


def gcm(key, nonce, aad, plaintext):
    if sys.platform != "linux":
        raise RuntimeError("reference oracle requires contained Linux")
    name = ctypes.util.find_library("gcrypt")
    if not name:
        raise RuntimeError("independent libgcrypt oracle missing")
    lib = ctypes.CDLL(name)
    lib.gcry_check_version.argtypes = [ctypes.c_char_p]
    lib.gcry_check_version.restype = ctypes.c_char_p
    version = lib.gcry_check_version(None).decode()
    ptr, size = ctypes.c_void_p, ctypes.c_size_t
    lib.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]
    lib.gcry_cipher_map_name.restype = ctypes.c_int
    lib.gcry_cipher_open.argtypes = [
        ctypes.POINTER(ptr),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.gcry_cipher_close.argtypes = [ptr]
    lib.gcry_cipher_close.restype = None
    for function in (
        "gcry_cipher_setkey",
        "gcry_cipher_setiv",
        "gcry_cipher_authenticate",
        "gcry_cipher_gettag",
    ):
        getattr(lib, function).argtypes = [ptr, ptr, size]
        getattr(lib, function).restype = ctypes.c_uint
    lib.gcry_cipher_encrypt.argtypes = [ptr, ptr, size, ptr, size]
    lib.gcry_cipher_encrypt.restype = ctypes.c_uint
    handle = ptr()
    if lib.gcry_cipher_open(
        ctypes.byref(handle), lib.gcry_cipher_map_name(b"AES256"), 9, 0
    ):
        raise RuntimeError("reference cipher open failed")
    try:
        for function, data in (
            ("gcry_cipher_setkey", key),
            ("gcry_cipher_setiv", nonce),
            ("gcry_cipher_authenticate", aad),
        ):
            if getattr(lib, function)(handle, data, len(data)):
                raise RuntimeError("reference cipher setup failed")
        output, tag = (
            ctypes.create_string_buffer(len(plaintext)),
            ctypes.create_string_buffer(16),
        )
        if lib.gcry_cipher_encrypt(
            handle, output, len(plaintext), plaintext, len(plaintext)
        ) or lib.gcry_cipher_gettag(handle, tag, 16):
            raise RuntimeError("reference encryption failed")
        return output.raw + tag.raw, version
    finally:
        lib.gcry_cipher_close(handle)


def fixture():
    # Literal published primitive KATs, independently of our production codec.
    kat = hashlib.scrypt(b"", salt=b"", n=16, r=1, p=1, dklen=64)
    if (
        kat.hex()
        != "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    ):
        raise RuntimeError("RFC7914 scrypt KAT failed")
    kat, version = gcm(bytes(32), bytes(12), b"", bytes(16))
    if kat.hex() != "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919":
        raise RuntimeError("AES256-GCM primitive KAT failed")
    domain = hashlib.sha256(b"PQBTC-ZERO-VALUE-PILOT-v1").digest()
    salt, nonce = bytes(range(1, 17)), bytes(range(17, 29))
    header = (
        b"PQBWLT1\0"
        + struct.pack(">HHHH", 1, 96, 1, 0)
        + domain
        + salt
        + nonce
        + struct.pack(">IIIII", 64, 131072, 8, 1, 0)
    )
    key = hashlib.scrypt(
        b"public synthetic backup password",
        salt=salt,
        n=131072,
        r=8,
        p=1,
        maxmem=160 * 1024 * 1024,
        dklen=32,
    )
    plaintext = bytes.fromhex(
        "d71361c000f9a7bc99dfb425bcb6bb27c32c36ab444ff3708b2d93b4e66d5b5b451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34"
    )
    encrypted, _ = gcm(key, nonce, header, plaintext)
    return header + encrypted, version


if __name__ == "__main__":
    package, _ = fixture()
    print(package.hex())
