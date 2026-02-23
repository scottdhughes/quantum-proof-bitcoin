#!/usr/bin/env python3
"""Reference-model PQSig v1 helper for vectors and tooling."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

ALG_ID = 0x00
PK_SCRIPT_SIZE = 33
PK_CORE_SIZE = 32
MSG32_SIZE = 32
SIG_SIZE = 4480

N = 16
H = 44
D = 4
HT_HEIGHT = H // D
A = 16
K = 8
W = 16
L = 32
SWN = 240
PORS_MMAX = 97

SIG_R_SIZE = 32
PORS_REVEAL_SIZE = K * N
PORS_AUTH_PAD_SIZE = PORS_MMAX * N
HT_AUTH_SIZE = HT_HEIGHT * N
HT_WOTS_SIZE = L * N
HT_COUNTER_SIZE = 4
HT_LAYER_SIZE = HT_AUTH_SIZE + HT_WOTS_SIZE + HT_COUNTER_SIZE

PORS_REVEAL_OFFSET = SIG_R_SIZE
PORS_AUTH_OFFSET = PORS_REVEAL_OFFSET + PORS_REVEAL_SIZE
HT_OFFSET = PORS_AUTH_OFFSET + PORS_AUTH_PAD_SIZE


def _hash32(domain: str, *parts: bytes) -> bytes:
    d = domain.encode("utf-8")
    d = d[:255]
    h = hashlib.sha256()
    h.update(bytes([len(d)]))
    h.update(d)
    for p in parts:
        h.update(p)
    return h.digest()


def _hash64(domain: str, *parts: bytes) -> bytes:
    d = domain.encode("utf-8")
    d = d[:255]
    h = hashlib.sha512()
    h.update(bytes([len(d)]))
    h.update(d)
    for p in parts:
        h.update(p)
    return h.digest()


def _hashn(domain: str, *parts: bytes) -> bytes:
    return _hash32(domain, *parts)[:N]


def _u16le(v: int) -> bytes:
    return int(v).to_bytes(2, "little", signed=False)


def _u32le(v: int) -> bytes:
    return int(v).to_bytes(4, "little", signed=False)


def derive_pk_seed(sk_seed: bytes) -> bytes:
    return _hashn("PQSIG-PK-SEED", sk_seed)


def derive_pk_root(pk_seed: bytes) -> bytes:
    return _hashn("PQSIG-PK-ROOT", pk_seed)


def derive_pk_script(sk_seed: bytes) -> bytes:
    pk_seed = derive_pk_seed(sk_seed)
    pk_root = derive_pk_root(pk_seed)
    return bytes([ALG_ID]) + pk_seed + pk_root


def parse_pk_script(pk_script33: bytes) -> tuple[bytes, bytes] | None:
    if len(pk_script33) != PK_SCRIPT_SIZE or pk_script33[0] != ALG_ID:
        return None
    pk_seed = pk_script33[1:17]
    pk_root = pk_script33[17:33]
    if pk_root != derive_pk_root(pk_seed):
        return None
    return pk_seed, pk_root


def _derive_pors_indices(hmsg: bytes) -> list[int]:
    mask = (1 << A) - 1
    out: list[int] = []
    for i in range(K):
        raw = int.from_bytes(hmsg[i * 2 : i * 2 + 2], "little")
        out.append(raw & mask)
    return out


def _derive_layer_counts(hmsg: bytes) -> list[int]:
    out: list[int] = []
    for i in range(D):
        raw = int.from_bytes(hmsg[32 + i * 4 : 32 + (i + 1) * 4], "little")
        out.append(raw % (SWN + 1))
    return out


def _derive_leaf_indices(hmsg: bytes) -> list[int]:
    mask = (1 << HT_HEIGHT) - 1
    out: list[int] = []
    for i in range(D):
        raw = int.from_bytes(hmsg[48 + i * 2 : 48 + (i + 1) * 2], "little")
        out.append(raw & mask)
    return out


def _fill_reveals(sk_seed: bytes, r: bytes, indices: list[int]) -> bytes:
    out = bytearray(PORS_REVEAL_SIZE)
    for i, idx in enumerate(indices):
        chunk = _hashn("PQSIG-PORS-REVEAL", sk_seed, r, _u16le(idx), _u32le(i))
        out[i * N : (i + 1) * N] = chunk
    return bytes(out)


def _fill_auth_pad(sk_seed: bytes, r: bytes, hmsg: bytes) -> bytes:
    out = bytearray(PORS_AUTH_PAD_SIZE)
    chunks = PORS_AUTH_PAD_SIZE // N
    for i in range(chunks):
        chunk = _hashn("PQSIG-OCTO-CHUNK", sk_seed, r, hmsg, _u32le(i))
        out[i * N : (i + 1) * N] = chunk
    return bytes(out)


def _fold_auth_pad(auth_pad: bytes, indices: list[int]) -> bytes:
    acc = _hashn("PQSIG-OCTO-INIT", auth_pad)
    chunks = len(auth_pad) // N
    for i in range(chunks):
        chunk = auth_pad[i * N : (i + 1) * N]
        acc = _hashn("PQSIG-OCTO-FOLD", acc, chunk, _u16le(indices[i % K]), _u32le(i))
    return acc


def _compute_pors_root(reveals: bytes, auth_pad: bytes, indices: list[int], r: bytes, msg32: bytes, pk_seed: bytes) -> bytes:
    packed_idx = b"".join(_u16le(i) for i in indices)
    mix = _hashn("PQSIG-PORS-MIX", reveals, auth_pad, packed_idx, r, msg32, pk_seed)
    octo = _fold_auth_pad(auth_pad, indices)
    return _hashn("PQSIG-PORS-ROOT", mix, octo)


def _message_nibble(msg16: bytes, n: int) -> int:
    b = msg16[n // 2]
    return (b >> 4) if (n & 1) == 0 else (b & 0x0F)


def _fill_wots_sig(sk_seed: bytes, pk_seed: bytes, msg16: bytes, layer: int, count: int, r: bytes) -> bytes:
    out = bytearray(HT_WOTS_SIZE)
    for i in range(L):
        nib = _message_nibble(msg16, i)
        tweak = (nib + (count % W) + i) & 0x0F
        chunk = _hashn(
            "PQSIG-WOTS-SIG",
            sk_seed,
            pk_seed,
            r,
            msg16,
            _u32le(layer),
            _u32le(count),
            _u32le(i),
            bytes([tweak]),
        )
        out[i * N : (i + 1) * N] = chunk
    return bytes(out)


def _wots_commit(wots_sig: bytes, msg16: bytes, layer: int, count: int, r: bytes, pk_seed: bytes) -> bytes:
    return _hashn("PQSIG-WOTS-COMMIT", wots_sig, msg16, _u32le(layer), _u32le(count), r, pk_seed)


def _fill_auth_path(sk_seed: bytes, pk_seed: bytes, msg16: bytes, layer: int, leaf_index: int, r: bytes) -> bytes:
    out = bytearray(HT_AUTH_SIZE)
    for depth in range(HT_HEIGHT):
        node = _hashn(
            "PQSIG-HT-AUTH",
            sk_seed,
            pk_seed,
            msg16,
            _u32le(layer),
            _u16le(leaf_index),
            _u32le(depth),
            r,
        )
        out[depth * N : (depth + 1) * N] = node
    return bytes(out)


def _compute_layer_root(msg16: bytes, wots_sig: bytes, auth_path: bytes, layer: int, leaf_index: int, count: int, r: bytes, pk_seed: bytes) -> bytes:
    node = _hashn("PQSIG-HT-LEAF", _wots_commit(wots_sig, msg16, layer, count, r, pk_seed), _u32le(layer), _u16le(leaf_index), _u32le(count))
    for depth in range(HT_HEIGHT):
        sibling = auth_path[depth * N : (depth + 1) * N]
        odd = ((leaf_index >> depth) & 1) != 0
        left, right = (sibling, node) if odd else (node, sibling)
        node = _hashn("PQSIG-HT-NODE", _u32le(layer), _u32le(depth), left, right, _u32le(count))
    return node


def pqsig_sign(msg32: bytes, sk_seed: bytes, pk_script33: bytes, max_counter: int = 1048576) -> bytes:
    if len(msg32) != MSG32_SIZE:
        raise ValueError("msg32 must be exactly 32 bytes")
    parsed = parse_pk_script(pk_script33)
    if parsed is None:
        raise ValueError("pk_script33 must be 33 bytes, ALG_ID=0x00, and have a valid PK_root")
    if not sk_seed:
        raise ValueError("sk_seed must not be empty")

    pk_seed, pk_root = parsed
    if derive_pk_seed(sk_seed) != pk_seed:
        raise ValueError("sk_seed does not match pk_script33")

    for counter in range(max_counter):
        r = _hash32("PQSIG-PRFMSG", sk_seed, msg32, pk_script33, _u32le(counter))
        hmsg = _hash64("PQSIG-HMSG", r, msg32, pk_script33)
        pors_indices = _derive_pors_indices(hmsg)
        layer_counts = _derive_layer_counts(hmsg)
        leaf_indices = _derive_leaf_indices(hmsg)

        reveals = _fill_reveals(sk_seed, r, pors_indices)
        auth_pad = _fill_auth_pad(sk_seed, r, hmsg)
        layer_msg = _compute_pors_root(reveals, auth_pad, pors_indices, r, msg32, pk_seed)

        sig = bytearray(SIG_SIZE)
        sig[0:32] = r
        sig[PORS_REVEAL_OFFSET:PORS_REVEAL_OFFSET + PORS_REVEAL_SIZE] = reveals
        sig[PORS_AUTH_OFFSET:PORS_AUTH_OFFSET + PORS_AUTH_PAD_SIZE] = auth_pad

        for layer in range(D):
            layer_offset = HT_OFFSET + layer * HT_LAYER_SIZE
            wots = _fill_wots_sig(sk_seed, pk_seed, layer_msg, layer, layer_counts[layer], r)
            auth = _fill_auth_path(sk_seed, pk_seed, layer_msg, layer, leaf_indices[layer], r)
            sig[layer_offset : layer_offset + HT_AUTH_SIZE] = auth
            sig[layer_offset + HT_AUTH_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE] = wots
            sig[layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE + 4] = _u32le(layer_counts[layer])
            layer_msg = _compute_layer_root(layer_msg, wots, auth, layer, leaf_indices[layer], layer_counts[layer], r, pk_seed)

        final_digest = _hashn("PQSIG-FINAL", layer_msg, r, msg32, pk_script33)
        if final_digest[0] == pk_root[0]:
            return bytes(sig)

    raise RuntimeError(f"failed to find grinding counter within max_counter={max_counter}")


def pqsig_verify(sig4480: bytes, msg32: bytes, pk_script33: bytes) -> bool:
    if len(sig4480) != SIG_SIZE or len(msg32) != MSG32_SIZE:
        return False

    parsed = parse_pk_script(pk_script33)
    if parsed is None:
        return False
    pk_seed, pk_root = parsed

    r = sig4480[0:32]
    reveals = sig4480[PORS_REVEAL_OFFSET:PORS_REVEAL_OFFSET + PORS_REVEAL_SIZE]
    auth_pad = sig4480[PORS_AUTH_OFFSET:PORS_AUTH_OFFSET + PORS_AUTH_PAD_SIZE]

    hmsg = _hash64("PQSIG-HMSG", r, msg32, pk_script33)
    pors_indices = _derive_pors_indices(hmsg)
    layer_counts = _derive_layer_counts(hmsg)
    leaf_indices = _derive_leaf_indices(hmsg)

    layer_msg = _compute_pors_root(reveals, auth_pad, pors_indices, r, msg32, pk_seed)

    for layer in range(D):
        layer_offset = HT_OFFSET + layer * HT_LAYER_SIZE
        auth = sig4480[layer_offset : layer_offset + HT_AUTH_SIZE]
        wots = sig4480[layer_offset + HT_AUTH_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE]
        count = int.from_bytes(sig4480[layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE + 4], "little")
        if count != layer_counts[layer] or count > SWN:
            return False
        layer_msg = _compute_layer_root(layer_msg, wots, auth, layer, leaf_indices[layer], count, r, pk_seed)

    final_digest = _hashn("PQSIG-FINAL", layer_msg, r, msg32, pk_script33)
    return final_digest[0] == pk_root[0]


def generate_default_kat() -> dict[str, str]:
    sk_seed = bytes.fromhex("1f" * 32)
    msg32 = bytes.fromhex("42" * 32)
    pk_script33 = derive_pk_script(sk_seed)
    sig = pqsig_sign(msg32, sk_seed, pk_script33)
    return {
        "name": "kat_default",
        "msg32": msg32.hex(),
        "sk_seed": sk_seed.hex(),
        "pk_script33": pk_script33.hex(),
        "sig4480": sig.hex(),
    }


@dataclass
class Envelope:
    verify_compressions: int = 1292
    sign_hashes: int = 6027717
    sign_compressions: int = 6869634
    outer_search_iters: int = 244170


ENVELOPE = Envelope()
