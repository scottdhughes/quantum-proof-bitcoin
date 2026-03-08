#!/usr/bin/env python3
"""Reference-model PQSig rc2 helper for vectors and tooling."""

from __future__ import annotations

import functools
import hashlib

ALG_ID = 0x01
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


def _derive_pors_indices(hmsg: bytes) -> list[int]:
    mask = (1 << A) - 1
    out: list[int] = []
    for i in range(K):
        raw = int.from_bytes(hmsg[i * 2 : i * 2 + 2], "little")
        out.append(raw & mask)
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


@functools.lru_cache(maxsize=128)
def _wots_secret_chunk(sk_seed: bytes, pk_seed: bytes, layer: int, leaf_index: int, chunk_index: int) -> bytes:
    return _hashn("PQSIG-WOTS-SECRET", sk_seed, pk_seed, _u32le(layer), _u16le(leaf_index), _u32le(chunk_index))


def _wots_step(node: bytes, pk_seed: bytes, layer: int, leaf_index: int, chunk_index: int, step: int) -> bytes:
    return _hashn("PQSIG-WOTS-STEP", node, pk_seed, _u32le(layer), _u16le(leaf_index), _u32le(chunk_index), _u32le(step))


def _advance_chain(node: bytes, pk_seed: bytes, layer: int, leaf_index: int, chunk_index: int, start_step: int, steps: int) -> bytes:
    out = node
    for step in range(start_step, start_step + steps):
        out = _wots_step(out, pk_seed, layer, leaf_index, chunk_index, step)
    return out


def _commit_public_chunks(public_chunks: bytes, pk_seed: bytes, layer: int, leaf_index: int) -> bytes:
    return _hashn("PQSIG-WOTS-PK", public_chunks, _u32le(layer), _u16le(leaf_index), pk_seed)


def _fill_wots_sig(sk_seed: bytes, pk_seed: bytes, msg16: bytes, layer: int, leaf_index: int) -> bytes:
    out = bytearray(HT_WOTS_SIZE)
    for i in range(L):
        nib = _message_nibble(msg16, i)
        secret = _wots_secret_chunk(sk_seed, pk_seed, layer, leaf_index, i)
        sig_chunk = _advance_chain(secret, pk_seed, layer, leaf_index, i, 0, nib)
        out[i * N : (i + 1) * N] = sig_chunk
    return bytes(out)


def _reconstruct_wots_public_chunks(wots_sig: bytes, msg16: bytes, pk_seed: bytes, layer: int, leaf_index: int) -> bytes:
    out = bytearray(HT_WOTS_SIZE)
    for i in range(L):
        nib = _message_nibble(msg16, i)
        sig_chunk = wots_sig[i * N : (i + 1) * N]
        public_chunk = _advance_chain(sig_chunk, pk_seed, layer, leaf_index, i, nib, (W - 1) - nib)
        out[i * N : (i + 1) * N] = public_chunk
    return bytes(out)


def _derive_leaf_public_key(sk_seed: bytes, pk_seed: bytes, layer: int, leaf_index: int) -> bytes:
    public_chunks = bytearray(HT_WOTS_SIZE)
    for i in range(L):
        secret = _wots_secret_chunk(sk_seed, pk_seed, layer, leaf_index, i)
        public_chunk = _advance_chain(secret, pk_seed, layer, leaf_index, i, 0, W - 1)
        public_chunks[i * N : (i + 1) * N] = public_chunk
    return _commit_public_chunks(bytes(public_chunks), pk_seed, layer, leaf_index)


def _hash_tree_node(left: bytes, right: bytes, pk_seed: bytes, layer: int, depth: int, node_index: int) -> bytes:
    return _hashn("PQSIG-HT-NODE", left, right, pk_seed, _u32le(layer), _u32le(depth), _u32le(node_index))


@functools.lru_cache(maxsize=32)
def _build_layer_levels(sk_seed: bytes, pk_seed: bytes, layer: int) -> tuple[tuple[bytes, ...], ...]:
    level = tuple(_derive_leaf_public_key(sk_seed, pk_seed, layer, leaf) for leaf in range(1 << HT_HEIGHT))
    levels = [level]
    depth = 0
    while len(level) > 1:
        parent = tuple(
            _hash_tree_node(level[2 * i], level[2 * i + 1], pk_seed, layer, depth, i)
            for i in range(len(level) // 2)
        )
        levels.append(parent)
        level = parent
        depth += 1
    return tuple(levels)


def _layer_auth_path(sk_seed: bytes, pk_seed: bytes, layer: int, leaf_index: int) -> tuple[bytes, bytes]:
    levels = _build_layer_levels(sk_seed, pk_seed, layer)
    idx = leaf_index
    path = bytearray()
    for depth in range(HT_HEIGHT):
        path.extend(levels[depth][idx ^ 1])
        idx >>= 1
    return bytes(path), levels[-1][0]


def _compute_layer_root(msg16: bytes, wots_sig: bytes, auth_path: bytes, layer: int, leaf_index: int, pk_seed: bytes) -> bytes:
    public_chunks = _reconstruct_wots_public_chunks(wots_sig, msg16, pk_seed, layer, leaf_index)
    node = _commit_public_chunks(public_chunks, pk_seed, layer, leaf_index)
    idx = leaf_index
    for depth in range(HT_HEIGHT):
        sibling = auth_path[depth * N : (depth + 1) * N]
        if idx & 1:
            node = _hash_tree_node(sibling, node, pk_seed, layer, depth, idx >> 1)
        else:
            node = _hash_tree_node(node, sibling, pk_seed, layer, depth, idx >> 1)
        idx >>= 1
    return node


def derive_pk_root(sk_seed: bytes) -> bytes:
    pk_seed = derive_pk_seed(sk_seed)
    return _build_layer_levels(sk_seed, pk_seed, D - 1)[-1][0]


def derive_pk_script(sk_seed: bytes) -> bytes:
    pk_seed = derive_pk_seed(sk_seed)
    pk_root = derive_pk_root(sk_seed)
    return bytes([ALG_ID]) + pk_seed + pk_root


def parse_pk_script(pk_script33: bytes) -> tuple[bytes, bytes] | None:
    if len(pk_script33) != PK_SCRIPT_SIZE or pk_script33[0] != ALG_ID:
        return None
    return pk_script33[1:17], pk_script33[17:33]


def pqsig_sign(msg32: bytes, sk_seed: bytes, pk_script33: bytes, max_counter: int = 1048576) -> bytes:
    if len(msg32) != MSG32_SIZE:
        raise ValueError("msg32 must be exactly 32 bytes")
    parsed = parse_pk_script(pk_script33)
    if parsed is None:
        raise ValueError("pk_script33 must be 33 bytes, ALG_ID=0x01, and contain the rc2 profile")
    if max_counter < 1 or max_counter > 1048576:
        raise ValueError("max_counter must be between 1 and 1048576")

    pk_seed, pk_root = parsed
    if derive_pk_seed(sk_seed) != pk_seed:
        raise ValueError("sk_seed does not match pk_script33")
    if derive_pk_root(sk_seed) != pk_root:
        raise ValueError("pk_root does not match sk_seed")

    r = _hash32("PQSIG-PRFMSG", sk_seed, msg32, pk_script33)
    hmsg = _hash64("PQSIG-HMSG", r, msg32, pk_script33)
    pors_indices = _derive_pors_indices(hmsg)
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
        wots = _fill_wots_sig(sk_seed, pk_seed, layer_msg, layer, leaf_indices[layer])
        auth, expected_root = _layer_auth_path(sk_seed, pk_seed, layer, leaf_indices[layer])
        sig[layer_offset : layer_offset + HT_AUTH_SIZE] = auth
        sig[layer_offset + HT_AUTH_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE] = wots
        sig[layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE + HT_COUNTER_SIZE] = b"\x00" * HT_COUNTER_SIZE
        layer_msg = _compute_layer_root(layer_msg, wots, auth, layer, leaf_indices[layer], pk_seed)
        if layer_msg != expected_root:
            raise RuntimeError(f"failed to reconstruct exact layer root at layer={layer}")

    if layer_msg != pk_root:
        raise RuntimeError("failed to reconstruct top public root")
    return bytes(sig)


def pqsig_verify(sig4480: bytes, msg32: bytes, pk_script33: bytes) -> bool:
    if len(sig4480) != SIG_SIZE or len(msg32) != MSG32_SIZE:
        return False

    parsed = parse_pk_script(pk_script33)
    if parsed is None:
        return False

    pk_seed, pk_root = parsed
    r = sig4480[0:SIG_R_SIZE]
    reveals = sig4480[PORS_REVEAL_OFFSET : PORS_REVEAL_OFFSET + PORS_REVEAL_SIZE]
    auth_pad = sig4480[PORS_AUTH_OFFSET : PORS_AUTH_OFFSET + PORS_AUTH_PAD_SIZE]

    hmsg = _hash64("PQSIG-HMSG", r, msg32, pk_script33)
    pors_indices = _derive_pors_indices(hmsg)
    leaf_indices = _derive_leaf_indices(hmsg)
    layer_msg = _compute_pors_root(reveals, auth_pad, pors_indices, r, msg32, pk_seed)

    for layer in range(D):
        layer_offset = HT_OFFSET + layer * HT_LAYER_SIZE
        auth = sig4480[layer_offset : layer_offset + HT_AUTH_SIZE]
        wots = sig4480[layer_offset + HT_AUTH_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE]
        count = sig4480[layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE : layer_offset + HT_AUTH_SIZE + HT_WOTS_SIZE + HT_COUNTER_SIZE]
        if count != b"\x00" * HT_COUNTER_SIZE:
            return False
        layer_msg = _compute_layer_root(layer_msg, wots, auth, layer, leaf_indices[layer], pk_seed)

    return layer_msg == pk_root
