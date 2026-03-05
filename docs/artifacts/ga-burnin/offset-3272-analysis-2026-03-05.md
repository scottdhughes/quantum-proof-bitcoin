# Offset 3272 Analysis (2026-03-05)

## Summary

The byte at offset `3272` is reproducibly accepted after mutation in the current PQSig v1 reference model.
This is a GA-blocking consensus-risk smell because the mutation lands in the layer-2 WOTS region but still passes final verification.
Remote blocker tracking lives in GitHub issue `#48` (`GA Blocker: offset 3272 layer-2 WOTS mutation still verifies`).

## Offset Layout Proof

- `3272 = HT_OFFSET + 2 * HT_LAYER_SIZE + HT_AUTH_SIZE`
- `HT_OFFSET = 1712`
- `HT_LAYER_SIZE = 692`
- `HT_AUTH_SIZE = 176`
- `2 * HT_LAYER_SIZE = 1384`
- `HT_OFFSET + 2 * HT_LAYER_SIZE = 3096`
- `3096 + HT_AUTH_SIZE = 3272`
- Result: the first byte after the layer-2 auth path, which makes it the first byte of the layer-2 WOTS region.

## C++ Symbol Trace

1. `src/crypto/pqsig/pqsig.cpp` slices each hypertree layer from `sig4480` using `layer_offset = HT_OFFSET + layer * HT_LAYER_SIZE`.
2. For `layer = 2`, the WOTS span starts at `layer_offset + HT_AUTH_SIZE`, so offset `3272` lands at the first byte of the layer-2 `wots` span.
3. `pqsig.cpp` passes that `wots` span into `hypertree::ComputeLayerRoot(...)`.
4. `src/crypto/pqsig/hypertree.h` forwards the same `wots_sig` bytes into `wotsc::CommitLayerSignature(...)`.
5. `src/crypto/pqsig/wotsc.h` hashes the full `wots_sig` span inside `wotsc::CommitLayerSignature(...)`, so the mutated byte participates directly in the layer-2 WOTS commit.
6. `src/crypto/pqsig/pqsig.cpp` then derives `final_digest` from the resulting `layer_message`, `r`, `msg32`, and `pk_script`.

## Reproduction

Command:

```bash
python3 contrib/pqsig-ref/repro_offset_3272.py
```

Observed output:

```text
kat=kat_01
offset=3272
formula=HT_OFFSET + 2 * HT_LAYER_SIZE + HT_AUTH_SIZE
ht_offset=1712
ht_layer_size=692
ht_auth_size=176
layer=2
layer_offset=176
region=layer-2-wots-first-byte
original_verify=True
mutated_verify=True
root_cause=final acceptance remains gated by final_digest[0] == pk_root[0]
```

## Acceptance Explanation

- The mutated byte is not ignored. It flows through the layer-2 WOTS commit and into the recomputed hypertree path.
- The signature can still survive because final acceptance is gated by the one-byte predicate `final_digest[0] == pk_root[0]`.
- That predicate is too weak to treat this as benign flexibility. The accepted mutation is a consensus-risk smell.

## Decision Statement

- Offset `3272` remains an open `priority:P1` GA blocker on 2026-03-05.
- March 9, 2026 cannot promote to GA unless this is either mitigated or explicitly waived with a stronger accepted-set rationale.
- No edits to `src/crypto/pqsig/pqsig.cpp` or `src/script/interpreter.cpp` are part of this package.
- GitHub issue `#48` is the canonical remote blocker record for release governance.
