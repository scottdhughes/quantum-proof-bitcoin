# PQSig Verify Fuzz Seeds

Curated local seeds for `FUZZ=pqsig_verify` smoke and corpus-backed runs.
CI already copies this directory into a scratch corpus before invoking the target.

All seeds are ASCII-free binary blobs. Each seed exists to keep a specific parser
or acceptance-boundary class represented in the local smoke corpus.

| Seed | Class | Expected shape | Purpose |
|---|---|---|---|
| `seed_short_sizes.bin` | short-size inputs | invalid | Exercises early size rejection. |
| `seed_bad_alg_id.bin` | bad alg-id | invalid | Exercises `PK_script[0] != 0x00` rejection. |
| `seed_pk_seed_mismatch.bin` | pk-seed mismatch | valid-size invalid | Keeps the `PK_root` re-derivation path in corpus. |
| `seed_pk_root_mismatch.bin` | pk-root mismatch | valid-size invalid | Keeps parser rejection for mismatched `PK_root`. |
| `seed_count_mismatch.bin` | layer-count mismatch | valid-size invalid | Exercises `count != layer_counts[layer]`. |
| `seed_count_overflow.bin` | count overflow | valid-size invalid | Exercises `count > SWN`. |
| `seed_layer2_wots_offset_3272.bin` | acceptance-boundary canary | valid-size invalid candidate | Reproduces the layer-2 WOTS byte flip at offset `3272` that still verifies in the current reference model. |
| `seed_kat_structured.bin` | structured KAT-like input | valid-shape mixed | Keeps a valid-size / structured path in corpus instead of smoke-running against an empty dir. |
| `seed_mixed_noise.bin` | mixed noise | invalid | Preserves broad parser exploration. |
