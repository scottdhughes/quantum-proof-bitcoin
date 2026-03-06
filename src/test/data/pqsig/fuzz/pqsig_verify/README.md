# PQSig Verify Fuzz Seeds

Curated local seeds for `FUZZ=pqsig_verify` smoke and corpus-backed runs.
CI already copies this directory into a scratch corpus before invoking the target.

All seeds are ASCII-free binary blobs. Each seed exists to keep a specific parser
or acceptance-boundary class represented in the local smoke corpus.

| Seed | Class | Expected shape | Purpose |
|---|---|---|---|
| `seed_short_sizes.bin` | short-size inputs | invalid | Exercises early size rejection. |
| `seed_bad_alg_id.bin` | bad alg-id | invalid | Exercises `PK_script[0] != 0x01` rejection. |
| `seed_pk_seed_mismatch.bin` | pk-seed mismatch | valid-size invalid | Keeps the `PK_root` re-derivation path in corpus. |
| `seed_pk_root_mismatch.bin` | pk-root mismatch | valid-size invalid | Keeps parser rejection for mismatched `PK_root`. |
| `seed_count_mismatch.bin` | reserved count mutation | valid-size invalid | Exercises the rc2 reserved-zero count field rejection. |
| `seed_count_overflow.bin` | reserved count overflow | valid-size invalid | Exercises nonzero count overflow rejection. |
| `seed_layer2_wots_offset_3272.bin` | regression canary | valid-size invalid | Preserves the former layer-2 WOTS byte flip at offset `3272`, which must now reject under exact public-root binding. |
| `seed_kat_structured.bin` | structured KAT-like input | valid-shape mixed | Keeps a valid-size / structured path in corpus instead of smoke-running against an empty dir. |
| `seed_mixed_noise.bin` | mixed noise | invalid | Preserves broad parser exploration. |
