# PQSig Verify Fuzz Seeds

Curated malformed-input seeds for `FUZZ=pqsig_verify` smoke and corpus runs.
These are intentionally invalid and target parser/acceptance boundaries:

- `seed_short_sizes.bin`: undersized wire blobs.
- `seed_bad_alg_id.bin`: malformed `PK_script` algorithm-prefix patterns.
- `seed_count_overflow.bin`: malformed hypertree count bytes (`0xff`).
- `seed_mixed_noise.bin`: mixed random/control bytes to trigger parser branches.
