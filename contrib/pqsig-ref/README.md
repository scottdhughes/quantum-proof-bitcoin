# PQSig rc2 Reference Helpers

This directory contains a deterministic reference model for the locked PQSig rc2
wire/profile implementation used on the `v1.0.0-rc2` track:

- fixed 33-byte `PK_script` (`ALG_ID || PK_seed || PK_root`)
- fixed 4480-byte signature layout
- deterministic exact-root signing and verification for the structured
  WOTS+C/PORS+FP/hypertree fields

## Files

- `pqsig_ref.py`: pure-Python sign/verify/key-derivation helper.
- `gen_kat.py`: emits frozen KAT fixtures to
  `src/test/data/pqsig/kat_v1.json`.

## Usage

```bash
python3 contrib/pqsig-ref/gen_kat.py
```
