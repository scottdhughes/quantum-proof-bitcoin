# PQSig v1 Reference Helpers

This directory contains a deterministic reference model for the locked PQSig v1
wire/profile implementation used in PQBTC v1:

- fixed 33-byte `PK_script` (`ALG_ID || PK_seed || PK_root`)
- fixed 4480-byte signature layout
- deterministic counter grind + structured WOTS+C/PORS+FP/hypertree fields

## Files

- `pqsig_ref.py`: pure-Python sign/verify/key-derivation helper.
- `gen_kat.py`: emits frozen KAT fixtures to
  `src/test/data/pqsig/kat_v1.json`.

## Usage

```bash
python3 contrib/pqsig-ref/gen_kat.py
```
