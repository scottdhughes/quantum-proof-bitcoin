# PQSig rc2 Reference Helpers

This directory contains a deterministic model of the held PQSig rc2
wire/profile implementation:

- fixed 33-byte `PK_script` (`ALG_ID || PK_seed || PK_root`)
- fixed 4480-byte signature layout
- deterministic exact-root signing and verification for the structured
  WOTS+C/PORS+FP/hypertree fields

This model mirrors the implementation and is not an independent cryptographic
reference. It must not be used as evidence that rc2 conforms to the cited
WOTS+C/PORS+FP construction or is safe for production.

## Files

- `pqsig_ref.py`: pure-Python sign/verify/key-derivation helper.
- `gen_kat.py`: emits frozen KAT fixtures to
  `src/test/data/pqsig/kat_v1.json`.
- `audit_rc2_conformance.py`: reproduces the known fixed-sum and distinct-index
  conformance failures that keep rc2 under a release hold.

## Usage

```bash
python3 contrib/pqsig-ref/gen_kat.py
python3 contrib/pqsig-ref/audit_rc2_conformance.py --expect-release-hold
```
