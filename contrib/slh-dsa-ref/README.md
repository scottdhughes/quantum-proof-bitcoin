# SLH-DSA Reference Harness

This directory contains an isolated interoperability and measurement harness
for the FIPS 205 `SLH-DSA-SHA2-128s` candidate. It is not linked into PQBTC,
does not define consensus behavior, and does not allocate or activate an
`ALG_ID`.

## Evidence Sources

- NIST ACVP vectors pinned in `vectors.json`
- OpenSSL 3.5 or later as one independent implementation
- `slh-dsa/slhdsa-c` at the exact commit pinned in `vectors.json` as the second
  independent implementation

The adapters use deterministic signing only for exact vector comparison.
Randomized signing remains the required posture for any future production
proposal.

## Run

```bash
python3 contrib/slh-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/slh-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --slhdsa-c /path/to/pinned/slhdsa-c \
  --benchmark-iterations 10
```

The full run checks the NIST checkout commit and source-file hashes, re-extracts
the selected vector fields, builds both adapters in a temporary directory,
requires the pinned `slhdsa-c` Git commit, reproduces selected NIST
key-generation and signature-generation vectors, enforces official accepted and
rejected signature-verification cases, checks the PQBTC 32-byte sighash/context
vector, compares complete signature bytes, and reports median key-generation,
signing, and verification times plus signature-only block-space economics. Both
external source checkouts must be clean and at their pinned commits.

OpenSSL is a prototype oracle only. Passing this harness does not make OpenSSL a
node dependency or approve SLH-DSA for consensus integration.
