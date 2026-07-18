# SLH-DSA Reference Harness

This directory contains an isolated interoperability and measurement harness
for the FIPS 205 `SLH-DSA-SHA2-128s` candidate. It is not linked into PQBTC,
does not define consensus behavior, and does not allocate or activate an
`ALG_ID`.

## Evidence Sources

- NIST ACVP vectors pinned in `vectors.json`
- an OpenSSL 3.6.3 runtime plus a clean checkout at the exact source commit
  pinned in `vectors.json` as one independent implementation
- `slh-dsa/slhdsa-c` at the exact commit pinned in `vectors.json` as the second
  independent implementation

The adapters use deterministic signing for deterministic vectors and explicit
16-byte randomizer injection for randomized vectors. The driver also exercises
OpenSSL's DRBG-backed signing path and supplies fresh operating-system entropy
to the portable implementation's caller-owned `addrnd` input. Randomized
signing remains the required posture for any future production proposal.

## Run

```bash
python3 contrib/slh-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/slh-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --openssl-source /path/to/pinned/openssl \
  --slhdsa-c /path/to/pinned/slhdsa-c \
  --benchmark-iterations 10 \
  --sanitizers
```

The full run checks the NIST checkout commit and source-file hashes, re-extracts
the complete external/pure SHA2-128s profile, and requires clean OpenSSL,
`slhdsa-c`, and ACVP source checkouts at their pinned commits. It executes all
10 key-generation cases, all 7 deterministic and 7 randomized
signature-generation cases, and all 14 signature-verification cases. It also
checks the PQBTC 32-byte sighash/context vector, complete signature-byte and
cross-verification agreement, randomized-signature diversity, empty/maximum
context boundaries, malformed lengths and key/message/context/signature
mutations, and optional ASan/UBSan adapter runs. The report includes separate
deterministic and randomized timing medians plus signature-only block-space
economics.

The portable API expects callers to validate the exact 7,856-byte signature
length before verification. Both adapters enforce that precondition and return
a normal verification failure for short or long signatures.

OpenSSL is a prototype oracle only. Passing this harness does not make OpenSSL a
node dependency or approve SLH-DSA for consensus integration.
