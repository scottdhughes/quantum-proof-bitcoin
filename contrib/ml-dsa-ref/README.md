# ML-DSA-44 Reference Harness

This directory contains an isolated conformance and measurement harness for
the FIPS 204 `ML-DSA-44` comparator. It is not linked into PQBTC, does not
define consensus behavior, and does not allocate or activate an `ALG_ID`.

## Evidence Sources

- NIST FIPS 204, its February 27, 2026 potential-updates sheet, and NIST's
  March 19, 2025 Section 6 guidance, all pinned by SHA256 in `vectors.json`
- all 70 NIST ACVP external/pure ML-DSA-44 cases at the exact ACVP-Server
  commit and source-file hashes pinned in `vectors.json`
- an OpenSSL 3.6.3 runtime plus a clean checkout at its pinned source commit
- `pq-code-package/mldsa-native` `v1.0.0-beta2` at its pinned commit

The two adapters use all-zero randomness for deterministic vectors, explicit
32-byte `rnd` injection for randomized ACVP vectors, and their native
randomized APIs for diversity and cross-verification checks. Hedged randomized
signing remains the required posture for any future production proposal.

`mldsa-native` is a fork of the `pq-crystals` reference implementation. It is
a separate portable-C code path from OpenSSL, but this ancestry means a green
differential run is not a substitute for independent cryptographic review.

## Run

```bash
python3 contrib/ml-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/ml-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --openssl-source /path/to/pinned/openssl \
  --mldsa-native /path/to/pinned/mldsa-native \
  --fips204 /path/to/NIST.FIPS.204.pdf \
  --fips204-updates /path/to/fips-204-potential-updates.xlsx \
  --fips204-section6-guidance /path/to/fips204-sec6-03192025.pdf \
  --benchmark-iterations 10 \
  --sanitizers
```

The full run requires clean Git checkouts at all pinned commits. It verifies
the three NIST document checksums and six ACVP source checksums, then executes
25 key-generation cases, 15 deterministic signature-generation cases, 15
randomized signature-generation cases, and all 15 signature-verification
accept/reject cases. It also checks complete signature-byte agreement,
cross-verification, native randomized-signature diversity, empty and maximum
contexts, malformed lengths, key/message/context/signature mutations, and
bounded ASan/UBSan adapter runs. The JSON report includes ten-run timing
medians and an explicitly scoped raw-payload block-space model.

The current research adapter uses POSIX `/dev/urandom` to exercise
`mldsa-native`'s randomized API. That wrapper path is intended for macOS/Linux
evidence runs and is not a proposed node entropy implementation.

Both adapters reject any signature whose decoded length is not exactly 2,420
bytes before entering the implementation verifier. OpenSSL and
`mldsa-native` are prototype oracles only; passing this harness neither makes
either one a node dependency nor approves ML-DSA-44 for consensus integration.
