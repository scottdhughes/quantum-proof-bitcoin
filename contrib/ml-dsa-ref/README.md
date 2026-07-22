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
- `libcrux-ml-dsa` `v0.0.10` at its pinned source commit and annotated tag,
  plus the exact crates.io archive pinned by SHA256

The three adapters use all-zero randomness for deterministic vectors, explicit
32-byte `rnd` injection for randomized ACVP vectors, and their randomized APIs
for diversity and cross-verification checks. Hedged randomized signing remains
the required posture for any future production proposal.

`mldsa-native` is a fork of the `pq-crystals` reference implementation. It is
a separate portable-C code path from OpenSSL, but this ancestry means a green
differential run is not a substitute for independent cryptographic review.

`libcrux-ml-dsa` is a direct portable-Rust implementation with a separate Git
history and no normal dependency on PQClean, `pq-crystals`, or
`mldsa-native`. Its unit-test outputs and selected implementation comments cite
PQ-Crystals, so the precise assessment is
`separate_implementation_lineage_with_reference_influence`. Agreement closes
the separate-implementation evidence gate; it does not establish independent
design, external cryptographic review, side-channel safety, or production
readiness.

## Run

```bash
python3 contrib/ml-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/ml-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --openssl-source /path/to/pinned/openssl \
  --mldsa-native /path/to/pinned/mldsa-native \
  --libcrux-source /path/to/full-history/pinned/libcrux \
  --libcrux-crate /path/to/libcrux-ml-dsa-0.0.10.crate \
  --fips204 /path/to/NIST.FIPS.204.pdf \
  --fips204-updates /path/to/fips-204-potential-updates.xlsx \
  --fips204-section6-guidance /path/to/fips204-sec6-03192025.pdf \
  --benchmark-iterations 10 \
  --sanitizers
```

The full run requires clean Git checkouts at all pinned commits, including a
full-history libcrux checkout for the ancestry check, the exact pinned libcrux
crate archive, Rust and Cargo, and the locked Rust dependencies. It verifies
the three NIST document checksums and six ACVP source checksums, then executes
25 key-generation cases, 15 deterministic signature-generation cases, 15
randomized signature-generation cases, and all 15 signature-verification
accept/reject cases against all three oracles. It also checks complete
signature-byte agreement, cross-verification, randomized-signature diversity,
empty and maximum contexts, malformed lengths, key/message/context/signature
mutations, the two retained upstream libcrux security tests, two exact
ML-DSA-44 malformed-hint regression cases, and bounded ASan/UBSan runs for the two
portable-C adapters. The upstream tests are accurately labeled ML-DSA-65; the
comparator no longer treats them as a package-wide advisory PASS. The complete
dated advisory inventory and scheduled dependency scans are defined by
`contrib/ml-dsa-engineering/advisory_ledger.json`. The JSON report includes
ten-run timing medians and an explicitly scoped raw-payload block-space model.

The current `mldsa-native` and libcrux research adapters use POSIX
`/dev/urandom` to exercise randomized signing. Those wrapper paths are intended
for macOS/Linux evidence runs and are not a proposed node entropy
implementation.

All three adapters reject any signature whose decoded length is not exactly
2,420 bytes before entering the implementation verifier. OpenSSL,
`mldsa-native`, and libcrux are prototype oracles only; passing this harness
neither makes one a node dependency nor approves ML-DSA-44 for consensus
integration.

## Supplemental Exact Model

`wolfram/` contains a separately transcribed exact-integer model for bounded
FIPS 204 algebra and hint-encoding rules. Its NTT is checked against both the
defining transform equation and direct negacyclic multiplication, while its
boundary tests exercise decomposition, hints, strict hint decoding, and
Montgomery reduction. This is specification-level supplemental evidence, not a
fourth implementation oracle, native side-channel evidence, external review,
or production approval.
