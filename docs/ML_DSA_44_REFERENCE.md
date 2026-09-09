# ML-DSA-44 Reference Comparator

## Status: REFERENCE ONLY - NOT CONSENSUS
## Spec-ID: ML-DSA-44-REFERENCE-v2
## Updated: 2026-09-09
## Consensus-Relevant: NO

## Decision Boundary

This slice establishes a reproducible conformance, interoperability, and cost
baseline for the FIPS 204 `ML-DSA-44` comparator. It does not select ML-DSA for
production, add a node dependency, allocate an `ALG_ID`, modify Script or
wallet behavior, or change the consensus accepted set. The release hold in
`PQSIG_PRODUCTION_READINESS.md` remains in force.

## Frozen Reference Contract

| Property | Reference value |
| --- | --- |
| Standard | NIST FIPS 204 |
| Parameter set | `ML-DSA-44` |
| NIST security category | 2 |
| Interface | External |
| Message mode | Pure ML-DSA, not HashML-DSA |
| Prototype message | Exactly 32 bytes |
| Prototype context | ASCII `PQBTC/tx-signature/v1` |
| Key-generation seed | 32 bytes |
| Public key | 1,312 bytes |
| Expanded private key | 2,560 bytes |
| Signing randomizer | 32 bytes |
| Signature | 2,420 bytes |
| Exact-vector signing | Deterministic or NIST-supplied fixed `rnd` |
| Future production posture | Hedged randomized signing, if separately approved |

Pure ML-DSA binds `0x00 || len(ctx) || ctx || message` before computing the
message representative. The prototype signs the 32-byte Bitcoin-style sighash
digest as the message and uses a fixed context to prevent silent cross-protocol
reinterpretation. That context is a research contract, not a consensus
allocation.

## Standards And Update Boundary

The manifest pins these NIST artifacts by SHA256:

| Artifact | SHA256 |
| --- | --- |
| FIPS 204 PDF | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` |
| Potential updates, last updated 2026-07-31 | `5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793` |
| Section 6 guidance, dated 2025-03-19 | `4a1d4b8d5aefef56069eb91bd464d5b5e177372e03bdde2541655e8e24d7a056` |

The potential-updates sheet states that its corrections are not official
changes and introduce no new technical requirements. Relevant entries correct
the explanatory `c_tilde` ordering to `mu || w1`, use `M'` consistently in
Sections 6.2 and 6.3, and clarify several pseudocode/text defects. The July 31
update also corrects the expected signing repetitions to `4.36`, `5.14`, and
`3.91` and raises the minimum internal-signing loop limit from `814` to `821`.
The isolated wrapper adopts `821`; the pinned ACVP outputs remain unchanged.

NIST's Section 6 guidance permits a separately validated external-`mu`
interface in specific module boundaries. This comparator does not select or
exercise that interface: it tests the Section 5 external/pure message API and
keeps context construction inside each oracle. A future hardware-signer or
streaming design must specify and validate the `mu` trust boundary separately.

## Reproducible Evidence

`contrib/ml-dsa-ref/vectors.json` records:

- NIST ACVP commit `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`
- SHA256 checksums for all six keygen, siggen, and sigver source files
- all 25 external/pure ML-DSA-44 key-generation group 1 cases
- all 15 deterministic external/pure signature-generation group 1 cases
- all 15 randomized external/pure signature-generation group 13 cases, with
  the official 32-byte `rnd` for each case
- all 15 external/pure signature-verification group 1 cases; cases 6, 7, and
  11 are accepted and the other 12 are rejected
- OpenSSL 3.6.4 source commit
  `d3c1b1169b3569ff3069e5b399f47b2b28e03d79`, tree
  `0f2db317fdf20b06193b96e79ac699b2d4e36d7d`, annotated tag object
  `360ffdb6d82f298d8d22c838dc2b7bf61ece056d`, and release-tarball SHA-256
  `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef`
- `mldsa-native` `v1.0.0-beta2` commit
  `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`
- `libcrux-ml-dsa` `v0.0.10` commit
  `c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd`, annotated tag object
  `255922337dee37aa32b21dbed27785f535de0336`, and ML-DSA subtree
  `0044b70c4675ba97623c9105387f592e038e837d`
- crates.io archive
  `libcrux-ml-dsa-0.0.10.crate`, SHA256
  `783ebed7cb27de6d44ef2aa662648d1a0869694f2f754f2f1ed45e959ef3b48e`
- one repo-defined 32-byte sighash/context interoperability vector

Representative signature hashes are:

| Vector | SHA256 |
| --- | --- |
| NIST deterministic siggen group 1 case 1 | `f2554d7153750b4deed79f80e5aa237a219fc92f83e59e7317c8d2089c4e7b91` |
| NIST randomized siggen group 13 case 181 | `8a17b6ff3f9633cd3c7cd0687d6384408e145bfd3725f6c57a8a2727f50ec989` |
| PQBTC prototype deterministic signature | `98094b39d9ae1ad76fc734f9e0199ad37315dd4eb7a22f29561582239f64e131` |

The driver builds three adapters in temporary directories. OpenSSL imports the
expanded private key and derives its public key through the provider; it does
not assume the public key is a suffix of the ML-DSA private key.
`mldsa-native` uses `mldsa_pk_from_sk` and the exact FIPS prefix. The libcrux
adapter uses its portable Rust ML-DSA-44 path. Its public API does not derive a
verification key from an imported expanded signing key, so the driver first
requires OpenSSL and `mldsa-native` to agree on that key and then supplies it
to libcrux for signing self-verification. All three reproduce the selected
NIST bytes, cross-verify every generated signature, and agree byte-for-byte
when given the same explicit `rnd`.

Each randomized API is exercised twice. All six signatures are distinct and
accepted by all three verifiers. Deterministic signing is retained for
reproducible evidence only; any production proposal must preserve the hedged
randomized posture and define entropy-failure behavior. The research-only
`mldsa-native` and libcrux adapters obtain their test bytes from POSIX
`/dev/urandom`; those wrappers are not a node entropy design and limit the full
harness to macOS/Linux.

`mldsa-native` is a fork of the `pq-crystals` reference implementation. It is a
separate portable-C code path from OpenSSL, so agreement is meaningful
differential evidence. Its ancestry still limits independence, and this result
must not be described as independent cryptographic review.

libcrux has a separate direct-Rust implementation history beginning at the
pinned May 2024 commit, and its normal crate dependency graph does not include
PQClean, `pq-crystals`, `mldsa-native`, or `pqcrypto-mldsa`. Its unit-test
outputs and selected sampling/optimization comments cite PQ-Crystals. The
frozen assessment is
`separate_implementation_lineage_with_reference_influence`: this is independent
implementation evidence, not independent design, external cryptographic
review, or production approval. The harness also reruns the upstream
regressions for `RUSTSEC-2026-0076` and `RUSTSEC-2026-0077` and adds two
ML-DSA-44 malformed-hint rejections, including the old out-of-bounds shape.
For 0077 it binds pinned Wycheproof ML-DSA-44 tcIds 125 and 126 by source,
case identity, and component hashes, then requires all three oracles to reject
the positive and negative signer-response coefficient cases at the
infinity-norm boundary.

Fresh post-repin exact-main evidence is bound by the
[versioned receipt](reviews/evidence/ml-dsa-44-trusted-main/0fa8f5fc4321f057fb758e4c2dc39b790023943c/SOURCE.json).
Evidence head `0fa8f5fc4321f057fb758e4c2dc39b790023943c` has an empty guarded
comparator diff from OpenSSL 3.6.4 repin baseline
`b22b21c3c6a06cb46f643eb1216325ecddacf7a4`. Review run `32924008998`
passed all exact and promoted replays and coverage floors with zero crashes,
sanitizer markers, oracle errors, or disagreements. Sustained run
`32924009052` completed the four 1,800-second verifier and signer sanitizer
campaigns with nonzero retained-corpus imports and zero crashes; the same
receipt binds resource run `32910153642` and advisory run `32910153947`.

In that 2026-08-26 tranche, the signer and review artifacts retain self-
contained retained-source provenance. Its strict-verifier campaign artifacts
retain imported counts but omit `retained_corpus_source` and
`retained_corpus_import`, so workflow restore logs—not those historical
artifacts alone—establish their source selection. This is conformance
evidence, not independent review or production approval.

On 2026-09-09, the
[exact-main receipt](reviews/evidence/ml-dsa-44-trusted-main/08eaa8ddee93069d2de09e8fb46aef6e7b1d0942/SOURCE.json)
bound protected-main head `08eaa8ddee93069d2de09e8fb46aef6e7b1d0942`
to baseline `e11258553613e5e1db7f98478419b5b3e9843c92`. Manual review
run `34307477001`, attempt `1`, completed its 1,800-second ASan/UBSan
differential campaign with `1,777,804` executions, `86` novel retained-seed
imports, all `5/5` exact and `38/38` promoted replays passing, all target and
OpenSSL-bridge coverage floors met, and zero crashes, sanitizer markers,
oracle errors, or disagreements. Its retained-source selection is recorded in
checksum-bound supplemental files in the same artifact rather than embedded
in `campaign.json`. Sustained run `34307476916`, attempt `1`, completed all
four 1,800-second verifier and stateful-signer ASan/UBSan and MSan campaigns:
the campaigns executed `8,013,773`, `13,130,663`, `93,446`, and `272,035`
units and imported `78`, `32`, `179`, and `139` novel retained seeds,
respectively, with zero crash or minimized-crash artifacts. Each strict
campaign embeds its exact retained source and import receipts in
`retained_corpus_source` and `retained_corpus_import`. These results are
bounded conformance and robustness evidence only; they do not establish
independent cryptographic review, production support, exhaustive coverage, or
grounds to change `production_backend=NONE` or the release hold.

Run:

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

The full run requires clean source checkouts at the exact pinned commits, a
full-history libcrux checkout for its ancestry check, the exact pinned libcrux
crate archive, and Rust/Cargo access to the crate's locked dependencies. The
installed OpenSSL CLI and `pkg-config` library must both report 3.6.4. The
OpenSSL adapter links that installed library; its source checkout establishes
review provenance and is not compiled by the harness.

## Prototype Measurements

Historical local arm64 macOS measurement on 2026-07-19, using OpenSSL 3.6.3,
the pinned portable-C oracle compiled with `-O2`, and the pinned portable-Rust
libcrux oracle compiled in release mode. Values are medians of ten repetitions
of the fixed PQBTC vector and are directional, not release envelopes. They time
the adapter's cryptographic calls and exclude compilation, process startup,
cross-verification, and OpenSSL context initialization.

| Oracle | Keygen | Deterministic sign | Deterministic verify | Randomized sign | Randomized verify |
| --- | ---: | ---: | ---: | ---: | ---: |
| OpenSSL 3.6.3 | 0.151 ms | 0.353 ms | 0.137 ms | 0.609 ms | 0.086 ms |
| `mldsa-native` | 0.031 ms | 0.165 ms | 0.065 ms | 0.237 ms | 0.030 ms |
| libcrux 0.0.10 | 0.096 ms | 0.197 ms | 0.068 ms | 0.219 ms | 0.030 ms |

The timing spread between deterministic and randomized calls includes random
generation and variable rejection-sampling work. Supported-platform,
worst-case, batch-verification, and block-validation measurements remain
required before selection.

## Bitcoin-System Implications

- The 2,420-byte signature is 45.98% smaller than the held 4,480-byte rc2
  signature, but the 1,312-byte public key is much larger than rc2's 33-byte
  script key.
- A raw `signature + public key` comparison is 3,732 bytes for ML-DSA-44 and
  4,513 bytes for rc2. If both were witness bytes and all other transaction
  costs were ignored, the 16,000,000-WU upper bounds would be 4,287 and 3,545
  respectively. This is a payload model, not a transaction-capacity or fee
  claim; output commitment, reveal, compact-size, script, and transaction
  encoding are deliberately unfrozen.
- If the full ML-DSA public key were placed directly in non-witness output
  data, its raw weight contribution would be 5,248 WU before script overhead.
  A hash-commit-and-reveal design would move cost and security behavior
  elsewhere. Neither design is selected here.
- The signature and public key both exceed Bitcoin's retained 520-byte general
  stack-element limit. The current node's narrow exception recognizes only
  the exact held rc2 witness shape, so this comparator is not admissible under
  current consensus or policy.
- ML-DSA is stateless, but wallet seed/import format, expanded-key caching,
  secret erasure, backup recovery, descriptor encoding, PSBT transport, and
  hardware-signer limits all require explicit contracts.
- Structured-lattice security, implementation side channels, malformed-key
  handling, and rejection-sampling behavior require external specialist
  review. Vector agreement does not answer those questions.

## What This Evidence Establishes

Established:

1. the exact final-standard ML-DSA-44 external/pure profile is frozen
2. all 70 applicable selected-profile ACVP cases pass all three codebases
3. deterministic and fixed-randomizer key/signature outputs agree byte-for-byte
4. randomized outputs are distinct and cross-verify across all three oracles
5. empty/maximum context, malformed lengths, and 12 cryptographic mutations
   have explicit outcomes
6. both portable-C adapters pass the bounded ASan/UBSan exercise
7. both retained upstream libcrux security tests pass on their ML-DSA-65
   scope, and two exact ML-DSA-44 RUSTSEC-2026-0076 malformed-hint cases reject
   without panic; exact pinned Wycheproof ML-DSA-44 RUSTSEC-2026-0077 tcIds
   125 and 126 reject across all three oracles
8. a separate implementation lineage agrees with the full comparator contract
9. the candidate has a reproducible ten-run performance and raw-payload model

Not established:

1. a production-quality consensus implementation
2. independent design or external cryptographic review
3. constant-time signing, adequate secret erasure, or fault-attack resistance
4. exhaustive fuzzing or sanitizer coverage of the linked OpenSSL and Rust
   libraries
5. acceptable wallet, descriptor, PSBT, hardware-signer, fee, or block behavior
6. an activation, migration, public-key commitment, or algorithm-agility design

## Next Gate

The frozen profile, provenance record, three-oracle reproduction contract,
threat model, review questions, and acceptance rules are packaged in
`ML_DSA_44_EXTERNAL_REVIEW.md`. External review is tracked by issue `#181` and
remains unsatisfied. The current gate state is `AWAITING_EXTERNAL_REVIEW`, not
review approval.

That review must cover the selected mode, randomization, rejection sampling,
malformed keys and hints, side channels, fault behavior, secret erasure, and key
derivation. Supported-platform and worst-case system measurements remain a
separate gate after review intake.

No candidate enters `src/crypto`, Script, wallet activation, or the `ALG_ID`
registry before external review, worst-case measurement, and a later explicit
consensus design.
