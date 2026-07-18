# ML-DSA-44 Reference Comparator

## Status: REFERENCE ONLY - NOT CONSENSUS
## Spec-ID: ML-DSA-44-REFERENCE-v1
## Updated: 2026-07-18
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
| Potential updates, last updated 2026-02-27 | `0e8ba77b46db71fda2c18e67111303335745a938686cad6faf35eac148f7ed3e` |
| Section 6 guidance, dated 2025-03-19 | `4a1d4b8d5aefef56069eb91bd464d5b5e177372e03bdde2541655e8e24d7a056` |

The potential-updates sheet states that its corrections are not official
changes and introduce no new technical requirements. Relevant entries correct
the explanatory `c_tilde` ordering to `mu || w1`, use `M'` consistently in
Sections 6.2 and 6.3, and clarify several pseudocode/text defects. The pinned
ACVP outputs and both oracles agree on the resulting key and signature bytes.

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
- OpenSSL 3.6.3 source commit
  `aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f`
- `mldsa-native` `v1.0.0-beta2` commit
  `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`
- one repo-defined 32-byte sighash/context interoperability vector

Representative signature hashes are:

| Vector | SHA256 |
| --- | --- |
| NIST deterministic siggen group 1 case 1 | `f2554d7153750b4deed79f80e5aa237a219fc92f83e59e7317c8d2089c4e7b91` |
| NIST randomized siggen group 13 case 181 | `8a17b6ff3f9633cd3c7cd0687d6384408e145bfd3725f6c57a8a2727f50ec989` |
| PQBTC prototype deterministic signature | `98094b39d9ae1ad76fc734f9e0199ad37315dd4eb7a22f29561582239f64e131` |

The driver builds two adapters in a temporary directory. OpenSSL imports the
expanded private key and derives its public key through the provider; it does
not assume the public key is a suffix of the ML-DSA private key.
`mldsa-native` uses `mldsa_pk_from_sk` and the exact FIPS prefix. Both reproduce
all selected NIST bytes, derive the same keys, cross-verify every generated
signature, and agree byte-for-byte when given the same explicit `rnd`.

Each native randomized API is also exercised twice. All four signatures are
distinct and accepted by both verifiers. Deterministic signing is retained for
reproducible evidence only; any production proposal must preserve the hedged
randomized posture and define entropy-failure behavior. The research-only
`mldsa-native` adapter obtains those test bytes from POSIX `/dev/urandom`; that
wrapper is not a node entropy design and limits the full harness to macOS/Linux.

`mldsa-native` is a fork of the `pq-crystals` reference implementation. It is a
separate portable-C code path from OpenSSL, so agreement is meaningful
differential evidence. Its ancestry still limits independence, and this result
must not be described as independent cryptographic review.

Run:

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

The full run requires clean source checkouts at the exact pinned commits. The
installed OpenSSL CLI and `pkg-config` library must both report 3.6.3. The
adapter links that installed library; the source checkout establishes review
provenance and is not compiled by the harness.

## Prototype Measurements

Local arm64 macOS measurement on 2026-07-18, using OpenSSL 3.6.3 and the pinned
portable-C oracle compiled with `-O2`. Values are medians of ten repetitions
of the fixed PQBTC vector and are directional, not release envelopes. They
time the adapter's cryptographic calls and exclude compilation, process
startup, cross-verification, and OpenSSL context initialization.

| Oracle | Keygen | Deterministic sign | Deterministic verify | Randomized sign | Randomized verify |
| --- | ---: | ---: | ---: | ---: | ---: |
| OpenSSL 3.6.3 | 0.099 ms | 0.157 ms | 0.092 ms | 0.752 ms | 0.052 ms |
| `mldsa-native` | 0.029 ms | 0.102 ms | 0.029 ms | 0.324 ms | 0.029 ms |

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
2. all 70 applicable selected-profile ACVP cases pass both codebases
3. deterministic and fixed-randomizer key/signature outputs agree byte-for-byte
4. native randomized outputs are distinct and cross-verify in both directions
5. empty/maximum context, malformed lengths, and 12 cryptographic mutations
   have explicit outcomes
6. both adapters pass the bounded ASan/UBSan exercise
7. the candidate has a reproducible ten-run performance and raw-payload model

Not established:

1. a production-quality consensus implementation
2. fully independent implementation ancestry or external cryptographic review
3. constant-time signing, adequate secret erasure, or fault-attack resistance
4. exhaustive fuzzing or sanitizer coverage of the linked OpenSSL library
5. acceptable wallet, descriptor, PSBT, hardware-signer, fee, or block behavior
6. an activation, migration, public-key commitment, or algorithm-agility design

## Next Gate

Produce a measured candidate-selection memo comparing this baseline with
`SLH_DSA_SHA2_128S_REFERENCE.md`. The memo must evaluate security assumptions,
implementation maturity and lineage, key/signature economics, signer and
verifier behavior, wallet/backup impact, and reviewability. It may select a
candidate for a separate engineering proposal or retain `HOLD`.

No candidate enters `src/crypto`, Script, wallet activation, or the `ALG_ID`
registry before that selection, an explicit consensus design, and external
cryptographic review.
