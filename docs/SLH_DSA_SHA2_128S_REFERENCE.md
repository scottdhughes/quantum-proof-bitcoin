# SLH-DSA-SHA2-128s Reference Prototype

## Status: REFERENCE ONLY - NOT CONSENSUS
## Spec-ID: SLH-DSA-SHA2-128S-REFERENCE-v1
## Updated: 2026-07-18
## Consensus-Relevant: NO

## Decision Boundary

This slice establishes a reproducible standards-conformance and performance
baseline for one final-standard candidate. It does not select the candidate for
production, add a node dependency, allocate an `ALG_ID`, modify Script, or
change the consensus accepted set. The production hold in
`PQSIG_PRODUCTION_READINESS.md` remains in force.

## Frozen Reference Contract

| Property | Reference value |
| --- | --- |
| Standard | NIST FIPS 205 |
| Parameter set | `SLH-DSA-SHA2-128s` |
| Security category | 1 |
| Interface | External |
| Message mode | Pure SLH-DSA, not HashSLH-DSA |
| Prototype message | Exactly 32 bytes |
| Prototype context | ASCII `PQBTC/tx-signature/v1` |
| Public key | 32 bytes |
| Private key | 64 bytes |
| Signature | 7,856 bytes |
| Exact-vector signing | Deterministic |
| Future production posture | Randomized signing, if separately approved |

Pure SLH-DSA internally binds `0x00 || len(ctx) || ctx || message` as specified
by FIPS 205. The prototype signs the 32-byte Bitcoin-style sighash digest as the
message and uses a fixed context to prevent signatures from being silently
reinterpreted by another protocol. The exact context remains a prototype
contract, not a consensus allocation.

## Reproducible Evidence

The checked-in manifest at `contrib/slh-dsa-ref/vectors.json` records:

- NIST ACVP repository commit
  `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`
- SHA256 checksums for the six key-generation, signature-generation, and
  signature-verification source files
- NIST key-generation group 1, test case 1
- NIST deterministic external/pure signature-generation group 19, test case
  161
- NIST external/pure signature-verification group 19, test cases 253 (reject)
  and 266 (accept, with the maximum 255-byte context)
- portable `slhdsa-c` commit
  `2b111e076a3bf0b6041651cf8746acf5ade56cc7`
- one repo-defined 32-byte sighash/context interoperability vector

The selected NIST signature has SHA256
`8ceee1f1b9feeb53f65e63a54c2ef252bfa4307df171ecdc2367923ef63d5223`.
The PQBTC prototype signature has SHA256
`14bf1a85f8fed8e18c61a3dfb25393527056da47b2d627e652bcfc4a105600e4`.

`compare_oracles.py` builds two adapters in a temporary directory:

1. OpenSSL 3.5 or later
2. the exact pinned `slh-dsa/slhdsa-c` checkout

Both independently reproduce the NIST keypair, reproduce the full 7,856-byte
NIST signature, self-verify it, return the official outcomes for the selected
accept/reject verification cases, and produce the same complete PQBTC prototype
signature. OpenSSL and `slhdsa-c` remain external research oracles and are not
linked into PQBTC.

Run:

```bash
python3 contrib/slh-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/slh-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --slhdsa-c /path/to/pinned/slhdsa-c \
  --benchmark-iterations 10
```

## Prototype Measurements

Local arm64 macOS measurement on 2026-07-18, using OpenSSL 3.6.3 and the pinned
portable-C oracle compiled with `-O2`. Values are medians of ten repetitions
of the fixed PQBTC vector and are directional, not release envelopes. They time
the adapter's cryptographic calls and exclude compilation, process startup, and
OpenSSL context initialization.

| Oracle | Key generation | Sign | Verify |
| --- | ---: | ---: | ---: |
| OpenSSL 3.6.3 | 19.384 ms | 146.434 ms | 0.114 ms |
| `slhdsa-c` | 40.896 ms | 298.063 ms | 0.228 ms |

Verification is fast enough to justify deeper node-level evaluation. Signing
latency is user-visible and requires wallet batching, hardware-signer, and
multi-input transaction measurements before selection.

## Bitcoin-System Implications

- The 32-byte raw public key preserves the compact key size used by the current
  research profile. A future script-layer tag would be a separate consensus
  design decision.
- A 7,856-byte signature is 75.36% larger than the held 4,480-byte rc2
  signature.
- At a 16,000,000-WU block limit, a signature-only upper bound falls from 3,571
  rc2 signatures to 2,036 SLH-DSA signatures, or 57.01% of the rc2 upper bound.
  Real transaction capacity is lower because this excludes transaction,
  witness, script, and compact size overhead. The harness emits this calculation
  from its checked-in cost model rather than relying on prose-only arithmetic.
- The signature exceeds Bitcoin's retained 520-byte general stack-element
  limit. The current node permits only the exact 4,480-byte rc2 signature in a
  narrowly matched witness shape, so it rejects this 7,856-byte reference
  signature today. Any future support requires an explicit consensus and policy
  sizing design; being below the separate 10,000-byte script-size limit does
  not make it admissible.
- SLH-DSA is stateless, so it avoids state-reuse and backup-coordination failure
  modes. Randomized signing still requires a sound entropy path and specified
  failure behavior.
- Hardware signers and PSBT flows must bind the exact 32-byte digest, context,
  algorithm, and randomized-signing policy without silent fallback.

## What This Evidence Establishes

Established:

1. the exact FIPS 205 parameter set is available in two independent
   implementations
2. both implementations match selected official NIST keygen, siggen, and
   positive/negative sigver vectors
3. both implementations agree byte-for-byte on a PQBTC-shaped 32-byte message
   and fixed context
4. the candidate has a reproducible local timing baseline

Not established:

1. a production-quality consensus implementation
2. constant-time signing or adequate secret erasure
3. complete ACVP, broad malformed-input, fuzz, or sanitizer coverage
4. acceptable block, mempool, wallet, backup, PSBT, or hardware-signer behavior
5. an activation, migration, or algorithm-agility design
6. independent cryptographic and consensus-code review

## Next Gate

The next bounded slice should add randomized-signing interoperability, broader
mutation and malformed-input vectors, and a complete selected-profile ACVP run.
Only after that evidence is green should PQBTC compare the same system-level
contract against `ML-DSA-44`. No candidate should enter `src/crypto`, Script,
wallet activation, or the `ALG_ID` registry during these reference slices.
