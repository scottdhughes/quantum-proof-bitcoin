# PQBTC Research Index

## Status: ACTIVE
## Spec-ID: RESEARCH-INDEX-v1
## Updated: 2026-07-19
## Consensus-Relevant: NO

## Purpose

Give Aineko and other future readers a single starting point for the research
and design corpus behind `quantum-proof-bitcoin`.

This index is intentionally opinionated. It points to the documents that best
answer specific classes of questions instead of listing every file in `docs/`.

## Current State

- The implemented rc2 profile is under a production release hold; integration
  coverage does not establish its claimed cryptographic security.
- An isolated FIPS 205 `SLH-DSA-SHA2-128s` reference harness now provides
  all 38 applicable external/pure ACVP cases, pinned two-oracle deterministic
  and randomized interoperability, malformed-input and sanitizer evidence, and
  timings without changing consensus behavior.
- An equivalent isolated FIPS 204 `ML-DSA-44` comparator now provides all 70
  applicable external/pure ACVP cases across OpenSSL, `mldsa-native`, and
  libcrux, exact and randomized differential evidence, malformed-input,
  disclosed-advisory regression and sanitizer coverage, timings, and a
  raw-payload cost model. The qualified libcrux lineage result closes the
  independent implementation evidence gate while keeping external
  cryptographic review unsatisfied.
- `PQSIG_CANDIDATE_SELECTION.md` selects `ML-DSA-44` as the primary
  engineering candidate, retains `SLH-DSA-SHA2-128s` as the conservative
  fallback, and preserves the production release hold. No consensus or wallet
  integration is authorized by that selection.
- `ML_DSA_44_EXTERNAL_REVIEW.md` freezes the review target, provenance,
  reproduction contract, threat model, required questions, reviewer criteria,
  severity rules, and deliverables. The AI-assisted assessment merged in PR
  `#183` with `REMEDIATE_AND_REREVIEW`, seven Medium findings, and no Critical
  or High finding. Issue `#181` remains open because the independent-human
  review gate is not satisfied.
- `ML_DSA_44_HEDGED_SIGNING_CONTRACT.md` defines the first remediation design
  boundary: internally generated 32-byte `rnd`, hedged-only production API,
  fail-closed errors, serialized callers, self-verification, lifecycle limits,
  and explicit rollback residual risk. Its executable model is not a selected
  backend or production implementation, so issue `#184` remains open.
- No PDF papers are currently checked into this repo.
- Delving Bitcoin now provides concrete adjacent research references that are
  directly relevant to Track A, especially around SHRINCS / SHRIMPS and
  algorithm-agility framing.
- `Spec.md` still does not name its external paper directly, but the strongest
  current lineage is now identified below: the SHRINCS thread points directly
  to `Hash-based Signature Schemes for Bitcoin`, while the SHRIMPS thread is a
  valuable follow-on direction for later compact-signature and multi-device
  thinking.

## How To Use This Index

- Start with the "Track A orientation" section for strategic work.
- Use the "Core protocol and consensus" section for architecture questions.
- Use the "Taproot replacement path" section for post-v1 migration work.
- Use the "Wallet / PSBT / operator" section for user-facing and operational
  work.
- Treat the "External references" section as adjacent context, not automatic
  design override.

## Track A Orientation

- [README_PQBTC.md](README_PQBTC.md)
  What the repo currently claims at a high level.
- [TRACK_A_NATIVE_PQ_BITCOIN.md](TRACK_A_NATIVE_PQ_BITCOIN.md)
  Strategic anchor. Use this first when the question is "what is this project
  actually trying to be?"
- [TRACK_A_90_DAY_ROADMAP.md](TRACK_A_90_DAY_ROADMAP.md)
  Current quarter execution plan.
- [TRACK_A_STATUS.md](TRACK_A_STATUS.md)
  Live working handoff for Aineko.

## Core Protocol And Consensus

- [Spec.md](Spec.md)
  Developer-facing protocol spec for the genesis chain and PQSig framing.
- [CONSENSUS_SURFACE.md](CONSENSUS_SURFACE.md)
  Fastest way to see what is consensus-critical versus deliberately out of scope.
- [CONSENSUS_DIFFS.md](CONSENSUS_DIFFS.md)
  High-level change surface versus inherited Bitcoin Core behavior.
- [SCRIPT_SEMANTICS.md](SCRIPT_SEMANTICS.md)
  Script-level meaning of PQ verification choices.
- [SIGHASH.md](SIGHASH.md)
  Current signature-hash posture and why the repo stayed narrow.
- [GENESIS.md](GENESIS.md)
  Chain identity and genesis-specific decisions.

## PQSig Construction And Encoding

- [PQSIG_PRODUCTION_READINESS.md](PQSIG_PRODUCTION_READINESS.md)
  Controlling cryptographic release hold and replacement gates.
- [PQSIG_CANDIDATE_SELECTION.md](PQSIG_CANDIDATE_SELECTION.md)
  Measured comparison, official-standards refresh, engineering selection, and
  rejection/fallback gates for ML-DSA-44 versus SLH-DSA-SHA2-128s.
- [SLH_DSA_SHA2_128S_REFERENCE.md](SLH_DSA_SHA2_128S_REFERENCE.md)
  Isolated standards-conformance and measurement baseline for the first final-
  standard candidate.
- [ML_DSA_44_REFERENCE.md](ML_DSA_44_REFERENCE.md)
  Isolated FIPS 204 three-oracle comparator, qualified implementation-lineage
  record, disclosed-advisory regressions, and measured baseline for the second
  final-standard candidate.
- [ML_DSA_44_EXTERNAL_REVIEW.md](ML_DSA_44_EXTERNAL_REVIEW.md)
  Frozen external-review input and acceptance contract for the selected
  engineering candidate; issue `#181` tracks the still-open review gate.
- [reviews/ML_DSA_44_AI_ASSISTED_TECHNICAL_REVIEW.md](reviews/ML_DSA_44_AI_ASSISTED_TECHNICAL_REVIEW.md)
  Reproducible supporting assessment with a `REMEDIATE_AND_REREVIEW`
  disposition and seven Medium remediation findings. It does not satisfy the
  independent-human gate.
- [ML_DSA_44_HEDGED_SIGNING_CONTRACT.md](ML_DSA_44_HEDGED_SIGNING_CONTRACT.md)
  Project-owned hedged-signing entropy, failure, concurrency, and lifecycle
  contract for the bounded issue `#184` remediation lane.
- [ML_DSA_44_WOLFRAM_ORACLE.md](ML_DSA_44_WOLFRAM_ORACLE.md)
  Supplemental exact-arithmetic cross-check for bounded FIPS 204 algebra,
  encoding boundaries, and malformed hint rejection. It is not another native
  implementation oracle and does not satisfy the external-review gate.
- [PQSIG_INTERNALS.md](PQSIG_INTERNALS.md)
  Best internal explainer for how the signature system is assembled.
- [PQSIG_WIRE_FORMAT.md](PQSIG_WIRE_FORMAT.md)
  Signature layout reference.
- [PQSIG_0X02_INTERNALS.md](PQSIG_0X02_INTERNALS.md)
  Forward-compatible fixture path context.
- [PQSIG_0X02_WIRE_FORMAT.md](PQSIG_0X02_WIRE_FORMAT.md)
  Encoding details for the neutral future fixture.
- [ALG_ID_REGISTRY.md](ALG_ID_REGISTRY.md)
  Algorithm ID lifecycle and allocation rules.
- [ALG_ID_PARSER_COMPAT.md](ALG_ID_PARSER_COMPAT.md)
  Parser and compatibility contract for algorithm evolution.

## Wallet, PSBT, And Signing Surface

- [WALLET.md](WALLET.md)
  Current implemented wallet state and what has already closed.
- [PSBT_STRATEGY.md](PSBT_STRATEGY.md)
  Frozen planning document for external signer and PSBT adaptations.
- [doc/psbt.md](../doc/psbt.md)
  Inherited upstream PSBT behavior reference.
- [doc/external-signer.md](../doc/external-signer.md)
  Useful when evaluating future external signer posture.
- [doc/descriptors.md](../doc/descriptors.md)
  Descriptor background for inherited surfaces that Track A may adapt.

## Taproot Replacement Path

- [TAPROOT_POSTURE.md](TAPROOT_POSTURE.md)
  Canonical answer to "are we inheriting Taproot as-is?" The answer is no.
- [TAPROOT_ACTIVATION.md](TAPROOT_ACTIVATION.md)
  Frozen activation and deployment family.
- [TAPROOT_MIGRATION_MATRIX.md](TAPROOT_MIGRATION_MATRIX.md)
  Canonical migration and compatibility matrix for the replacement path.
- [DECISION_DEFERRAL_LEDGER.md](DECISION_DEFERRAL_LEDGER.md)
  What remains explicitly deferred and why.

## Delivery, CI, And Operational Evidence

- [CORE_DIFF_PLAN.md](CORE_DIFF_PLAN.md)
  Big-picture implementation phases.
- [POST_RC_EPICS.md](POST_RC_EPICS.md)
  Remaining major epics after the first RC tranche.
- [CI_COMPLETENESS.md](CI_COMPLETENESS.md)
  Required gate and backlog classification.
- [OPS_SLO.md](OPS_SLO.md)
  Post-v1 operator confidence contract.
- [GA_ACCEPTANCE_CHECKLIST.md](GA_ACCEPTANCE_CHECKLIST.md)
  Useful history for understanding evidence discipline.
- [GA_BURNIN_LOG.md](GA_BURNIN_LOG.md)
  Release-era evidence trail and issue references.

## External References

- NIST FIPS 204:
  [Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
  Controlling final standard and potential-updates boundary for ML-DSA.
- NIST FIPS 205:
  [Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)
  Controlling final standard for the retained SLH-DSA fallback.
- NIST CSWP 39upd1, June 29, 2026:
  [Considerations for Achieving Crypto Agility](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final)
  Current official agility framing. PQBTC applies it through explicit,
  immutable algorithm binding rather than reinterpretation of existing
  outputs.
- Blockstream Research, March 3, 2026:
  [Quantum-resistant transaction signing on Liquid using Simplicity smart contracts](https://blog.blockstream.com/blockstream-research-demonstrates-quantum-resistant-transaction-signing-on-liquid-using-simplicity-smart-contracts/)
  Use as an adjacent benchmark for opt-in deployment on a Bitcoin-like system,
  not as a replacement for Track A.
- Delving Bitcoin, December 11, 2025:
  [SHRINCS: 324-byte stateful post-quantum signatures with static backups](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158)
  Best current Delving Bitcoin lineage reference for the repo's likely
  signature ancestry. The thread explicitly says SHRINCS is covered in the
  appendix of `Hash-based Signature Schemes for Bitcoin` and discusses WOTS+C,
  static backups, and stateful-versus-stateless fallback behavior.
- Delving Bitcoin, March 27, 2026:
  [SHRIMPS: 2.5 KB post-quantum signatures across multiple stateful devices](https://delvingbitcoin.org/t/shrimps-2-5-kb-post-quantum-signatures-across-multiple-stateful-devices/2355)
  High-value follow-on research thread for Track A. Strong source for later
  compact-signature and multiple-stateful-device thinking, even if it is less
  likely than the SHRINCS thread to be the immediate source behind `Spec.md`.
- Delving Bitcoin, February 9, 2026:
  [Algorithm agility to defeat quantum and classical attacks on Bitcoin's signature algorithms](https://delvingbitcoin.org/t/algorithm-agility-to-defeat-quantum-and-classical-attacks-on-bitcoins-signature-algorithms/2241)
  Important for migration thinking and long-horizon wallet safety framing.
  Useful adjacent context even though PQBTC is a native chain rather than an
  opt-in hedge for Bitcoin mainnet.
- BlockstreamResearch GitHub organization:
  [https://github.com/BlockstreamResearch](https://github.com/BlockstreamResearch)
  Useful as an implementation-reference shelf when Track A needs concrete code
  examples, especially around SHRINCS-family work, verifier structure, and
  wallet backup ideas. Treat these repositories as adjacent code references,
  not as an architecture source of truth for PQBTC.
- BlockstreamResearch:
  [shrincs-cpp](https://github.com/BlockstreamResearch/shrincs-cpp)
  Best direct code-reference candidate for Track A if PQBTC needs concrete
  C++ SHRINCS implementation patterns, tests, or KAT layout inspiration. Keep
  in mind the repository describes itself as work in progress, not
  production-ready.
- BlockstreamResearch:
  [shrincs-simplicity-verifier](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier)
  Useful for understanding how Blockstream packages SHRINCS verification logic
  in a Bitcoin-adjacent environment. Good comparison material for verifier
  structure, but not a direct dependency target for a block-0 native chain.
- BlockstreamResearch:
  [codex32](https://github.com/BlockstreamResearch/codex32)
  Useful later if PQBTC needs stronger human-readable backup or recovery
  posture. Relevant to wallet-operability thinking, not immediate consensus
  work.
- BlockstreamResearch:
  [pq-p2pkh](https://github.com/BlockstreamResearch/pq-p2pkh)
  Lower-priority reference. Keep in view for proof-system or ownership-proof
  ideas, not for current launch-critical work.
- BlockstreamResearch:
  [simplicity](https://github.com/BlockstreamResearch/simplicity)
  Adjacent research track only. Useful for understanding Blockstream's broader
  execution model, but it should not pull PQBTC away from its native-chain
  architecture by default.
- Likely underlying paper for `Spec.md`:
  [Hash-based Signature Schemes for Bitcoin](https://eprint.iacr.org/2025/2203)
  by Mikhail Kudinov and Jonas Nick.
  This is now the strongest identified external paper match for `Spec.md`.
  It matches the repo's emphasis on SPHINCS-family variants, WOTS+C, PORS+FP,
  reduced `q_s`, and wallet/key-derivation practicality, and the SHRINCS
  Delving Bitcoin thread explicitly points to it.

## Recommended Read Order For Aineko

1. [TRACK_A_STATUS.md](TRACK_A_STATUS.md)
2. [TRACK_A_NATIVE_PQ_BITCOIN.md](TRACK_A_NATIVE_PQ_BITCOIN.md)
3. [TRACK_A_90_DAY_ROADMAP.md](TRACK_A_90_DAY_ROADMAP.md)
4. [README_PQBTC.md](README_PQBTC.md)
5. [TAPROOT_MIGRATION_MATRIX.md](TAPROOT_MIGRATION_MATRIX.md)
6. [CI_COMPLETENESS.md](CI_COMPLETENESS.md)
7. [OPS_SLO.md](OPS_SLO.md)
8. Then the topic-specific document for the exact task.
