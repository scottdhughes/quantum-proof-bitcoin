# PQBTC Track A: Native Post-Quantum Bitcoin

## Status: ACTIVE
## Spec-ID: TRACK-A-v1
## Frozen-By: strategy-pass-20260406
## Consensus-Relevant: NO

## Purpose

Clarify the strategic anchor for `quantum-proof-bitcoin` so engineering decisions
do not drift toward a different product category.

## Core Claim

`quantum-proof-bitcoin` is a **consensus-native post-quantum Bitcoin-like
chain from genesis**, not merely a migration aid or an opt-in add-on for an
existing network.

Operationally, that means the intended launch posture is a **new chain starting
at block 0**, not an attempt to graft PQBTC consensus onto inherited Bitcoin
chain history.

The project should preserve that identity unless Scott explicitly changes the
product thesis.

## Scope

Track A covers:

- a PQ-native chain with post-quantum authorization built into consensus
- a new genesis and new chain history owned by PQBTC itself
- wallet, PSBT, descriptor, RPC, and operational flows that assume PQ-native
  signing as the default path
- migration and compatibility work needed for the repo's chosen explicit
  Taproot-replacement posture
- test, CI, and operator hardening needed to make the implementation credible

## Non-Goals

Track A is not:

- a Liquid wallet integration project
- a Simplicity contract demo
- an opt-in protection layer that leaves the base chain classical by default
- a near-term attempt to replace Bitcoin mainnet by social consensus alone
- a generic "post-quantum blockchain" rebrand that discards the current repo's
  Bitcoin-derived architecture

## Why Track A Stays The Anchor

- The repo already contains substantial native-chain work: frozen PQ-only
  consensus, descriptor-native wallet flows, PQ PSBT support, and migration
  posture documentation.
- Resetting onto an opt-in sidechain path would discard the project's main
  differentiator.
- The hard problem worth owning here is not just "can a Bitcoin-like system
  verify PQ signatures," but "what does a coherent PQ-native Bitcoin-derived
  chain look like end to end?"

## How Blockstream Fits

On March 3, 2026, Blockstream Research published a production Liquid mainnet
demonstration of post-quantum transaction signing using Simplicity and a
SHRINCS verifier.

This matters because it shows:

- post-quantum verification can run on a production Bitcoin-like system today
- an opt-in path can be deployed without consensus changes
- stateful versus stateless recovery tradeoffs are product-level design
  questions, not just cryptography details

But it does **not** replace Track A because:

- Liquid + Simplicity is an opt-in sidechain path, not a consensus-native base
  chain redesign
- Blockstream's write-up explicitly says the result is not a complete
  system-wide quantum fix
- the demonstrated verifier stack is materially different from this repo's
  current PQSig rc2 design

Therefore the correct use of the Blockstream work is:

- benchmark
- inspiration
- migration and interoperability input

and **not**:

- reason to restart the repo from zero
- reason to abandon the native-chain thesis

## Decision Rule

If the question is "what is the fastest path to opt-in post-quantum protection
for Bitcoin-like assets," then the Blockstream/Liquid/Simplicity line is a
strong reference path.

If the question is "what should `quantum-proof-bitcoin` be," Track A remains
the answer: a native post-quantum chain.

Do not collapse those two questions into one.

## Near-Term Engineering Bias

Near-term work should favor:

1. CI completeness and gating confidence
2. Taproot replacement migration coverage
3. wallet and signing flow maturity
4. operator hardening and runtime evidence
5. clear external positioning against adjacent approaches such as
   Liquid/Simplicity

## Adjacent Track

It is reasonable to keep a separate research track for:

- Liquid/Simplicity comparison notes
- migration design ideas
- interoperability thought experiments
- stateful versus stateless recovery analysis

That adjacent track should inform Track A. It should not silently replace it.
