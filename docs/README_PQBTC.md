# Quantum-Proof Bitcoin

A Bitcoin Core fork with post-quantum signatures from genesis.

## Overview

This project implements a Bitcoin-like UTXO chain using hash-based post-quantum signatures (WOTS+C / PORS+FP in the SPHINCS framework) instead of ECDSA/Schnorr.

### Key Properties

| Property | Value |
|----------|-------|
| Signature scheme | PQSig rc2 (WOTS+C + PORS+FP) |
| Signature size | 4,480 bytes |
| Public key size | 33 bytes (1-byte ALG_ID + 32-byte core) |
| Max signatures/key | 2^40 |
| Security level | NIST Level 1 (~128-bit classical) |
| Block weight | 16,000,000 WU |
| PoW | SHA-256d (unchanged from Bitcoin) |

## Documentation

- [Protocol Specification](Spec.md) - Normative spec with MUST/SHOULD language
- [Core Diff Plan](CORE_DIFF_PLAN.md) - Bitcoin Core fork implementation phases
- [Track A: Native PQ Bitcoin](TRACK_A_NATIVE_PQ_BITCOIN.md) - Strategic anchor, scope, non-goals, and how adjacent approaches fit
- [Track A 90-Day Roadmap](TRACK_A_90_DAY_ROADMAP.md) - Concrete execution plan for April 6, 2026 through July 5, 2026
- [SHRINCS Decision Track](SHRINCS_DECISION_TRACK.md) - Controlled evaluation lane for SHRINCS-family adoption without destabilizing active Track A work
- [Signature Profile Comparison Memo](PQSIG_PROFILE_COMPARISON.md) - Decision memo comparing active `PQSig rc2` against SHRINCS-style and SHRIMPS-style candidates
- [Genesis And Network Posture](GENESIS_AND_NETWORK_POSTURE.md) - Launch interpretation for a fresh block-0 chain, network identity, and non-goals around inherited Bitcoin history
- [Research Index](RESEARCH_INDEX.md) - Curated map of the repo's internal research corpus and key external references
- [Watch-Only `pq(...)` Contract](PQ_DESCRIPTOR_WATCHONLY_CONTRACT.md) - Fixed public PQ descriptor boundaries, import behavior, and test-backed expectations
- [PQ Wallet Manager Setup](PQ_WALLET_MANAGER_SETUP.md) - Dedicated PQ-native receive/change manager setup path and its guardrails
- [PQ Address RPC Posture](PQ_ADDRESS_RPC_POSTURE.md) - Dedicated PQ address RPC boundary and why inherited address RPCs stay separate on PQ-only wallets
- [`createwalletdescriptor` Posture](CREATEWALLETDESCRIPTOR_POSTURE.md) - Current inherited descriptor-creation behavior and why it is not yet the PQ-native creation path

## Status

**`v1.0.0` held; `v1.0.0-rc2` active** - the project is on the rc2 mitigation
track after retiring the old `ALG_ID=0x00` profile before GA.

The repo already includes frozen PQ-only consensus, descriptor-native PQ wallet
managers, PQ PSBT signing/finalization support, and deterministic wallet
backup/recovery coverage. Current work is focused on confidence/gating
completeness, Taproot replacement migration coverage, and operational
hardening rather than first-pass wallet implementation.

## RC Documentation

- [v1.0.0-rc1 Release Notes](RELEASE_V1_RC1.md)
- [v1.0.0-rc1 Runbook](RUNBOOK_V1_RC1.md)
- [GA Acceptance Checklist](GA_ACCEPTANCE_CHECKLIST.md)
- [GA Burn-in Log](GA_BURNIN_LOG.md)
- [Post-RC Epic Tracker](POST_RC_EPICS.md)

## License

MIT (TBD)
