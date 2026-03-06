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

## Status

**`v1.0.0` held; `v1.0.0-rc2` active** - the project is on the rc2 mitigation track after retiring the old `ALG_ID=0x00` profile before GA.

## RC Documentation

- [v1.0.0-rc1 Release Notes](RELEASE_V1_RC1.md)
- [v1.0.0-rc1 Runbook](RUNBOOK_V1_RC1.md)
- [GA Acceptance Checklist](GA_ACCEPTANCE_CHECKLIST.md)
- [GA Burn-in Log](GA_BURNIN_LOG.md)
- [Post-RC Epic Tracker](POST_RC_EPICS.md)

## License

MIT (TBD)
