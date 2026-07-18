# Quantum-Proof Bitcoin

A Bitcoin Core fork with post-quantum signatures from genesis.

## Overview

This project is a Bitcoin Core-derived research chain for evaluating
post-quantum transaction signatures and their wallet, policy, and consensus
integration.

### Key Properties

| Property | Value |
|----------|-------|
| Implemented research profile | PQSig rc2 (`ALG_ID=0x01`) |
| Signature size | 4,480 bytes |
| Public key size | 33 bytes (1-byte ALG_ID + 32-byte core) |
| Production approval | None - release hold |
| Claimed security/budget | Not established for the rc2 implementation |
| Block weight | 16,000,000 WU |
| PoW | SHA-256d (unchanged from Bitcoin) |

## Documentation

- [Protocol Specification](docs/Spec.md) - Normative spec with MUST/SHOULD language
- [Signature Production Readiness](docs/PQSIG_PRODUCTION_READINESS.md) - Controlling cryptographic evidence, release hold, and replacement gates
- [Core Diff Plan](docs/CORE_DIFF_PLAN.md) - Bitcoin Core fork implementation phases

## Status

**Research only - production release hold.** The implemented rc2 signature path
does not conform to security-critical WOTS+C/PORS+FP invariants claimed by the
draft specification. Do not use it to secure real funds or describe it as
production quantum-resistant cryptography. Existing consensus, wallet, PSBT,
and CI coverage remains useful integration evidence while a final-standard
candidate is implemented and independently reviewed.

## License

MIT (TBD)
