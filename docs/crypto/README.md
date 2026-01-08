# QPB Cryptography

## Signature Algorithms

| Algorithm | alg_id | Status | Description |
|-----------|--------|--------|-------------|
| **SHRINCS** | `0x30` | **Active** | Stateful hash-based scheme with SPHINCS+ fallback. Sole algorithm. |
| **ML-DSA-65** | `0x11` | Deprecated | Former genesis algorithm. Removed from consensus. |
| **SLH-DSA** | `0x21` | Reserved | NIST FIPS 205 (SPHINCS+). Not consensus-active. |

## Algorithm Details

- **SHRINCS (alg_id 0x30)** — Consensus-active on all networks. Uses WOTS+C, PORS+FP, and XMSS^MT hypertree with SPHINCS+ fallback. See [SHRINCS Spec](SHRINCS.md) for details.
  - **Public key:** 16 bytes (composite hash)
  - **Signature:** ~308-340 bytes (stateful) or ~7,856 bytes (fallback)
  - **PQSigCheck cost:** 2 units
  - **Security level:** NIST Level 1

- **ML-DSA-65 (alg_id 0x11)** — Deprecated and removed from consensus. Historical reference only. See [ML-DSA-65 Spec](MLDSA-65.md).

- **SLH-DSA (alg_id 0x21)** — Reserved for future activation. Currently rejected by consensus.

## Verification

All pure-Rust crypto code is verified with Miri for undefined behavior detection:

```bash
cargo +nightly miri test --lib shrincs
```

## Known Limitations

SHRINCS is a stateful signature scheme. Wallet key import (`dumpwallet`/`importwallet`) currently does not support exporting/importing signing state. See README.md for details.

Future alg_id activations require explicit soft/hard fork and spec/code updates.
