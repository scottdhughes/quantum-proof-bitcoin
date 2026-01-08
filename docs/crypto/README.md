# QPB Cryptography

## Signature Algorithms

| Algorithm | alg_id | Status | Description |
|-----------|--------|--------|-------------|
| **ML-DSA-65** | `0x11` | Active | NIST FIPS 204 (Dilithium3). Genesis algorithm. |
| **SLH-DSA** | `0x21` | Reserved | NIST FIPS 205 (SPHINCS+). Not consensus-active. |
| **SHRINCS** | `0x30` | Implemented | Hybrid stateful+stateless scheme. ~636 byte sigs. |

## Algorithm Details

- **ML-DSA-65 (alg_id 0x11)** — Consensus-active at genesis. See [ML-DSA-65 Spec](MLDSA-65.md) for sizes, provenance, and validation invariants.

- **SLH-DSA (alg_id 0x21)** — Reserved for future activation. Currently rejected by consensus.

- **SHRINCS (alg_id 0x30)** — Fully implemented (Phases 1-5 complete). Uses WOTS+C, PORS+FP, and XMSS^MT hypertree with SPHINCS+ fallback. See [SHRINCS Spec](SHRINCS.md) for details.
  - **Activation heights:** Devnet (0), Testnet (100), Mainnet (TBD after audit)
  - **Test with:** `cargo test --features "shrincs-dev,shrincs-ffi"`

## Verification

All pure-Rust crypto code is verified with Miri for undefined behavior detection:

```bash
cargo +nightly miri test --lib shrincs
```

Future alg_id activations require explicit soft/hard fork and spec/code updates.
