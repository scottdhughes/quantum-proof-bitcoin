# Quantum-Proof Bitcoin Fork (Genesis Chain) — Protocol Spec v0 (DRAFT)

Status: Draft
Last-Updated: YYYY-MM-DD

This document is a developer-facing protocol specification for a Bitcoin Core-derived chain
starting from a new genesis block (height 0), with post-quantum (PQ) signatures required
for transaction authorization from genesis.

Normative language: "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY" are
to be interpreted as in RFC 2119.

---

## 1. Goals

### 1.1 Goals
- Provide a Bitcoin-like UTXO ledger with Script.
- Require post-quantum signatures for authorization from genesis (PQ-only).
- Support multisig via Script templates (e.g., M-of-N).
- Provide an HD-like wallet UX using hardened derivation + public key "keypool batches".

### 1.2 Non-goals (v0)
- No Schnorr/MuSig-style aggregation promise (hash-based native aggregation is out of v0 scope).
- No attempt to redesign PoW for "quantum-proof mining"; PoW remains SHA-256d.

---

## 2. Consensus Defaults (v0)

### 2.1 Proof-of-Work
- PoW: SHA-256d
- Target block interval: 600 seconds (10 minutes)
- Difficulty retarget: 2016 blocks (Bitcoin-style)

### 2.2 Supply Schedule
- Initial block subsidy: 50 COIN
- Halving interval: 210,000 blocks
- Max supply: 21,000,000 COIN

### 2.3 Block Capacity
- Max block weight: 16,000,000 weight units

Rationale: PQ signatures are ~4.5 KB each; v0 increases capacity to keep throughput usable.

---

## 3. Transaction Format (v0)

### 3.1 Base Transaction Encoding
The chain uses Bitcoin-style transactions with witness support and weight accounting.

### 3.2 Standardness vs Consensus
- Consensus MAY permit legacy non-witness transactions.
- Policy SHOULD prefer witness transactions (malleability and fee market reasons).
- v0 standard output types are defined in §6.

---

## 4. PQ Signature System ("PQSig v0")

### 4.1 High-Level Construction
PQSig v0 is a stateless, hash-based signature scheme in the SPHINCS framework, using:
- WOTS+C for the one-time layer, and
- PORS+FP for the few-time layer,
with hypertree parameters chosen for q_s = 2^40 max signatures per public key.

(See the referenced paper's sections on WOTS+C, PORS+FP, SPHINCS framework substitution,
and the parameter tables.)

### 4.2 Security Parameterization (v0 constants)
- Target security: NIST Level 1 / ~128-bit classical security.
- Internal hash output length: n = 128 bits (16 bytes).
- PK.seed length: 128 bits (16 bytes).
- PK.root length: 128 bits (16 bytes).
- PRFmsg output length: 256 bits (32 bytes).

### 4.3 Parameter Set (Consensus-Critical)
PQSig v0 MUST use the following fixed parameter set (Table 1 row "W+C P+FP 2^40"):
- q_s = 2^40
- h = 44
- d = 4
- a = 16
- k = 8
- w = 16
- l = 32
- S_{w,n} = 240
- SigSize = 4480 bytes (fixed)
- Verification proxy: 1292 compression calls (~0.29 compressions/byte)

### 4.4 Hash Functions and Domain Separation
PQSig v0 uses tweakable hashing (domain separation via "tweaks"; similar to tagged hashing).

Implementations MUST define:
- Th: a tweakable hash function producing n=128-bit outputs (16 bytes).
- PRF: keyed hash / PRF used for secret derivation.
- PRFmsg: keyed hash used to generate per-message randomness R (32-byte output).
- Hmsg: message hash used to derive:
  - the leaf index / instance pointer, and
  - k distinct leaf indices for PORS+FP (plus any other required extraction)

Hmsg output sizing:
- Because PORS+FP requires extracting k distinct indices plus an instance pointer, Hmsg
  MUST provide a sufficiently large output. v0 uses SHA-512 (512-bit output) for Hmsg.

(If insufficient distinct indices are produced, the signer repeats with fresh randomness.)

### 4.5 Grinding / Search Behavior (Deterministic Rule)
PQSig v0 signing includes a probabilistic search ("grinding") step.

v0 rule:
- The counter MUST be applied inside PRFmsg to sample fresh randomness R per attempt,
  and the final R is included in the fixed-size signature encoding.
- Implementations MUST be deterministic given:
  - the secret key,
  - the transaction digest,
  - and any explicit optional randomness input opt (if supported).

### 4.6 Public Key and Signature Encodings

#### 4.6.1 "Crypto" public key (PK_core)
- PK_core MUST be 32 bytes:
  - PK_core = PK.seed (16 bytes) || PK.root (16 bytes)

#### 4.6.2 Script-layer public key (PK_script)
To allow future agility, Script-layer pubkeys MUST be tagged:
- PK_script MUST be 33 bytes:
  - PK_script = ALG_ID (1 byte) || PK_core (32 bytes)
- v0 ALG_ID = 0x00

#### 4.6.3 Signature encoding (SIG)
- SIG MUST be exactly 4480 bytes for PQSig v0.
- Any other length MUST fail script verification.

Note: SIG is parsed according to PQSig v0's internal layout (including R and any padded
authentication set elements). For Script, SIG is treated as an opaque 4480-byte blob.

---

## 5. Script System (v0)

### 5.1 Script Limits (Consensus)
To support 4480-byte signatures, the script element size limit MUST be increased.

- MAX_SCRIPT_ELEMENT_SIZE MUST be >= 10,000 bytes.

### 5.2 Signature Verification Opcodes (v0)
v0 defines PQ-only semantics.

Option A (recommended for a new chain): Repurpose existing opcodes:
- OP_CHECKSIG verifies PQSig v0 (ALG_ID 0x00) for a PK_script.
- OP_CHECKMULTISIG verifies M-of-N PQSig v0 signatures.

Option B (more explicit): Introduce new opcodes OP_PQCHECKSIG / OP_PQCHECKMULTISIG.
(If implemented, Option B is preferred for long-term clarity, but Option A reduces surface area.)

v0 MUST choose exactly one option and implement it consistently across all script contexts.

### 5.3 Sighash
v0 uses Bitcoin-style sighash computation.

Policy guidance (non-consensus):
- v0 wallets SHOULD default to SIGHASH_ALL.
- v0 MAY restrict supported sighash flags in standardness policy to reduce complexity.

---

## 6. Standard Output Types (Policy)

Because PQ is the goal, v0 standardness SHOULD avoid 160-bit hashes.

### 6.1 Standard Single-Sig
Standard single-sig outputs SHOULD use P2WSH with witnessScript:
- <PK_script> OP_CHECKSIG

### 6.2 Standard Multisig
Standard multisig outputs SHOULD use P2WSH with witnessScript:
- m <PK_script_1> ... <PK_script_n> n OP_CHECKMULTISIG

---

## 7. Wallet Key Management (v0)

### 7.1 HD Wallet Constraints
Non-hardened public child derivation (xpub-style) does not apply cleanly to hash-based schemes.

### 7.2 Required Wallet Model (Keypool Batches)
Wallets MUST support:
- Hardened-only derivation of child secret seeds from a master seed.
- "Keypool batching": a signer (hardware wallet/HSM) precomputes and exports batches
  of PK_script values to the online wallet.
- The online wallet MUST request more pubkeys when the pool is low.

Recommended defaults (non-consensus):
- Consumer wallet: 1,000–10,000 pubkeys per account keypool
- Custody/exchange: 100,000+ pubkeys per account keypool

---

## 8. Mempool and DoS Controls (Policy)

Policy SHOULD enforce:
- Limits on total PQ signature operations per transaction (standardness).
- Minimum feerates that account for large witness data.
- Optional per-block PQ verification budget heuristics (policy-only; consensus remains fixed).

---

## 9. Upgrade and Versioning (Plan)
- ALG_ID byte in PK_script provides a clean hook for future signature versions.
- New ALG_ID values MUST be introduced via a consensus upgrade process.

---

## Appendix A: Parameter Table Reference
PQSig v0 corresponds to the parameter set in Table 1:
"W+C P+FP 2^40: h=44 d=4 a=16 k=8 w=16 l=32 S_{w,n}=240 SigSize=4480 SigVerify(compr.)=1292"

(That spec is based directly on the paper's construction notes, parameter choices, and constraints around Hmsg sizing, HD wallets, and multisig practicality.)
