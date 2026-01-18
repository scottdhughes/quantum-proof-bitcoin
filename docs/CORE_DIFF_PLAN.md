# Bitcoin Core Fork — PQ-Only Chain (Genesis) — Diff Plan (v0)

This document lists the concrete subsystems/files to modify in a Bitcoin Core fork,
in the order that reduces risk and keeps the "blast radius" contained.

---

## 0) Choose an Upstream Base and Freeze It
- Pick a specific Bitcoin Core tag/commit as upstream baseline.
- Freeze it; all PQ work branches from that commit.
- Record toolchain versions and CI containers.

Deliverable:
- docs/UPSTREAM.md with commit hash and build instructions.

---

## 1) Chain Identity + Genesis

### 1.1 Chainparams
Modify:
- src/chainparams.cpp (and/or src/kernel/chainparams.cpp depending on Core version)

Changes:
- New chain name(s): main/test/regtest
- New message start bytes
- New default ports
- New bech32 HRP
- New base58 prefixes (if still used)
- New checkpoints (empty initially)
- New genesis block (time, nonce, bits, merkle root, hash)

Deliverables:
- contrib/genesis/ script/tool to mine genesis for given bits/target.
- docs/GENESIS.md recording genesis params and final hash.

Risk notes:
- Genesis is purely chain identity; do it first so everything else runs on your chain.

---

## 2) Consensus Parameter Changes (Block Weight)

Modify:
- src/consensus/consensus.h (or consensus/params where your base version defines it)
- src/validation.cpp (if limits are enforced there)
- src/policy/policy.h (policy-level max block weight / standardness)

Change:
- MAX_BLOCK_WEIGHT -> 16,000,000

Tests:
- src/test/* for block weight assumptions
- functional tests that assume 4,000,000 WU

---

## 3) Add a PQ Signature Library Module (Standalone First)

Create new module (suggested):
- src/crypto/pqsig/
  - pqsig.h / pqsig.cpp (public interface)
  - internal implementation files (wotsc.*, porsfp.*, hypertree.*, thash.*, prf.*, etc.)
  - known-answer tests (KAT fixtures) in src/test/data/pqsig/

Interface (example):
```cpp
bool PQSigVerify(Span<const uint8_t> sig4480,
                 Span<const uint8_t> msg32,
                 Span<const uint8_t> pk_script33);

bool PQSigSign(Span<uint8_t> out_sig4480,
               Span<const uint8_t> msg32,
               Span<const uint8_t> sk_seed, ...);
```

Implementation requirements:
- Hard-code the v0 parameter set:
  q_s=2^40, h=44, d=4, a=16, k=8, w=16, l=32, S_{w,n}=240, SigSize=4480.
- Implement Hmsg with SHA-512 output sizing rules required by PORS+FP.
- Implement domain separation (tweaks/tagging) per spec.

Deliverables:
- Unit tests: keygen/sign/verify
- Fuzz harness for PQSigVerify input parsing
- Microbenchmarks: verify time distribution; sign time distribution (grinding)

Risk notes:
- Keep this module independent of Script first.
- Treat signature parsing as hostile input.

---

## 4) Script Engine: Allow Big Stack Elements

Modify:
- src/script/script.h
  - MAX_SCRIPT_ELEMENT_SIZE (increase to >= 10,000)

Also audit:
- Any other hard-coded 520-byte assumptions in interpreter/policy.
- Any serialization/path that rejects large pushes.

Tests:
- src/test/script_tests.cpp
- functional tests that validate script element constraints

Risk notes:
- This change is consensus-critical. Make it early, and add explicit tests.

---

## 5) Script Engine: Replace Signature Verification (PQ-only)

Modify:
- src/script/interpreter.h / interpreter.cpp
  - signature checking path (CheckSig / EvalChecksig / CheckSignatureEncoding
    depends on Core version)
- src/script/sign.h / sign.cpp (wallet signing helpers)

Changes:
- Remove/disable DER encoding rules and libsecp256k1 checks for CHECKSIG.
- Enforce PQSig v0 encoding:
  - PK_script must be 33 bytes (ALG_ID + 32)
  - SIG must be exactly 4480 bytes
- Compute msg32 using existing sighash function (tx digest), then call PQSigVerify.

Opcodes:
Choose one path:
A) Repurpose OP_CHECKSIG/OP_CHECKMULTISIG to PQSig
B) Add OP_PQCHECKSIG/OP_PQCHECKMULTISIG and mark legacy CHECKSIG disabled/nonstandard

Deliverables:
- Script unit tests:
  - valid sig passes
  - wrong length fails
  - wrong pk length fails
  - wrong sighash fails
- Functional tests:
  - mine blocks with PQ spends
  - mempool acceptance rules

Risk notes:
- Keep the sighash as-is to reduce risk.
- Ensure no accidental acceptance of empty/invalid sigs.

---

## 6) Policy / Mempool Standardness

Modify:
- src/policy/policy.cpp / policy.h
- src/validation.cpp (mempool checks)

Policy recommendations:
- Standard outputs: P2WSH only (single-sig and multisig templates)
- Cap standardness for:
  - max PQ sigops per tx
  - max script size for witnessScript
  - min relay feerate appropriate for large witnesses

Deliverables:
- Document defaults in docs/POLICY.md
- Functional tests: relay limits and eviction behavior

---

## 7) Wallet: New Key Type + Keypool Batching

Modify/create (depending on whether you keep wallet):
- src/wallet/*

Core work items:
- Add PQ key material storage:
  - master seed (BIP39-like optional)
  - hardened derivation to child secret seeds
- Implement "keypool batches":
  - signer precomputes a batch of PK_script values
  - wallet tracks pool index, replenishment thresholds
- Address generation:
  - produce P2WSH witnessScripts: <PK_script> OP_CHECKSIG
  - compute P2WSH scriptPubKey and bech32 address

RPC impacts:
- getnewaddress returns PQ-only address type
- dump/restore wallet exports seed + keypool metadata
- importdescriptors/importaddress support importing PK_script batches for watch-only

Deliverables:
- docs/WALLET.md describing keypool workflow for:
  - consumer wallet
  - exchange/custody service
- Functional tests: restore-from-seed scans keypool gap limit correctly

Risk notes:
- This is the biggest product surface. You can ship node+CLI first,
  then iterate wallet.

---

## 8) Mining / Template / RPC Plumbing

Modify:
- src/miner.cpp (block assembly)
- src/rpc/mining.cpp
- src/rpc/rawtransaction.cpp (if needed)

Ensure:
- block templates allow large witness data
- fee estimation doesn't break on larger tx sizes
- policy properly prices weight

---

## 9) QA: Test Strategy

### Unit tests
- PQSig KAT vectors
- Script correctness tests for CHECKSIG/MULTISIG in PQ mode
- Serialization edge cases for large witness items

### Fuzz
- PQSigVerify fuzz target
- Script interpreter fuzz target (large element handling)

### Functional
- Regtest:
  - generate PQ addresses
  - fund
  - spend
  - multisig spend
  - reorg handling

CI:
- run unit + functional + fuzz smoke

---

## 10) Security Review Checklist (Before Public Release)
- Independent review of PQSig parsing and domain separation.
- Verify parameter constants match spec and are immutable in consensus.
- Benchmark verify throughput under adversarial blocks:
  - many inputs with PQ signatures
  - worst-case multisig scripts
- Audit wallet keypool restore/scanning logic (avoid fund loss).
