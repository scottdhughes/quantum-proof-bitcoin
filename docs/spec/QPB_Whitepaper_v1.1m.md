Quantum Proof Bitcoin (QPB)

Consensus Specification for a Post-Quantum Secure Chain

Version 1.1m (Genesis Draft) — INTERNAL

**Date:** 2025-12-26  
**Authors:** Internal Design Team

Internal note: This document is an implementable consensus specification for a new Bitcoin-derived chain that is post-quantum secure from genesis. It is not a security audit, nor legal/compliance advice. It assumes standard Bitcoin node best-practices (including pruning) remain available.

**Changelog (from v1.1)**

This revision aligns the written spec with the reference implementation’s “ML‑DSA‑only genesis” posture:

- Genesis PQ suite is **ML‑DSA‑65** (alg_id = 0x11, FIPS 204 / Dilithium3). It is the **only** consensus‑active signature algorithm at genesis.
- **SLH‑DSA** (alg_id = 0x21, FIPS 205) and **SHRINCS** (alg_id = 0x30, research composite) are **RESERVED/INACTIVE** at genesis and **MUST be rejected** by consensus until activated by a future hard fork.
- Updated size constants to match ML‑DSA‑65: pk_bytes = 1952, sig_bytes = 3309 (pk_ser = 1953, sig_ser = 3310 including the sighash type byte).
- PQSigCheck cost units updated: 0x11 cost = 1 (active). Other costs remain placeholders while inactive.

All other rules in this document are unchanged from v1.1.

Non-consensus clarifications:

- Threat model updated for Grover on PoW (energy/centralization risks).

- Survivability: Crypto is anchored on NIST‑standard ML‑DSA‑65 at genesis; hash‑based SLH‑DSA and composite SHRINCS are reserved for potential future activation. Systems 85% (bounded growth/DoS, 200 GB/year at 0.5 TPS).

0. Notation and Conventions (Normative)

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, and MAY are to be interpreted as described in RFC 2119.

All integers are unsigned unless explicitly stated. All byte strings are sequences of octets.

Unless otherwise specified, serialization is identical to Bitcoin Core's "consensus serialization" (little-endian for integers, CompactSize for variable-length vectors).

1. Abstract

QPB forks Bitcoin to require post‑quantum signatures from block 0. At genesis, the only consensus‑active signature algorithm is **ML‑DSA‑65** (FIPS 204 / Dilithium3; 1952‑byte public keys, 3309‑byte signatures). SHRINCS (0x30) and SLH‑DSA (0x21) are reserved/inactive and MUST be rejected until activated by a future hard fork. UTXO model intact; PoW Argon2. Two outputs: P2QPKH (key hash), P2QTSH (script tree, no key spend). Sighash: 32B digest, chain‑replay proof. Weights: Adaptive median (100/100k blocks), 1.4x growth, quadratic penalty. Bounds: 8MB bytes, 32M WU, 500 PQSigCheck cost units/block. Goal: Sustain 0.5 TPS at 200 GB/year growth; quantum survival via PQ signatures + hashes + economics.

2. Scope and Non-Goals (Informative)

2.1 In Scope (Consensus)

- Block and transaction validity rules (serialization, sighash, signature verification).

- Two output types: P2QPKH (simple) and P2QTSH (script tree, no key path).

- Adaptive block weight limit and coinbase penalty rule.

- DoS bounds: block bytes cap, witness element cap, PQSigCheck budget.

2.2 Out of Scope (Non-Consensus)

- Wallet UX, address encoding, and descriptor formats.

- P2P encryption and transport (e.g., BIP324-style upgrades).

- Miner policy (relay/mining policy), mempool rules, fee estimation.

- Codebase layout, RPC design, GUI, and operational hardening.

- Signature aggregation / validity proofs (research track; not in consensus for v1).

3. Threat Model (Informative)

3.1 Primary Threat: Quantum Attacks on Classical Signatures

A cryptographically relevant quantum computer (CRQC) running Shor’s algorithm can recover private keys from exposed ECDSA/Schnorr public keys and forge signatures. QPB mitigates this by removing ECDLP-based signatures entirely.

3.2 Planning Signal: Rapid Improvements in Shor-Resource Estimates

Published resource estimates for factoring RSA-2048 have dropped substantially over time (e.g., <1M noisy qubits under certain assumptions). This does not directly translate to ECC break costs or timelines, but it is a conservative planning signal: do not assume “decades of warning.”

3.3 Secondary Threat: Quantum Speedups on Hashing

Grover’s algorithm gives a quadratic speedup against symmetric primitives (e.g., SHA-256). This impacts mining and some hashing security margins but is addressed operationally by difficulty adjustment and conservative hash output sizes (256-bit hashes remain standard practice). Updated for Grover on PoW: Energy/centralization risks—state actor could dominate with quantum hardware (~10^12 qubits logical, 10^18 J/year energy at scale).

3.4 DoS / Resource Exhaustion

PQ signatures are larger and may be slower to verify. QPB therefore:

- Caps block bytes and defines weight with a conservative witness discount.

- Raises the witness-item cap (above Bitcoin’s 520-byte limit) but bounds it tightly.

- Imposes a per-block PQSigCheck cost budget and retains script operation limits.

4. Design Principles (Informative)

Determinism and Simplicity: consensus rules must be easy to implement, test, and reason about.

Upgrade Isolation: new features use new witness versions and explicit algorithm IDs.

No Key-Path Spending: script-tree commitments avoid long-exposure pubkey risk, following the spirit of P2TSH.

Bounded Validation: any attacker-controlled field is bounded (bytes, ops, sig verification budget).

Lean Genesis: begin with one PQ signature primitive that is widely implemented and testable today (ML‑DSA‑65), and reserve additional primitives (SLH‑DSA, SHRINCS) for hard forks once justified by audit and operational need.

5. Consensus Constants (Normative)

5.1 Chain Identifier

CHAIN_ID MUST be defined as:  
CHAIN_ID = HASH256(SerializeBlockHeader(genesis_block_header))  
where HASH256(x) = SHA256(SHA256(x)).

5.2 Global Limits

| Name                   | Value      | Meaning                                                        |
| ---------------------- | ---------- | -------------------------------------------------------------- |
| MAX_BLOCK_BYTES        | 8_000_000  | Absolute max serialized block size in bytes                    |
| ABS_HARD_CAP_WU        | 32_000_000 | Absolute max block weight in WU                                |
| WEIGHT_FLOOR_WU        | 4_000_000  | Penalty-free floor for effective median weight                 |
| MAX_MULTIPLIER         | 2          | Max block weight is 2 * effective median                       |
| W_ST                   | 100        | Short-term median window (blocks)                              |
| W_LT                   | 100_000    | Long-term median window (blocks)                               |
| LT_CLAMP_FACTOR        | 10         | Caps short-term median relative to long-term median            |
| LT_GROWTH_NUM          | 14         | Long-term growth limiter numerator                             |
| LT_GROWTH_DEN          | 10         | Long-term growth limiter denominator (1.4x)                    |
| MAX_WITNESS_ITEM_BYTES | 20_480     | Max size of any witness stack element for QPB witness versions |
| MAX_PQSIGCHECK_BUDGET  | 500        | Max PQSigCheck cost units per block (QScript + P2QPKH)         |
| MAX_PQSIGCHECK_PER_TX  | 40         | Max PQSigCheck cost units per transaction                      |


5.3 PQ Algorithm Registry (Genesis)

Algorithm identifiers are one byte (alg_id). At genesis, the only ACTIVE algorithm identifier is alg_id = 0x11. All other alg_id values MUST be rejected until activated by a future hard fork.

| alg_id | Algorithm           | Status @ Genesis    | NIST Cat | Public Key Bytes | Signature Bytes |
| ------ | ------------------- | ------------------- | -------- | ---------------- | --------------- |
| 0x11   | ML-DSA-65           | ACTIVE              | 3        | 1952             | 3309            |
| 0x21   | SLH-DSA-SHA2-192s   | RESERVED (inactive) | 3        | 48               | 16224           |
| 0x30   | SHRINCS (composite) | RESERVED (inactive) | -        | 64               | 324             |


All other alg_id values are unassigned at genesis and MUST be rejected.

5.4 PQSigCheck Cost Units (Genesis)

| alg_id              | Cost Units                        |
| ------------------- | --------------------------------- |
| 0x11 (ML-DSA-65)    | 1                                 |
| 0x21 (SLH-DSA-192s) | 8 (reserved; inactive at genesis) |
| 0x30 (SHRINCS)      | 1 (reserved; inactive at genesis) |


6. SegWit From Genesis (Normative)

6.1 Transaction serialization

A transaction MAY be serialized in either legacy form or witness form:
	•	Legacy serialization (no witness):
nVersion || vin || vout || nLockTime
	•	Witness serialization:
nVersion || marker || flag || vin || vout || witness || nLockTime

Where:
	•	marker MUST be 0x00.  
	•	flag MUST be 0x01.  
	•	witness is the serialization of all input witness stacks:
for each input, a CompactSize item count followed by CompactSize(len(item))||item for each stack item.

6.2 txid and wtxid
	•	txid(tx) = HASH256(SerializeTx(tx, include_witness=false))
	•	wtxid(tx) = HASH256(SerializeTx(tx, include_witness=true))

6.3 Witness commitment (BIP141-compatible)

A block with any non-empty witness data MUST contain a witness commitment output in the coinbase transaction, and MUST satisfy all of the following rules:

Coinbase wtxid in the witness merkle tree

For the witness merkle root calculation only, the coinbase transaction wtxid is assumed to be 32 bytes of 0x00.

Witness merkle root

Let W[0..n-1] be the list of wtxids of all transactions in the block in order, except set W[0] = 0x00..00.
Compute witness_root as the standard Bitcoin-style merkle root over W (pairwise HASH256 concatenation; if odd count, duplicate the last hash).

Witness reserved value

The coinbase transaction’s input witness MUST consist of exactly one stack item of exactly 32 bytes, called witness_reserved_value.

Commitment hash

commitment_hash = HASH256( witness_root || witness_reserved_value )

Commitment placement in coinbase outputs

The commitment MUST appear in a coinbase output scriptPubKey that is at least 38 bytes, and whose first 6 bytes are exactly:
0x6a 0x24 0xaa 0x21 0xa9 0xed
followed by 32 bytes commitment_hash.  
If more than one output matches the pattern, the one with the highest output index is the commitment.

If all transactions in a block have empty witness data, the witness commitment MAY be omitted.

6.4 scriptSig rule (native witness programs)
For native witness programs (including QPB witness versions v2/v3), scriptSig MUST be exactly empty, or the spend is invalid.

6.5 OP_CODESEPARATOR
If OP_CODESEPARATOR is executed during QScript v0 evaluation, script evaluation MUST fail.

7. Common Serialization and Hashing (Normative)

7.1 CompactSize and SerBytes

CompactSize(n) and vector encodings are identical to Bitcoin consensus encoding.  
SerBytes(b) MUST be encoded as: CompactSize(len(b)) || b.

7.2 Tagged Hash

TaggedHash(tag, msg) MUST be defined as:  
TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)  
where tag is the ASCII byte sequence of the tag string.

7.3 Block Weight (WU)

BlockWeightWU(B) = 4 * base_bytes(B) + 4 * witness_bytes(B)  
where base_bytes is serialized block without witnesses, witness_bytes is all witness data.  
Blocks MUST satisfy BlockWeightWU <= ABS_HARD_CAP_WU and serialized size <= MAX_BLOCK_BYTES.

8. QIP-0001 — Witness Programs, QScript v0, and Sighash (Normative)

8.1 Overview

QPB defines exactly two SegWit-style witness programs:

- v2 P2QTSH: Pay-to-Quantum-Tapscript-Hash (script tree, no key path).

- v3 P2QPKH: Pay-to-Quantum-PubKey-Hash (simple key-hash spend).

Any other witness version is invalid at genesis.

8.1.1 Common Rule: Witness Item Size

Witness stack item MUST be <= MAX_WITNESS_ITEM_BYTES. For QScript v0 (v2/v3), max stack element size SHALL be MAX_WITNESS_ITEM_BYTES, replacing legacy 520-byte limit. Scripts MUST be <= 10,000 bytes.

8.2 P2QPKH (Witness Version 3)

8.2.1 scriptPubKey

OP_3 PUSH32(qpkh32)  
qpkh32 = HASH256(TaggedHash("QPB/QPKH", pk_ser))

8.2.2 Witness Stack

[sig_ser, pk_ser]  
pk_ser = alg_id (1 byte) || pk_bytes  
sig_ser = sig_bytes || sighash_type (1 byte)

8.2.3 Validation Algorithm (P2QPKH)

Parse witness.

Check qpkh32 commitment.

msg32 = QPB_SIGHASH(tx, in_idx, sighash_type, prevouts).

PQVerify(alg_id, pk_bytes, msg32, sig_bytes) (per QIP-0004).

Failure invalidates tx. Add PQSIGCHECK_COST(alg_id) to budgets.

8.3 P2QTSH (Witness Version 2)

8.3.1 scriptPubKey

OP_2 PUSH32(qroot32)

8.3.2 Witness Stack

[stack_items..., leaf_script, control_block]

Where:

- leaf_script is byte string as QScript v0 (leaf_version below).

- control_block length 1 + 32*m, m <= 128.

Let:

- control_byte = control_block[0]

- merkle_path = control_block[1:] (32*m bytes, m nodes)

Constraints:

- (len(control_block) - 1) mod 32 == 0, else invalid.

- m = (len(control_block) - 1) / 32 <= 128, else invalid.

- (control_byte & 1) == 1 (parity 1, no key-path).

- leaf_version = control_byte & 0xfe.

Genesis: leaf_version == 0x00 (QScript v0). Other invalid.

Annex not supported; witness MUST be exactly [stack_items..., leaf_script, control_block] (no extra items).

8.3.3 QTap Hashing

leaf_hash = TaggedHash("QPB/QTapLeaf", bytes([leaf_version]) || SerBytes(leaf_script))  
BranchHash(a, b) = TaggedHash("QPB/QTapBranch", min(a,b) || max(a,b))

h = leaf_hash  
for i in 0..m-1:  
  h = BranchHash(h, merkle_path[i])  
qroot = h

Valid if qroot == Extract32(prevout.scriptPubKey).

Note: Matches BIP360 control-block/parity (QPB tags).

8.3.4 Validation Algorithm (P2QTSH)

Parse control_block; m <= 128.

Reconstruct qroot32.

Execute leaf_script under QScript v0 (leaf_version=0x00 genesis).

Failure invalidates tx.

8.4 QScript v0 (Leaf Script Semantics)

8.4.1 Allowed / Disallowed Operations

QScript v0: Bitcoin Script ops minus ECC (e.g., no OP_CHECKSIG). Limit: 201 ops, 10KB size. Max stack elements: 1000. Enforce minimal push/IF, NULLDUMMY, CLEANSTACK. Disabled opcodes fail if executed. Numeric encoding rules: Minimal, as in Bitcoin Core.

8.4.2 OP_CHECKPQSIG Stack and Semantics

Pops: sig_ser, pk_ser. msg32 = QPB_SIGHASH(tx, in_idx, sighash_type, prevouts, ext_flag=0x01, leaf_hash). Pushes 1/0 if PQVerify succeeds. Costs PQSIGCHECK_COST(alg_id).

8.4.3 OP_CTV (New Opcode)

OP_CTV (0xB5): Aligns with BIP119. Stack empty: Fail. Top != 32 bytes: NOP. Else, SHA256(SerTxTemplate(tx)) == item; fails mismatch, NOP success (no pop). SerTxTemplate: nVersion (4B LE) || nLockTime (4B LE) || [scriptSigs hash if non-empty] || input count (4B LE) || sequences hash || output count (4B LE) || outputs hash || current input index (4B LE). scriptSigs hash: SHA256(concat SerString(scriptSig_i) for i if non-empty, SerString = CompactSize(len) || data). sequences hash: SHA256(concat u32le(sequence_i) for i). outputs hash: SHA256(concat SerOut(output_i) for i, SerOut = u64le(value) + SerBytes(scriptPubKey)). Implementations SHOULD cache hashes (anti-DoS). Costs 1 op. PQ-safe (hash-only).

8.5 QPB_SIGHASH (Common Signature Digest)

8.5.1 Sighash Type Byte

sighash_type: ALL (0x01), NONE (0x02), SINGLE (0x03); +0x80 for ANYONECANPAY. base = sighash_type & 0x7f MUST be in {0x01, 0x02, 0x03}; otherwise signature validation fails.

8.5.2 Preimage Construction

hashPrevouts = if ANYONECANPAY: 0x00...00 (32B) else SHA256(concat all prevouts SerPrevout = txid(32B LE) + vout(4B LE))  
hashSequences = if ANYONECANPAY or base in {NONE,SINGLE}: 0x00...00 else SHA256(concat all sequence(4B LE))  
hashOutputs = if ALL: SHA256(concat all SerOut = value(8B LE) + SerBytes(scriptPubKey))  
elif SINGLE and in_idx < len(vout): SHA256(SerOut(vout[in_idx]))  
else: 0x00...00

preimage = u32le(tx.version) || hashPrevouts || hashSequences || SerPrevout(in.prevout) || u64le(prev.value) || SerBytes(prev.scriptPubKey) || u32le(in.sequence) || hashOutputs || u32le(tx.locktime) || u32le(sighash_type) || CHAIN_ID (32 bytes) || ext_flag (1 byte: 0x00 key, 0x01 script) || leaf_hash (32 bytes, if ext_flag=0x01)  
msg32 = HASH256(TaggedHash("QPB/SIGHASH", preimage))

9. QIP-0002 — Adaptive Block Weight (Normative)

9.1 Definitions

For validating block at height h, STM and LTM MUST be computed from blocks [max(0, h−W) … h−1] (previous blocks only).  
LT_sample(h) = min(BlockWeight(h), floor((LT_GROWTH_NUM / LT_GROWTH_DEN) * LTM(h-1)))  
LTM(h) = max(WEIGHT_FLOOR_WU, median(LT_sample over min(W_LT, h) blocks))  # Bootstrap: Use floor for missing; LTM(0) = WEIGHT_FLOOR_WU  
STM(h) = max(WEIGHT_FLOOR_WU, median(BlockWeight over min(W_ST, h) blocks))  # Bootstrap: Use floor for missing; STM(0) = WEIGHT_FLOOR_WU  
EffectiveMedian(h) = min(STM(h), LT_CLAMP_FACTOR * LTM(h))  
MaxAllowedWeight(h) = min(ABS_HARD_CAP_WU, MAX_MULTIPLIER * EffectiveMedian(h))  
Median(V) SHALL mean the lower median: sorted(V)[ (len(V)-1)//2 ].

9.2 Consensus Rules (Block Weight)

BlockWeightWU(B) <= MaxAllowedWeight(h)

9.3 Penalty Rule (Coinbase Subsidy)

If W > M: penalty = floor(subsidy * ((W - M)/M)^2)  # Use 128-bit intermediates  
Coinbase value <= subsidy + fees - penalty  
Subsidy: Bitcoin halving—initial 50 QPB/block, halve every 210,000 blocks, 21M cap. Post-2140, tail emission 0.1 QPB/block infinite.

9.4 State Machine Diagram (Informative)

[Diagram: Input BlockWeight → LT_sample clamp → LTM median → STM median → EM min → MaxAllowed]

9.5 Integer-Safe Penalty Evaluation (Normative)

Use 128-bit unsigned for intermediates; floor division.

10. QIP-0003 — PQ Validation Budgets and Resource Limits (Normative)

10.1 PQSigChecks

Sum PQSIGCHECK_COST over all verifies <= MAX_PQSIGCHECK_PER_TX (per tx) and <= MAX_PQSIGCHECK_BUDGET (per block)

10.2 Witness Item Size (Re-stated)

As in 8.1.1.

11. QIP-0004 — PQ Signature Serialization and Verification (Normative)

11.1 pk_ser and sig_ser Parsing

pk_ser := alg_id || pk_bytes (fixed per alg_id)  
sig_ser := sig_bytes (fixed) || sighash_type  
For alg_id=0x11, pk_bytes MUST be 1952 bytes and sig_bytes MUST be 3309 bytes. Any other length is invalid.

11.2 Verification

PQVerify(0x11, pk, msg32, sig): ML‑DSA‑65.Verify (Dilithium3). Failure invalidates spend.

12. Appendix A — Consensus Rule Checklist (Implementers)

A.1 Transaction

- Witness version in {2,3}.

- Sighash includes CHAIN_ID, ext_flag, leaf_hash.

- PQVerify succeeds.

A.2 Block

- Weight <= max allowed.

- PQSigChecks <= budgets.

- Penalty applied.

13. Appendix B — Test Vector Schema (Normative Recommendation)

tx_hex: [TBD hex]  
prevout: value=100000, scriptPubKey=OP_3 PUSH32(qpkh32)  
witness: sig_ser (3310B), pk_ser (1953B)  
Expected: Valid; msg32=[32B hash]

Example Vector 2: Invalid Sig (P2QPKH)  
[Similar; flip bit in sig; Expected: Invalid]

Example Vector 3: P2QTSH with OP_CTV  
[Script with OP_CTV; Expected: Valid if template matches]

14. References (Informative)

- NIST FIPS 204 (ML-DSA).

- NIST FIPS 205 (SLH-DSA).

- BIP 360, 347, 141, 119.

- Monero Dynamic Block Size (The Monero Book).

- Chaincode Labs Quantum Report.

- SHRINCS Research (Delving Bitcoin, Dec 2025) (reserved / research track).

- NIST IR 8545 (HQC KEM selection, March 2025).

Roadmap: STARK aggregation for batch verifies (1KB proof/n sigs).
