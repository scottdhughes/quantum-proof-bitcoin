# PQBTC SHRINCS Transaction Envelope v0

## Status: DESIGN CANDIDATE - CONSENSUS DISABLED - RELEASE HOLD
## Spec-ID: PQBTC-SHRINCS-TX-v0
## Evidence-Updated: 2026-08-16
## Consensus-Relevant: NO

## Decision

Define and test a candidate transaction-authorization envelope for the pinned
current SHRINCS draft without changing the node's accepted transaction set.

The preferred first architecture is a **dedicated native witness version**, not
a reusable general-purpose `OP_CHECKSHRINCS` opcode. The candidate is called
`P2SHRINCS-v0` in this document. It has exactly one public-key commitment and
exactly one SHRINCS verification per input.

This record does not:

- allocate or activate witness version 2;
- alter Script, consensus, policy, wallet, descriptors, PSBT, or address
  encoding;
- select a production chain ID or genesis;
- admit the research verifier as a production backend;
- approve the pinned SHRINCS draft for real value; or
- remove the production release hold.

## Why a dedicated witness version is stronger than an opcode

The current verifier evidence gives exact portable SHA-256 bounds for the fixed
32-byte transaction digest and fixed 22-byte SHRINCS context.

For a stateful signature at FXMSS depth `d`:

```text
signature bytes      = 538 + 16d
SHA-256 compressions = 497 + 2d
margin                = 41 + 14d > 0
```

For the stateless recovery signature:

```text
signature bytes          = 5,776
worst-case compressions = 5,534
margin                    = 242
```

Thus, for every canonical signature in the pinned profile, the numerical
count of portable SHA-256 compressions is strictly less than the number of
signature bytes. This is a useful monotonic resource invariant, but bytes and
compression calls are different units and it does not by itself price CPU work.
The decisive architectural property is that a dedicated path performs exactly
one verification per input, so an attacker cannot multiply verification work
by reusing one witness inside a script.

A generic opcode weakens that property: Script may duplicate or reuse the same
signature and public key and invoke the verifier repeatedly unless a separate
execution-cost meter is introduced. A dedicated witness program avoids that
new metering surface, avoids the historical 520-byte stack-element limit, and
makes parsing and resource accounting exact.

This does not rule out a future `OP_CHECKSHRINCS`. It establishes that a native
single-verification path is the safer first PQBTC experiment.

## Candidate output

The design candidate uses witness version 2 with a 32-byte program:

```text
scriptPubKey = OP_2 PUSH32 program

program = TaggedHash(
    "PQBTC/SHRINCS/OUTPUT/v0",
    public_key_48
)
```

The tag is ASCII without a terminating null byte. `TaggedHash(tag, m)` is:

```text
SHA256(SHA256(tag) || SHA256(tag) || m)
```

The public key is the exact canonical 48-byte public key of the pinned current
SHRINCS draft:

```text
PK.seed || PK.sl_root || PK.sf_root
```

The program commits to one immutable profile. An existing output must never be
reinterpreted under a different algorithm or parameter set.

`OP_2` is a **design candidate only**. It remains unallocated and inactive in
the node until a later consensus proposal.

## Pre-activation prohibition

The inherited node does **not** presently enforce this program. Its generic
unknown-witness-version branch returns success for future-soft-fork
compatibility unless a policy discouragement flag is applied. Therefore an
`OP_2 PUSH32` output created under the current node is not a SHRINCS lock and
must be treated as consensus-anyone-can-spend.

Until a fresh PQBTC chain activates exact v0 semantics, wallet, RPC, descriptor,
PSBT, mining, and address-generation code must not create or advertise these
outputs. Any node-level research prototype must reject the candidate program
while activation is disabled; merely leaving it unknown is unsafe.

## Candidate witness

A spend has exactly two witness items:

```text
0: canonical SHRINCS signature
1: canonical 48-byte SHRINCS public key
```

No annex, script, control block, sighash byte, additional item, or empty
placeholder is permitted.

The public key must hash to the output program before signature verification.
The signature must be one of:

- stateful: 554 through 4,618 bytes, in steps of 16 bytes;
- stateless recovery: exactly 5,776 bytes.

Length distinguishes the stateful and stateless components of the **same frozen
SHRINCS profile**. It is not cross-algorithm dispatch.

## Transaction digest

Version zero supports only fixed `SIGHASH_ALL`. No hashtype byte is appended to
the signature.

For transaction `tx`, input index `i`, and a 32-byte network `chain_id`, compute:

```text
hash_prevouts = SHA256(
    concat(outpoint_j for every input j)
)

hash_amounts = SHA256(
    concat(uint64_le(amount_j) for every input j)
)

hash_scriptpubkeys = SHA256(
    concat(compact_size(len(scriptPubKey_j)) || scriptPubKey_j
           for every spent input j)
)

hash_sequences = SHA256(
    concat(uint32_le(sequence_j) for every input j)
)

hash_outputs = SHA256(
    concat(uint64_le(value_k) || compact_size(len(scriptPubKey_k)) ||
           scriptPubKey_k for every output k)
)
```

The proposed preimage is:

```text
0x00                                  # sighash epoch
0x01                                  # fixed SIGHASH_ALL
chain_id[32]
int32_le(tx.version)
uint32_le(tx.lock_time)
hash_prevouts[32]
hash_amounts[32]
hash_scriptpubkeys[32]
hash_sequences[32]
hash_outputs[32]
0x00                                  # no annex, no script path
uint32_le(input_index)
```

The 32-byte message signed by SHRINCS is:

```text
TaggedHash("PQBTC/SHRINCS/TXSIG/v0", preimage)
```

The SHRINCS context is fixed to the 22 ASCII bytes:

```text
PQBTC/SHRINCS/TXSIG/v0
```

The digest commits to:

- network identity;
- version and lock time;
- every prevout, input count, and input order;
- every spent amount;
- every spent scriptPubKey, including the current output commitment;
- every input sequence;
- every output amount and scriptPubKey, output count, and output order; and
- the current input index.

Version zero has no `SIGHASH_NONE`, `SIGHASH_SINGLE`, `ANYONECANPAY`, annex,
script path, code-separator, or key-path variant.

## Network chain ID

The production `chain_id` is not selected here because PQBTC's canonical
network genesis and identity reset must be frozen first. The later consensus
proposal must derive or assign one 32-byte constant per network and must bind it
to the final genesis configuration.

The committed design vector uses only this explicitly non-production test
constant:

```text
SHA256("PQBTC-SHRINCS-TX-V0-TEST-CHAIN")
```

A signature from one network must not verify on another.

## Resource and weight observations

For a one-input, two-P2SHRINCS-output transaction with an empty scriptSig, the
candidate weights are:

| Signature path | Signature bytes | Approx. transaction weight | 4M-WU upper count | Approx. tx/s at 10 minutes |
| --- | ---: | ---: | ---: | ---: |
| minimum stateful | 554 | 1,157 WU | 3,457 | 5.762 |
| maximum stateful | 4,618 | 5,221 WU | 766 | 1.277 |
| stateless recovery | 5,776 | 6,379 WU | 627 | 1.045 |

These are structural calculations for the candidate envelope, not throughput or
fee promises. They omit realistic multi-input mixes and non-signature node
costs.

The byte/compression inequality is limited to the signature verifier and is
not a fee calibration. Transaction sighash preprocessing, UTXO access, Script
dispatch, block propagation, and other validation work still require full-node
benchmarks.

## Validation model

`contrib/shrincs-tx/tx_model.py` independently specifies:

- CompactSize and transaction serialization used by the design;
- output commitment and candidate scriptPubKey;
- strict witness parsing;
- fixed transaction digest;
- signature-length classification;
- candidate transaction weight; and
- the signature-byte-versus-compression-count inequality.

The committed vector freezes the model's current output. CI must regenerate it
byte-for-byte.

The signed-seam harness additionally:

1. derives a deterministic current-draft SHRINCS key;
2. constructs a synthetic two-input transaction;
3. signs input zero's digest statefully through the pinned executable draft;
4. verifies the signature through both the draft and the independent C
   verifier;
5. validates the output commitment and exact two-item witness; and
6. proves that mutations to both existing inputs and outputs, their count and
   order, every transaction commitment surface, the input index, chain ID, or
   SHRINCS context invalidate the signature.

## Gates before node integration

A later implementation proposal may add disabled regtest plumbing only after:

1. this exact model and signed seam are green;
2. the production chain-ID derivation is frozen with unique PQBTC genesis data;
3. an independent review confirms the digest commits to every intended field;
4. transaction-digest cache and multi-input resource bounds are measured;
5. canonical witness and error semantics are specified;
6. no algorithm fallback or legacy `CHECKSIG` path remains reachable;
7. the current inherited node is tested to reject creation and use of the
   candidate output while activation is disabled;
8. activation is impossible in release builds; and
9. the controlling release hold remains machine-enforced.

Independent cryptographic review, consensus-code audit, signer-state safety,
hardware-signer evidence, and a zero-value labnet remain required before any
activation proposal.
