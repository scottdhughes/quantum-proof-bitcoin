# PQBTC SHRINCS Transaction v0 — Unwired C++ Component

## Status

```text
RESEARCH ONLY
CONSENSUS DISABLED
TEST-BINARY ONLY
PRODUCTION BACKEND = NONE
RELEASE HOLD = TRUE
```

This document describes a native C++ reproduction of the consensus-disabled
transaction-envelope model in `contrib/shrincs-tx/`.

The component is deliberately compiled only into `test_pqbtc`. It is not
compiled or linked into `bitcoin_consensus`, `bitcoin_node`, the wallet, RPC,
policy, mining, descriptors, PSBT, or any release executable. No interpreter,
policy, or activation file references its API.

The purpose of this tranche is to answer one narrow question:

> Do Bitcoin Core's native transaction, script, serialization, and hashing
> types reproduce the exact bytes and digests frozen by the independent Python
> model before any consensus integration is attempted?

A passing test answers only that question.

## Candidate byte shape

The inactive candidate output is:

```text
OP_2 PUSH32 program

program = TaggedHash(
    "PQBTC/SHRINCS/OUTPUT/v0",
    public_key_48
)
```

The strict witness is:

```text
[canonical_signature, public_key_48]
```

Canonical signature lengths are:

```text
stateful:  538 + 16 * depth bytes, 1 <= depth <= 255
            554, 570, ..., 4618
stateless: exactly 5776 bytes
```

Every other length is rejected. The length rule distinguishes two modes of one
frozen SHRINCS profile; it is not cross-algorithm negotiation. There is no
ECDSA, Schnorr, held-rc2, ML-DSA, or unknown-algorithm fallback.

## Critical pre-activation fact

The inherited interpreter currently treats unknown witness versions as
future-upgrade success. Therefore `OP_2 PUSH32` is **not** a SHRINCS lock on the
current chain. Until exact semantics are activated on a fresh PQBTC network,
such an output must be treated as consensus-anyone-can-spend.

The C++ component does not create, relay, mine, advertise, or validate the
candidate output through `VerifyWitnessProgram`. `IsScriptPubKey` only
recognizes the proposed byte shape for tests.

## Fixed digest

The component reproduces the Python model's fixed `SIGHASH_ALL` digest:

```text
TaggedHash(
    "PQBTC/SHRINCS/SIGHASH/v0",
    epoch || fixed_sighash_all || chain_id || version || lock_time ||
    hash_prevouts || hash_amounts || hash_scriptpubkeys ||
    hash_sequences || hash_outputs || spend_type || input_index
)
```

where:

```text
hash_prevouts       = SHA256(concat(serialized prevouts))
hash_amounts        = SHA256(concat(uint64_le spent amounts))
hash_scriptpubkeys  = SHA256(concat(CompactSize(script) || script))
hash_sequences      = SHA256(concat(uint32_le sequences))
hash_outputs        = SHA256(concat(serialized outputs))
```

The outer digest uses:

```text
epoch              = 0
fixed_sighash_all  = 1
spend_type         = 0
input_index        = uint32 little-endian
```

The SHRINCS signing context is separately fixed to:

```text
PQBTC/SHRINCS/TXSIG/v0
```

Every input must have an empty `scriptSig`. The caller must provide exactly one
spent `CTxOut` for every transaction input. Invalid counts, input indices,
amounts, or script sizes fail closed.

No production chain ID is selected. Tests use only:

```text
SHA256("PQBTC-SHRINCS-TX-V0-TEST-CHAIN")
```

A production chain ID remains blocked on the unique genesis and network
identity reset.

## Exact native parity evidence

The Boost suite binds the C++ implementation to the Python design vector:

```text
output commitment:
  e4aec884405768485ef6d3407f9d5da17781053f66f7945e8fd1dda7e9e1eb97

input 0 digest:
  e81658399900d55841623b54f075cebfe6c9caf307e62e5952634d16ae61f35d

input 1 digest:
  cdf2b774b68cdbd23a424faee209495c523a790c92fa6ea293e166ea075245e7
```

It also binds the public key used by the independently signed Python/C seam:

```text
output commitment:
  d23ac81a74411a8645d375abd22acf8d10e3e18b96b173ec99d8fb1496759665

transaction digest:
  dc00d9f169e44ad39fea3db0736ee5ec834d8a3ae8e8ac7e8997ee1eacc399d5
```

The suite reproduces exact expected digests for all 22 transaction-surface
mutations from the Python model:

- version and lock time;
- both inputs' prevout txids and indices;
- both spent amounts and scriptPubKeys;
- both sequences;
- input order, removal, and addition;
- both output amounts and scripts; and
- output order, removal, and addition.

The chain ID and input index are tested separately.

## Resource identities

For stateful depth `d`:

```text
signature bytes S(d) = 538 + 16d
minimal tx weight W(d) = 1141 + 16d
portable verifier compressions C(d) = 497 + 2d
S(d) - C(d) = 41 + 14d > 0
```

An independent Wolfram symbolic check gives:

```text
d/d d [C(d) / W(d)] = -5670 / (1141 + 16d)^2 < 0
```

Thus the compression-to-weight ratio is strictly decreasing over all stateful
depths. For a 4,000,000-WU block filled with the model's minimal
one-input/two-output transactions:

```text
stateful depth 1:
  weight per tx          = 1157
  transactions per block = 3457
  compressions per tx    = 499
  block compressions     = 1,725,043

stateful depth 255:
  weight per tx          = 5221
  transactions per block = 766
  compressions per tx    = 1007
  block compressions     = 771,362

stateless recovery:
  weight per tx          = 6379
  transactions per block = 627
  compressions per tx    = 5534
  block compressions     = 3,469,818
```

The stateless path is therefore the dominant minimal-transaction full-block
case under this portable model. These numbers are architectural evidence, not
a fee rate, sigop schedule, activation limit, or supported-platform benchmark.
Coinbase overhead and realistic multi-input transactions reduce the achievable
counts.

## Files and reachability

```text
src/script/shrincs_tx_v0.h
src/script/shrincs_tx_v0.cpp
src/test/shrincs_tx_v0_tests.cpp
ci/test/test_shrincs_tx_cpp_component.py
```

`src/test/CMakeLists.txt` compiles the component source directly into
`test_pqbtc`. A Python architecture guard scans every other C/C++ file under
`src/` and fails if it references `shrincs_tx_v0`.

## Validation

Focused guards:

```bash
python3 -m unittest ci.test.test_shrincs_tx_cpp_component
python3 -m unittest ci.test.test_shrincs_tx_model
```

Native test after the normal project build:

```bash
build/bin/test_pqbtc \
  --run_test=shrincs_tx_v0_tests \
  --catch_system_error=no \
  --log_level=test_suite
```

The repository's ordinary Linux native PQ tranche remains responsible for
compiling and running the Boost suite. The dedicated component workflow adds
scope and reachability checks without creating a second production build path.

## What this does not establish

This tranche does not establish:

- cryptographic security of SHRINCS;
- formal correctness of the C++ component;
- consensus or policy suitability;
- production resource limits;
- signer-state, side-channel, or fault safety;
- wallet, descriptor, PSBT, or external-signer behavior;
- safe activation of witness version 2; or
- real-value network readiness.

## Next attack after native parity

After the native suite is green and independently reviewed, the next smallest
safe step is an **activation-disabled interpreter seam** that explicitly
recognizes the candidate byte shape but fails closed unless a dedicated test
activation flag is supplied. That later tranche must still avoid wallet,
policy, RPC, mining, and release activation and must prove that pre-activation
outputs cannot become silently spendable through the experimental path.
