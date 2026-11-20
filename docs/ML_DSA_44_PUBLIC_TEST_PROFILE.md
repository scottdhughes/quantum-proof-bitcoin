# ML-DSA-44 public test profile

## Status: FROZEN
## Spec-ID: MLDSA44-PUBLIC-TEST-v1
## Frozen-By: owner-public-test-20261110
## Consensus-Relevant: YES

This is an explicitly opted-in, valueless experimental profile authorized by
the owner's 2026-11-10 native qualification and public-soak instruction. It is
not production admission. The production RELEASE_HOLD and human-review-not-
performed record remain. An accurately described public test is permitted by
the owner continuation. No existing network or sealed contract is redefined.

## Identity and selection

Select only through explicit command-line `-chain=test -mldsa44test`, in a Linux
build with `ENABLE_EXPERIMENTAL_MLDSA44=ON`. Config/settings selection, conflicting
demo/network flags and unsupported builds refuse before selecting custody data.
The isolated data directory is `mldsa44-test-v1`; inherited `-chain=test` without
the flag remains its existing Bitcoin-derived fixture.

Use the frozen GENESIS-v1 TEST identity exactly:

- Message start: `a7e29cf7`.
- Genesis display hash: `2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979`.
- Merkle display hash: `d3bf22ef43098736f11406c5bff808e933df335705f4c8c022dcffaa0d26164a`.
- Genesis time `1772119544`, nonce `2499947721`, version `1`, bits `0x207fffff`.
- P2P/RPC ports `23833/23832`, Bech32m HRP `tq`.
- Base58 public/script/secret prefixes `191/187/64`; extended prefixes
  `149,138,123,144` and `146,100,134,147`.

No inherited Bitcoin seeds, checkpoints, assumeutxo snapshots or minimum-chain-
work assumptions select another chain. Manual public bootstrap peers are
operator configuration. The test PoW target is fixed at the declared easy
limit, with no retargeting and on-demand test mining. Target spacing is 60s;
subsidy/halving, maturity, transaction serialization and identifiers retain the
existing rules. Buried validation rules are active from H1, with witness rules
available for that transition. Assumevalid must not skip ML-DSA verification.

## Activation and accepted set

The activation height is H=1. H-1 is the exact TEST genesis. The complete logical
pre-H UTXO inventory must be empty, with zero native v2/32 entries and
SHA256(empty) `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Refuse startup/activation on identity or inventory mismatch. The frozen genesis
coinbase remains unspendable under the inherited genesis special case.

At and after H1, every spendable output, including each coinbase payout, is
`OP_2 PUSH32 <program>`. The only other permitted output is zero-valued
`OP_RETURN` followed by exactly one canonical push of 0..80 bytes. The BIP141
36-byte witness commitment fits this exception. Every non-coinbase prevout must
be native v2/32; scriptSig is empty. Classical, rc2, nested P2SH, witness-v0/v1
and other future-witness output/prevout shapes cannot enter this accepted set.

Native verification uses unchanged CONTRACT-1 bytes, TEST binding, exact
signature/public-key lengths, key commitment, transaction context and all-input
metadata. It never dispatches through PQSIG ALG_ID. The global registry and
other networks retain their existing semantics. Apply profile output/input
rules to mempool acceptance and ConnectBlock, including reindex-chainstate.

Wallet issuance remains disabled before H1. The declared activation bootstrap
may mine H1 to `OP_2 PUSH32` followed by 32 zero bytes, an unowned test-only
program. Then reserve real signer-derived tq addresses and mine directly to
them with normal maturity. OP_TRUE funding is not a public-profile escape hatch.

## Experimental resource contract

When ML-DSA verification is active, each native v2/32 input contributes exactly
625 units to the existing signature-operation cost calculation. The 80,000
block ceiling permits at most 128 ML-DSA verifications; the 16,000 standard-
transaction ceiling permits at most 25. Mempool entries, mining selection and
block validation use that same function and active flag. The inherited
4,000,000-WU block limit remains. The signer's separate 100-input/100-output
service bounds do not become consensus limits.

The reference public-node configuration uses 32 MB maxmempool. Measure actual
admission, pressure/eviction, template selection, 25/26-input transaction and
128/129-input block controls, full-weight validation and malformed rejection.
Before public use, 30 normal-build observations at the block verification limit
must have p95 wall time <=2s and node peak RSS <=1GiB on each declared release
platform/configuration. Record raw values and hardware. Instrumented builds
qualify correctness separately; their timing is not release timing evidence.
This test budget is conservative experimental policy, not general hardware or
cryptographic assurance. A semantic revision requires a new profile Spec-ID.

## Operator and public run

Node RPC reports a distinct `valueless_mldsa44_test` context with scope
`VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY`, H1 state, TEST binding, sealed
CONTRACT-1 hash, this profile hash and its resource limits. Wallet/signer/client
selection is explicit and wrong-network operations refuse. Secrets use the
trusted operator FD channel and never appear in argv, environment, URL, logs,
public metadata or signer IPC. Existing offline demo behavior remains separate.

Only P2P is public. RPC, browser console and signer IPC remain local. A public
TLS ingress/transport adapter may carry the native P2P stream if declared and
tested; private-tailnet connectivity alone is not public operation. The actual
24-hour workload, host/version identities, public endpoint, failure criteria,
resources, fault/upgrade schedule and shutdown controls are bound in a separate
immutable run declaration before starting. Only actual elapsed public run time
counts. Production activation and public-soak success are separate decisions.
