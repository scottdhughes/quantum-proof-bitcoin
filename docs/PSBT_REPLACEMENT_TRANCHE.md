# PQBTC PSBT Replacement Tranche

## Status: ACTIVE
## Spec-ID: PSBT-REPLACEMENT-TRANCHE-v1
## Frozen-By: track-a-phase1-20260406
## Consensus-Relevant: NO

## Purpose

Define the first owned product-facing Track A tranche for post-v1 Taproot
replacement work.

This tranche is intentionally narrow. It does not attempt to solve all future
wallet, descriptor, RPC, or witness-v1 semantics at once. Its job is to make
the PQ-native PSBT path explicit, testable, and correctly bounded.

## Why This Tranche Comes First

- It is user-facing and wallet-adjacent rather than purely theoretical.
- It already has real PQ-native coverage in the repo.
- It forces explicit decisions about how PQ signatures move through the
  signing/finalization path without silently inheriting Taproot semantics.
- It is narrow enough to finish cleanly before broader descriptor or address
  work.

## Scope

This tranche covers:

- PQ-native PSBT creation, processing, decode, and finalization behavior for
  the currently implemented PQ wallet path
- the proprietary PQ partial-signature representation already exercised in-tree
- RPC-visible expectations for the existing PQ wallet flow
- explicit boundaries between current PQ-native PSBT behavior and deferred
  Taproot-replacement PSBT behavior

## Out Of Scope

This tranche does not define:

- generic witness-v1 or inherited Taproot PSBT semantics
- `tr(...)` descriptor semantics for the replacement path
- replacement address encoding rules
- a new production external-signer standard
- multi-algorithm PSBT negotiation beyond the current active PQ profile
- any consensus change

## Current Implemented Facts

The current repo already demonstrates the following behavior:

1. A blank descriptor wallet can activate PQ-native receive and change managers
   through the dedicated `createpqwalletmanagers` RPC and spend through a
   PQ-native PSBT flow.
2. `walletcreatefundedpsbt` followed by `walletprocesspsbt(finalize=false)`
   produces a PSBT that carries one PQ proprietary partial-signature field on
   each relevant PQ input.
3. On PQ-only active wallets, explicit-input and automatic-input
   `walletcreatefundedpsbt` flows keep automatic change on the active internal
   `pqpriv(...)` manager rather than re-entering inherited change-address
   behavior, including the current `changePosition` and
   `subtractFeeFromOutputs` option edges.
4. That proprietary field uses:
   - identifier: `pqbtc`
   - subtype: `1`
   - key suffix: the active `pk_script`
   - value: the current fixed-size PQ signature payload (`4480` bytes in binary)
5. Finalization consumes that PQ proprietary partial signature and emits the
   expected final witness stack:
   - stack item 0: fixed-size PQ signature
   - stack item 1: witness script
6. Non-active PQ `pk_script` values in that proprietary partial-signature field
   are rejected during PSBT round-trip parsing.
7. The lower-level `importdescriptors` path for active `pqpriv(...)` managers
   still works and remains lightly exercised as descriptor-level setup coverage.

These facts are already exercised in:

- [wallet_pq_psbt.py](../test/functional/wallet_pq_psbt.py)
- [pqsig_script_tests.cpp](../src/test/pqsig_script_tests.cpp)
- [PQ_WALLET_MANAGER_SETUP.md](PQ_WALLET_MANAGER_SETUP.md)

## Canonical Semantics For This Tranche

### 1. Current PQ-native signing path

For the active PQ wallet path, PSBT signing is represented through the existing
proprietary input field rather than through inherited Taproot PSBT fields.

### 2. Proprietary field contract

The current tranche treats the following as the owned PQBTC contract:

- identifier `pqbtc`
- subtype `1`
- binary value carrying the fixed-size PQ signature for the active profile
- key material bound to the active `pk_script`

This is the current PQ-native bridge between wallet signing and PSBT
finalization.

### 3. Finalization contract

For this tranche, finalization of the PQ-native PSBT path must produce the
existing witness form that the repo already validates:

- PQ signature
- revealed witness script

This tranche does not redefine sighash behavior. The current fixed
`SIGHASH_ALL` posture remains in force.

### 4. Decode visibility

`decodepsbt` should expose the PQ proprietary field clearly enough for testing
and debugging, but this tranche does not require a brand-new human-facing PSBT
schema beyond the currently decoded proprietary representation.

### 5. Active-profile restriction

The proprietary PQ partial-signature field is owned only for the currently
active PQ profile. Invalid or non-active `pk_script` values must continue to
reject.

## Deferred Boundaries

The following remain explicitly deferred after this tranche:

- inherited Taproot PSBT fields as replacement semantics
- `tr(...)` descriptor meaning for replacement outputs
- address-type promotion for replacement semantics
- generic wallet address-type behavior involving witness-v1 replacement outputs
- production external signer interface standardization

Relevant neighboring surfaces that remain follow-on work:

- [wallet_createwalletdescriptor.py](../test/functional/wallet_createwalletdescriptor.py)
- [wallet_address_types.py](../test/functional/wallet_address_types.py)
- [wallet_pq_descriptors.py](../test/functional/wallet_pq_descriptors.py)

## Primary Test Surfaces

- [wallet_pq_psbt.py](../test/functional/wallet_pq_psbt.py)
  End-to-end wallet PSBT parity for active `pqpriv(...)` managers.
- [rpc_psbt.py](../test/functional/rpc_psbt.py)
  Broad inherited PSBT RPC surface that this tranche must not accidentally
  destabilize.
- [pqsig_script_tests.cpp](../src/test/pqsig_script_tests.cpp)
  PQ proprietary partial-signature round-trip and rejection guards.

## Expected Deliverables

Phase-1 completion for this tranche means:

1. this semantics doc is checked in
2. the tranche boundaries are explicit
3. the highest-value PSBT follow-on gaps are ranked
4. targeted tests can be run without ambiguity about what behavior is owned now

Phase-2 completion for this tranche means:

1. any needed RPC/PSBT clarifications are implemented
2. tests and docs agree on the proprietary PQ partial-signature path
3. no inherited Taproot PSBT semantics are accidentally implied

## Current Confidence Snapshot

Targeted confidence pass run on 2026-04-08:

- `build/bin/test_pqbtc --run_test=pqsig_script_tests`
  - result: passed
- `python3 test/functional/test_runner.py --jobs=1 wallet_pq_psbt.py`
  - result: passed
  - current posture: dedicated `createpqwalletmanagers` setup for the main
    spend/PSBT path, explicit `fundrawtransaction` PQ-change coverage, explicit
    automatic-input `walletcreatefundedpsbt` PQ-change coverage, including
    `changePosition` and `subtractFeeFromOutputs`, with one retained low-level
    `importdescriptors` check
- `python3 test/functional/test_runner.py --jobs=1 rpc_psbt.py`
  - result: failed
  - failing point: `finalizepsbt`
  - observed error: `TX decode failed Signature is not a valid encoding`

Interpretation:

- the owned PQ-native PSBT path is healthy
- the broader inherited PSBT RPC surface still contains at least one path that
  does not cleanly fit PQBTC's current signature semantics

Narrowed root cause:

- the failing repro spends classical `pkh(...)` inputs from the default wallet,
  not the active `pqpriv(...)` path
- `walletprocesspsbt(finalize=false)` emits ordinary-looking classical
  `partial_sigs` for those inputs
- `decodepsbt` / `finalizepsbt` then reject that signed PSBT because
  [interpreter.cpp](../src/script/interpreter.cpp#L75)
  currently makes `CheckSignatureEncoding()` PQ-only for all pre-taproot paths:
  any non-empty signature whose size is not `pqsig::SIG_SIZE` is rejected as
  `SCRIPT_ERR_SIG_DER`

This means the current blocker is not a mystery in the owned PQ-native tranche.
It is an explicit compatibility break in the inherited classical PSBT decode /
finalize path.

Decision boundary:

- if PQBTC intends to keep classical pre-taproot PSBT flows alive during the
  migration window, it needs dual-mode signature encoding validation here
- if PQBTC intends to drop those flows, `rpc_psbt.py` should stay out of the
  owned tranche and be marked as explicitly deferred legacy compatibility work

Current decision:

- Track A is all-PQ
- inherited classical pre-taproot PSBT decode / finalize compatibility is not
  part of the owned tranche
- `rpc_psbt.py` remains a useful reference surface, but its classical signing
  expectations should be treated as deferred legacy compatibility work rather
  than a blocker on PQ-native progress

## Follow-On Questions

The next questions after this tranche should be:

1. Should PQBTC expose a richer decode view for the PQ proprietary field?
2. Which descriptor surface should be promoted next after PSBT:
   `wallet_createwalletdescriptor.py` or `wallet_pq_descriptors.py`?
3. What is the smallest safe replacement-path bridge from PQ-native PSBT
   behavior toward future replacement witness-v1 semantics without importing
   inherited Taproot behavior wholesale?

## Ranked Follow-On Queue

This is the current best next-work ranking after the initial PSBT tranche
semantics are frozen.

### 1. `wallet_pq_descriptors.py`

- Current inventory posture: `pq_backlog`
- Why first:
  - already PQ-specific instead of inherited Taproot-first
  - close to the owned PSBT tranche because it exercises `pq(...)`
    descriptor behavior directly
  - lower semantic risk than broad address-type or miniscript work
- Goal:
  tighten the canonical descriptor contract for fixed watch-only `pq(...)`
  behavior before expanding replacement descriptor creation surfaces

### 2. `wallet_createwalletdescriptor.py`

- Current inventory posture: `pq_backlog`, `deferred` in the Taproot migration
  matrix
- Why second:
  - high leverage descriptor-creation surface
  - directly relevant to future replacement descriptor semantics
  - more dangerous than `wallet_pq_descriptors.py` because it touches inherited
    `tr(...)` / `bech32m` creation paths
- Goal:
  decide what, if anything, should become an explicitly PQBTC-owned replacement
  descriptor creation surface instead of inherited Taproot behavior

### 3. `wallet_address_types.py`

- Current inventory posture: `dual_profile`, `deferred`
- Why third:
  - likely needed eventually for address/output-type policy coherence
  - broad and mixed surface with significant inherited behavior
  - should follow descriptor clarifications, not lead them
- Goal:
  revisit address-type behavior only after descriptor and PSBT boundaries are
  more explicit

### 4. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`

- Current inventory posture: `dual_profile`, `deferred`
- Why fourth:
  - intersects both descriptor and PSBT behavior
  - useful stress case later
  - too indirect for the first replacement tranche

### 5. `wallet_miniscript.py`

- Current inventory posture: `dual_profile`, `deferred`
- Why fifth:
  - large inherited surface
  - high semantic blast radius
  - best handled only after narrower descriptor and PSBT contracts are stable

## Explicit "Not Next" Surfaces

These are useful references, but they should not drive the next Track A slice:

- `feature_taproot.py`
  Current posture: `legacy_only`
- `wallet_taproot.py`
  Current posture: `legacy_only`

They are good negative-control context, not the next owned replacement work.

## Immediate Debug Queue

Before widening this tranche, the next debug questions should be:

1. Which exact `rpc_psbt.py` scenario at the failing line is still assuming an
   inherited non-PQ signature encoding path?
2. Should PQBTC carve out a PQ-specific `rpc_psbt` subset rather than trying to
   preserve the full inherited surface?
3. Is the correct fix:
   - adapting test expectations
   - routing signing/finalization differently for non-PQ paths
   - or explicitly declaring the inherited path out of scope for Track A?
