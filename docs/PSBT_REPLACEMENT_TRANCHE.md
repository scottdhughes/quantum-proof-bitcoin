# PQBTC PSBT Replacement Tranche

## Status: ACTIVE
## Spec-ID: PSBT-REPLACEMENT-TRANCHE-v1
## Frozen-By: track-a-phase1-20260406
## Consensus-Relevant: NO

## Purpose

Define the first owned product-facing Track A tranche for post-v1 Taproot
replacement work.

This tranche is intentionally bounded. It does not attempt to solve all future
wallet, descriptor, RPC, or witness-v1 semantics at once. Its job is to make
the PQ-native PSBT path explicit, freeze the restored inherited pre-taproot
decode/finalize seam, and keep both correctly bounded away from Taproot
replacement semantics.

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
- restored inherited pre-taproot PSBT decode/finalize compatibility for the
  current classical single-key and multisig watch-only flows
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
- binary value carrying the fixed-size PQ signature for the implemented profile
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

Relevant neighboring surfaces that remain follow-on work for replacement
semantics:

- [wallet_createwalletdescriptor.py](../test/functional/wallet_createwalletdescriptor.py)
- [wallet_address_types.py](../test/functional/wallet_address_types.py)
  Required for the current address/RPC boundary; still deferred for
  replacement-path address semantics.
- [wallet_pq_descriptors.py](../test/functional/wallet_pq_descriptors.py)

## Primary Test Surfaces

- [wallet_pq_psbt.py](../test/functional/wallet_pq_psbt.py)
  End-to-end wallet PSBT parity for active `pqpriv(...)` managers.
- [rpc_psbt.py](../test/functional/rpc_psbt.py)
  Broad inherited PSBT RPC surface that now owns both the active-PQ subset and
  the restored inherited pre-taproot decode/finalize path.
- [pqsig_script_tests.cpp](../src/test/pqsig_script_tests.cpp)
  PQ proprietary partial-signature round-trip and rejection guards.

## Frozen `rpc_psbt.py` Boundary

The owned `rpc_psbt.py` surface now covers both the PQ-native path and the
restored inherited pre-taproot finalize path:

- blank descriptor wallet created inside the test
- active PQ managers initialized only through `createpqwalletmanagers`
- one PQ-owned UTXO funded with the existing `create_wallet_funded_tx` helper
- one owned PSBT flow:
  `walletcreatefundedpsbt -> walletprocesspsbt(finalize=false) -> decodepsbt -> finalizepsbt`
- inherited classical `pkh(...)`, multisig, and watch-only signer flows remain
  active inside the same test and must decode, finalize, and broadcast
  successfully
- Taproot-facing PSBT semantics remain explicitly deferred; no inherited
  witness-v1 replacement behavior is implied by this tranche

Nothing in this tranche owns replacement-path Taproot semantics or generic
witness-v1 behavior.

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

Current validation reference:

- `build/test/functional/test_runner.py --jobs=1 rpc_psbt.py`
  - result: passed
  - current posture:
    - active `pqpriv(...)` wallet PSBT processing succeeds inside
      `rpc_psbt.py`
    - `decodepsbt` exposes exactly one `pqbtc` proprietary partial-signature
      field per signed PQ input
    - no inherited Taproot field is implied for the owned PQ path
    - `finalizepsbt` produces the expected
      `[pq_signature, witness_script]` witness shape with the fixed
      4480-byte signature payload
    - inherited classical `pkh(...)`, multisig, and watch-only PSBT paths also
      decode, finalize, and broadcast successfully
- `python3 test/functional/wallet_pq_psbt.py`
  - result: passed

Interpretation:

- the owned PQ-native PSBT path is healthy in both the dedicated wallet suite
  and `rpc_psbt.py`
- inherited classical pre-taproot PSBT decode/finalize compatibility is
  restored and no longer a deferred failure boundary

Frozen decision:

- Track A remains all-PQ
- inherited classical pre-taproot PSBT decode / finalize compatibility is now
  part of the owned Track A wallet contract
- `rpc_psbt.py` belongs in `pq_required`, while Taproot-facing PSBT semantics
  remain deferred in the replacement matrix

## Follow-On Questions

The next questions after this tranche should be:

1. Should PQBTC expose a richer decode view for the PQ proprietary field?
2. Does `feature_coinstatsindex_compatibility.py` become the next owned
   follow-on once real prior PQBTC release assets exist?
3. If the asset-dependent compatibility path stays blocked, is broader
   inherited miniscript funding/finalization rehab the next wallet-side slice?

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

- Current inventory posture: `pq_required`, `deferred`
- Current owned boundary:
  - inherited address-shape smoke coverage
  - descriptor-wallet `bech32m` address-shape smoke coverage
  - inherited mixed-address `sendmany("", sends)` positive control
  - PQ-only inherited `getnewaddress` / `getrawchangeaddress` rejection
    coverage for valid explicit address types, including `bech32m`
  - invalid address-type precedence
- Goal:
  keep this explicit address/RPC boundary required while replacement-path
  Taproot/address semantics remain deferred

### 4. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`

- Current inventory posture: `pq_required`, `deferred`
- Current owned boundary:
  - keeps inherited xpub-backed decaying miniscript descriptor import as the
    watch-only multisig coordination context
  - uses inherited coordinator `sendtoaddress(...)` funding into the decaying
    multisig receive address
  - owns `walletcreatefundedpsbt` plus serial signer participation across the
    full decaying locktime loop
  - owns the non-final rejection boundary before the relevant locktime is
    reached
  - owns successful finalization and broadcast after maturity as the required
    signer threshold decays from 4-of-4 to 1-of-4
  - belongs in `pq_required`

### 5. `wallet_miniscript.py`

- Current inventory posture: `pq_required`, `deferred`
- Current owned boundary:
  - keeps the inherited miniscript sanity guards for insane and unsatisfiable
    descriptors
  - owns watch-only import, address derivation, and funding detection across
    the current `wsh(...)` Miniscript and in-file `tr(...)` descriptor set
  - owns signer-backed funding, PSBT signing, finalization, and broadcast
    across the current satisfiable Miniscript and TapMiniscript descriptor set
  - preserves deliberate incomplete cases when the wallet lacks sufficient keys
    or cannot collapse multiple viable leaves into a single final witness
  - owns the max-size TapMiniscript positive import/spend seam plus one oversize
    negative-control import failure
  - keeps ranged xpub/tprv miniscript imports and one TapMiniscript xpub import
    as deferred invalid-key controls
  - belongs in `pq_required`

### 6. `wallet_multisig_descriptor_psbt.py`

- Current inventory posture: `pq_required`
- Current owned boundary:
  - keeps inherited xpub-backed `wsh(sortedmulti(...))` descriptor import as
    watch-only reference context
  - keeps cross-participant receive/change address agreement as part of that
    watch-only descriptor contract
  - freezes one inherited coordinator `sendtoaddress(...)` failure as the
    deferred classical funding boundary
  - uses direct coinbase generation into the multisig receive address to create
    one real watch-only UTXO without reopening inherited send-path semantics
  - preserves watch-only
    `walletcreatefundedpsbt -> decodepsbt -> walletprocesspsbt(finalize=false)`
    coverage for the resulting watch-only multisig
  - freezes the first inherited signer
    `walletprocesspsbt(finalize=false)` contribution seam as a real raw-PSBT
    boundary: signer 0 returns an incomplete PSBT carrying exactly one
    classical-looking `partial_sig` entry for the input
  - owns node-side `decodepsbt`, subsequent signer processing, `combinepsbt`,
    `finalizepsbt`, and successful broadcast of that signed PSBT under the
    current pre-taproot signature rules
  - belongs in `pq_required`

## Explicit "Not Next" Surfaces

These are useful references, but they should not drive the next Track A slice:

- `feature_taproot.py`
  Current posture: `legacy_only`
- `wallet_taproot.py`
  Current posture: `legacy_only`

They are good negative-control context, not the next owned replacement work.

## Immediate Debug Queue

Before widening the next tranche, the next debug questions should be:

1. Is `feature_blocksdir.py` now the cleanest next validation tranche after
   freezing `wallet_multisig_descriptor_psbt.py`?
2. Is there any smaller remaining wallet-adjacent surface than broad inherited
   classical multisig funding/signing rehab, or should that stay deferred?
3. Should chainstate-facing backlog reduction resume before reopening any of
   those broader inherited wallet compat paths?
