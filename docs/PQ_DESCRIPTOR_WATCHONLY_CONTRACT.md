# PQBTC Watch-Only `pq(...)` Descriptor Contract

## Status: ACTIVE
## Spec-ID: PQ-DESCRIPTOR-WATCHONLY-v1
## Frozen-By: track-a-phase1-20260406
## Consensus-Relevant: NO

## Purpose

Define the currently owned contract for fixed watch-only `pq(...)` descriptors.

This note is intentionally narrower than the broader descriptor roadmap. It
captures what the repo already supports today for importing, persisting,
introspecting, and tracking funds with a fixed public PQ descriptor.

## Scope

This contract covers:

- top-level `pq(PK_script)` parsing and inference
- watch-only wallet import behavior for fixed `pq(...)` descriptors
- descriptor round-trip and address derivation behavior
- persistence and balance tracking for imported `pq(...)` outputs
- the current watch-only spend-preparation boundary for fixed `pq(...)`
  descriptors

## Out Of Scope

This contract does not define:

- active ranged wallet managers
- `getnewpqaddress` behavior
- external signer standards
- replacement `tr(...)` semantics
- generic address-type migration policy

Those belong to adjacent or later work, especially `pqpriv(...)` managers and
descriptor-creation follow-ons.

## Canonical Contract

### 1. Descriptor form

`pq(...)` is a top-level only descriptor over one fixed PQ `PK_script`.

Owned constraints:

- `PK_script` must be valid hex
- `PK_script` must be exactly `pqsig::PK_SCRIPT_SIZE` bytes
- `PK_script` must use the active `ALG_ID_RC2`
- `pq(...)` cannot be nested inside wrappers such as `wsh(...)`

### 2. Script form

`pq(PK_script)` expands to the standard PQ witness program already used in the
repo today:

- witness script: `<PK_script> OP_CHECKSIG`
- scriptPubKey: `P2WSH(witness_script)`
- output type: `bech32`

This is a single-type descriptor with one output script and a two-element
maximum witness satisfaction:

- PQ signature
- witness script

### 3. Wallet import posture

A fixed `pq(...)` descriptor is watch-only and non-ranged.

Current import contract:

- `importdescriptors([{desc: pq(...), timestamp: ...}])` succeeds
- keypool remains `0`
- `active=true` is rejected
- `range` is rejected
- `next_index` is rejected

In simple terms: `pq(...)` is for watching one exact PQ output shape, not for
running an active wallet manager.

### 4. Introspection contract

Current RPC-visible expectations:

- `getdescriptorinfo(pq(...))`
  - `isrange = false`
  - `issolvable = true`
  - `hasprivatekeys = false`
- `deriveaddresses(pq(...))` returns exactly one address
- `getaddressinfo(address)["desc"]` round-trips to the descriptor
- `getaddressinfo(address)["has_private_keys"] = false`
- `listdescriptors()` returns the descriptor as watch-only, inactive state

Private export is intentionally unavailable for this fixed public descriptor:

- `listdescriptors(true)` fails with `Can't get descriptor string`

### 5. Persistence and watch-only tracking

Imported `pq(...)` descriptors must:

- survive unload/load
- preserve descriptor round-trip after reload
- track funds sent to the standard PQ `P2WSH` output
- report the watched UTXO and watch-only balance correctly

### 6. Watch-only spend-preparation boundary

Imported fixed `pq(...)` descriptors are watch-only but still solvable enough to
prepare a PSBT-backed send when the wallet is given the exact tracked input and
no change output is needed.

Current owned expectations:

- `listunspent()` reports the tracked coin as solvable
- `listunspent()[*]["has_private_keys"] = false`
- `send(..., psbt=true)` can return an incomplete PSBT when the caller
  preselects the tracked input and uses `subtract_fee_from_outputs` to avoid
  change
- the watch-only wallet does not add PQ proprietary partial-signature fields
- `walletprocesspsbt(finalize=false)` on that watch-only wallet remains
  non-signing and incomplete

This is a spend-preparation boundary only. It does not make the fixed watch-only
descriptor an active signer.

Deprecated RPC metadata is intentionally not the contract here:

- `getaddressinfo()["iswatchonly"]` remains deprecated and always `false`
- `listunspent()[*]["spendable"]` remains deprecated and always `true`

For fixed public `pq(...)` descriptors, the owned source-of-truth fields are
`private_keys_enabled = false` at wallet scope plus
`has_private_keys = false` at address/coin scope.

### 7. Relationship to `pqpriv(...)`

`pq(...)` and `pqpriv(...)` are related, but not interchangeable:

- `pq(...)` is fixed, public, watch-only, and non-ranged
- `pqpriv(...)` is ranged, active-wallet-capable, and rooted in a private seed

When the repo can infer a fixed public descriptor from a derived PQ wallet
output, the inferred public form is `pq(...)`, not `pqpriv(...)`.

## Rejected Shapes

The following are intentionally rejected today:

- malformed hex in `pq(...)`
- wrong-length `PK_script`
- wrong `ALG_ID`
- nested `pq(...)` expressions
- active/ranged import settings on a fixed watch-only `pq(...)` descriptor

## Evidence

Implementation references:

- [descriptor.cpp](/Users/scott/quantum-proof-bitcoin/src/script/descriptor.cpp)
- [pq_scriptpubkeyman.cpp](/Users/scott/quantum-proof-bitcoin/src/wallet/pq_scriptpubkeyman.cpp)
- [backup.cpp](/Users/scott/quantum-proof-bitcoin/src/wallet/rpc/backup.cpp)

Current test evidence:

- [pq_descriptor_tests.cpp](/Users/scott/quantum-proof-bitcoin/src/test/pq_descriptor_tests.cpp)
- [wallet_pq_descriptors.py](/Users/scott/quantum-proof-bitcoin/test/functional/wallet_pq_descriptors.py)

## Confidence Snapshot

Targeted confidence pass run on 2026-04-08:

- `build/bin/test_pqbtc --run_test=pq_descriptor_tests`
  - result: passed
- `python3 test/functional/wallet_pq_descriptors.py`
  - result: passed
  - covers import rejection guards, descriptor round-trip, reload persistence,
    watch-only tracking, and the fixed watch-only non-signing PSBT-preparation
    boundary

Interpretation:

- the fixed public `pq(...)` descriptor contract is healthy
- the current owned boundary between fixed watch-only `pq(...)` and active
  ranged `pqpriv(...)` behavior is explicit and test-backed
- the suite is now strong enough to sit in the required PQ-first functional
  gate

## Next Follow-On

The next descriptor-facing question is not whether fixed `pq(...)` works. It
does.

The next owned follow-on is:

- [wallet_createwalletdescriptor.py](/Users/scott/quantum-proof-bitcoin/test/functional/wallet_createwalletdescriptor.py)

That is where the repo needs to decide how much descriptor creation behavior it
wants to own under an all-PQ Track A stance instead of inheriting old Taproot
expectations.
