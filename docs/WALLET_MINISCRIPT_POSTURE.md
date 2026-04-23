# PQBTC `wallet_miniscript.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-MINISCRIPT-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for the current inherited miniscript and
TapMiniscript wallet import, funding, signing, and finalization surface.

## Current Owned Surface

The current passing
[wallet_miniscript.py](../test/functional/wallet_miniscript.py) suite owns a
broader wallet miniscript contract:

- inherited miniscript sanity guards for insane and unsatisfiable descriptors
  remain active
- the in-file watch-only descriptor set can be imported, derive addresses, and
  detect funds across both `wsh(...)` Miniscript and the currently implemented
  `tr(...)` branches
- the signer-backed descriptor set can be imported, funded, signed, finalized,
  and broadcast for satisfiable branches across both Miniscript and the current
  TapMiniscript coverage in-file
- `walletprocesspsbt(finalize=false)` exposes the expected number of
  `partial_signatures` or `taproot_script_path_sigs` entries before
  finalization
- deliberate under-keyed or ambiguous branch-selection cases remain incomplete
  by design rather than failing at a signature-encoding wall
- the suite owns relative-locktime, absolute-locktime, preimage, multi-key,
  and witness-size-selection behavior within the current wallet harness
- the max-size TapMiniscript import/spend boundary is covered positively, and
  one oversize import remains a negative control
- ranged xpub/tprv miniscript imports and one TapMiniscript xpub import remain
  explicit invalid-key deferred controls

## What This Does Not Mean

This posture note does **not** mean:

- replacement-path TapMiniscript or witness-v1 activation semantics are defined
- generic relay, mempool, or policy behavior is implied beyond this wallet test
- broad non-descriptor inherited funding/send-path behavior is complete

## Confidence Snapshot

Current validation reference:

- `build/test/functional/test_runner.py --jobs=1 wallet_miniscript.py`
  - result: passed
  - current posture:
    - watch-only and signer-backed descriptor imports stay green across the
      current Miniscript and TapMiniscript fixtures
    - satisfiable signer-backed PSBTs finalize and broadcast successfully
    - intentionally under-keyed cases remain incomplete without regressing the
      rest of the signer/finalize surface
    - max-size TapMiniscript spend coverage remains green

## Interpretation

- `wallet_miniscript.py` is now a fixed wallet miniscript
  funding/signing/finalization contract, not a narrow non-signing carveout
- it belongs in `pq_required`, while its `taproot_matrix_bucket` remains
  `deferred` because replacement-path meaning is still separate work
- the next clean follow-on can rebalance toward chainstate/validation work
  instead of reopening the same wallet surface again
