# PQBTC `wallet_miniscript.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-MINISCRIPT-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for the narrow inherited miniscript
watch-only import, direct funding, and non-signing spend-preparation surface.

## Current Owned Surface

The current passing
[wallet_miniscript.py](../test/functional/wallet_miniscript.py) suite owns a
bounded miniscript carveout:

- inherited miniscript sanity guards for insane and unsatisfiable descriptors
  remain active
- one static public-key `wsh(or_b(pk(...),s:pk(...)))` miniscript import and
  address derivation remains the only positive in-file miniscript descriptor
  surface
- raw helper funding of that inherited classical miniscript output remains an
  explicit deferred `scriptpubkey` negative control under the default policy
  path
- direct coinbase generation into the imported miniscript address creates one
  real watch-only UTXO without reopening broad inherited send-path semantics
- the funded watch-only miniscript can prepare an incomplete PSBT-backed send
  when the tracked input is preselected and the fee is subtracted from the
  output to avoid change
- `walletprocesspsbt(finalize=false)` remains non-signing and incomplete for
  that watch-only miniscript PSBT
- `finalizepsbt` remains incomplete for that miniscript PSBT
- ranged xpub/tprv miniscript imports and one TapMiniscript xpub import remain
  explicit invalid-key deferred controls

## What This Does Not Mean

This posture note does **not** mean:

- inherited classical miniscript signing has been rehabilitated
- TapMiniscript activation or replacement semantics are defined
- this suite should move into `pq_required`

Those remain deferred.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/wallet_miniscript.py`
  - result: passed
  - current posture:
    - static miniscript import/derive stays green
    - one real watch-only miniscript UTXO can be tracked and used for
      incomplete PSBT preparation
    - watch-only processing and finalize remain explicitly non-signing

## Interpretation

- `wallet_miniscript.py` is now a fixed non-signing miniscript
  funding/spend-preparation slice
- it remains `dual_profile` / `deferred`, not a required PQ-first gate
- the next clean wallet follow-on shifts to broader inherited classical
  multisig funding/signing work
- broad miniscript signer rehabilitation and TapMiniscript semantics remain
  deferred
