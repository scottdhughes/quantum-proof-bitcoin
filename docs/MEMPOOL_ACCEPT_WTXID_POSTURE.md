# PQBTC `mempool_accept_wtxid.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-ACCEPT-WTXID-POSTURE-v1
## Updated: 2026-05-04
## Frozen-By: track-a-phase1-20260504
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited wtxid-aware mempool acceptance
when two transactions share identical non-witness data but have different
witnesses under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_accept_wtxid.py](../test/functional/mempool_accept_wtxid.py) suite
owns the single-node wtxid/non-witness-data mempool boundary:

- a parent transaction can be funded, signed, mined, and used to construct two
  malleated child transactions
- the two child transactions have the same `txid` and distinct `wtxid` values
- the first child is accepted into the mempool and its stored mempool entry
  reports the expected `wtxid`
- `testmempoolaccept` reports `txn-already-in-mempool` for the exact same
  child transaction
- `testmempoolaccept` reports `txn-same-nonwitness-data-in-mempool` for the
  alternate witness with the same non-witness data
- repeated `sendrawtransaction` calls for either child do not replace the
  already-accepted mempool transaction
- newly connected peers are rebroadcast the canonical `wtxid` for the
  transaction already in the mempool

## What This Does Not Mean

This posture note does **not** mean:

- the full mempool package, persistence, expiry, reorg, TRUC, or mining
  policy families are owned here
- package relay or package RBF behavior is covered
- broad P2P relay behavior beyond this single-node wtxid rebroadcast check is
  covered
- prior-release compatibility suites can run without real prior PQBTC release
  assets

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-04:

- `build/test/functional/test_runner.py --jobs=1 mempool_accept_wtxid.py`
  - result: passed
  - current posture:
    - same-`txid` / different-`wtxid` mempool handling remains stable
    - exact already-in-mempool and same-nonwitness-data reject reasons remain
      stable
    - rebroadcast uses the canonical mempool `wtxid`

## Interpretation

- `mempool_accept_wtxid.py` is now a required inherited wtxid-aware mempool
  acceptance gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
