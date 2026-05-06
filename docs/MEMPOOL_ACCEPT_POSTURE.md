# PQBTC `mempool_accept.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-ACCEPT-POSTURE-v1
## Updated: 2026-05-04
## Frozen-By: track-a-phase1-20260504
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited raw transaction mempool
acceptance and resource-envelope checks under the current legacy-compatible
PQC profile.

## Current Owned Surface

The current passing
[mempool_accept.py](../test/functional/mempool_accept.py) suite owns the broad
single-node `testmempoolaccept` and raw transaction policy surface:

- malformed RPC arguments, empty batches, oversized batches, and undecodable
  transactions keep their expected RPC errors
- already-known, already-in-block, missing-input, duplicate-input, coinbase,
  and prevout-null transactions keep their expected reject reasons
- base fee, maxfeerate, negative-feerate, replacement, and finality checks
  continue to report stable acceptance or rejection
- nonstandard version, scriptPubKey, bare multisig, scriptSig, dust, standard
  transaction-size, small non-witness-size, and OP_RETURN policy boundaries
  remain covered
- relative locktime, CLTV-style locktime, and BIP68 sequence policy checks
  remain exercised through mempool admission
- anchor output standardness and nested-anchor rejection remain covered
- confirmed bare-multisig spending remains accepted under the current
  legacy-compatible PQC profile

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool functional suite is owned by this tranche
- package relay, package RBF, expiry, persistence, reorg, TRUC, or mining
  template behavior is covered here
- PQ-native witness-size stress replaces this inherited policy surface
- prior-release compatibility suites can run without real prior PQBTC release
  assets

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-04:

- `build/test/functional/test_runner.py --jobs=1 mempool_accept.py`
  - result: passed
  - current posture:
    - inherited raw transaction mempool acceptance passes under the current
      legacy-compatible PQC profile
    - standardness and resource-envelope reject reasons remain stable
    - anchor and confirmed bare-multisig policy cases remain covered

The adjacent previous-release-dependent
[feature_unsupported_utxo_db.py](../test/functional/feature_unsupported_utxo_db.py)
probe was also run and skipped because previous releases are not available in
this worktree.

## Interpretation

- `mempool_accept.py` is now a required inherited mempool acceptance gate
- it complements, but does not replace,
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md) and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
