# PQBTC `mempool_dust.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-DUST-POSTURE-v1
## Updated: 2026-05-04
## Frozen-By: track-a-phase1-20260504
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited dust-relay mempool policy
under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing [mempool_dust.py](../test/functional/mempool_dust.py)
suite owns the single-node dust relay policy boundary:

- `-dustrelayfee=0` accepts small outputs that would otherwise trip dust
  policy, including the suite-local ephemeral-dust regression shape
- the exact dust threshold amount is accepted for each covered standard output
  script type
- one satoshi below the computed dust threshold is rejected with `dust`
- OP_RETURN/null-data outputs preserve the zero dust threshold
- default dust relay fee and multiple configured `-dustrelayfee` values keep
  stable acceptance and rejection behavior
- the covered inherited output-script set includes P2PK, P2PKH, P2SH, P2WPKH,
  P2WSH, P2TR-shaped script construction, future witness versions, bare
  multisig, and OP_RETURN

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool policy suite is owned by this tranche
- ephemeral-dust package behavior, expiry, package relay, package RBF,
  persistence, reorg, mining-template or prior-release
  compatibility
  behavior is covered here
- PQ-native witness-size stress replaces this inherited dust relay policy
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-04:

- `build/test/functional/test_runner.py --jobs=1 mempool_dust.py`
  - result: passed
  - current posture:
    - dust threshold acceptance and `dust` rejection remain stable under the
      current legacy-compatible PQC profile
    - `-dustrelayfee=0` preserves the expected small-output acceptance path
    - OP_RETURN keeps zero-threshold dust behavior

## Interpretation

- `mempool_dust.py` is now a required inherited dust relay policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md),
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md), and
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md), and
  [mempool_unbroadcast.py](MEMPOOL_UNBROADCAST_POSTURE.md), and
  [mempool_updatefromblock.py](MEMPOOL_UPDATEFROMBLOCK_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
