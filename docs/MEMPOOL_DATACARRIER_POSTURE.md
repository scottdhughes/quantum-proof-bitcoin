# PQBTC `mempool_datacarrier.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-DATACARRIER-POSTURE-v1
## Updated: 2026-05-04
## Frozen-By: track-a-phase1-20260504
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited OP_RETURN/datacarrier mempool
policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_datacarrier.py](../test/functional/mempool_datacarrier.py) suite owns
the single-node datacarrier policy boundary:

- default datacarrier relay remains uncapped by the historical 83-byte limit
- `-datacarrier=0` rejects OP_RETURN outputs with the expected policy reason
- custom `-datacarriersize=83` accepts the historical payload size and rejects
  payloads that exceed that configured boundary
- `-datacarriersize=2` accepts empty and zero-byte OP_RETURN payloads while
  rejecting one-byte data payloads
- `getmempoolinfo()["maxdatacarriersize"]` reports the expected default,
  disabled, custom, and small-limit values
- confirmed bare-multisig policy remains allowed by default as the suite-local
  inherited policy smoke check

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool policy suite is owned by this tranche
- dust, ephemeral-dust, expiry, package relay, package RBF, persistence, reorg,
  TRUC, mining-template, or prior-release compatibility behavior is covered
  here
- PQ-native witness-size stress replaces this inherited OP_RETURN policy
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-04:

- `build/test/functional/test_runner.py --jobs=1 mempool_datacarrier.py`
  - result: passed
  - current posture:
    - OP_RETURN/datacarrier policy boundaries remain stable under the current
      legacy-compatible PQC profile
    - configured size limits and disabled relay behavior preserve expected
      mempool rejection semantics
    - `getmempoolinfo` reports the configured datacarrier limits

## Interpretation

- `mempool_datacarrier.py` is now a required inherited datacarrier policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
