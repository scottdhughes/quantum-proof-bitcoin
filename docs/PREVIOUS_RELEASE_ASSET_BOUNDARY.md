# PQBTC Previous-Release Asset Boundary

## Status: ACTIVE
## Spec-ID: PREVIOUS-RELEASE-ASSET-BOUNDARY-v1
## Updated: 2026-06-11

## Purpose

Record the current blocker for previous-release functional suites so Track A
does not promote skipped compatibility tests as required gates.

## Required Harness Shape

The immediate Track A candidate is
[feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py).
That suite calls `skip_if_no_previous_releases()` and starts two nodes with
`versions=[None, 280200]`.

Under the current functional-test framework, `280200` maps to `v28.2`, so the
default local layout is:

- `releases/v28.2/bin/pqbtcd`
- `releases/v28.2/bin/pqbtc-cli`

If `PREVIOUS_RELEASES_DIR` is set, the same `v28.2/bin/pqbtcd` and
`v28.2/bin/pqbtc-cli` layout is expected below that directory instead.

## Current Local State

Current inspection found no usable previous-release PQBTC binary assets:

- `PREVIOUS_RELEASES_DIR` is unset
- the repo-local `releases/` directory is empty
- the fork's GitHub releases currently expose no executable release assets:
  - `v1.0.0` has no assets
  - `v1.0.0-rc1` has only `RELEASE_V1_RC1.md` and `RUNBOOK_V1_RC1.md`
- the checked `v28.2` tag is an inherited signed Bitcoin Core final tag, not a
  PQBTC release-asset source
- `test/get_previous_releases.py` downloads upstream Bitcoin Core
  `bitcoin-28.2-*` archives and is therefore not enough to prove a prior-PQBTC
  compatibility gate

## Source Decision

Do not promote `feature_coinstatsindex_compatibility.py` from `pq_backlog` until
real PQBTC previous-release binaries are available outside the git-tracked
tree.

Acceptable sources are:

1. an existing local PQBTC archive unpacked into the harness layout above
2. a reproducible build of the intended prior PQBTC release, staged outside
   git-tracked source and exposed through `PREVIOUS_RELEASES_DIR`
3. downloaded PQBTC release artifacts with executable binaries and documented
   checksums

When assets exist, record their source and SHA256 checksums before promotion.
Do not commit large generated binaries or downloaded release payloads.

## Remaining Asset-Dependent Suites

The current `pq_backlog` is entirely previous-release or prior-fixture
dependent:

1. `feature_coinstatsindex_compatibility.py`
2. `feature_unsupported_utxo_db.py`
3. `mempool_compatibility.py`
4. `wallet_backwards_compatibility.py`
5. `wallet_migration.py`

## Validation Snapshot

Current local validation without previous-release assets:

- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts: `pq_required: 120`, `pq_backlog: 5`
- `build/test/functional/test_runner.py --jobs=1 feature_coinstatsindex_compatibility.py`
  - result: skipped
  - skip reason: previous releases not available or disabled
