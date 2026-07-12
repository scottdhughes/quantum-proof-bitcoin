# PQBTC Previous-Release Asset Boundary

## Status: ACTIVE
## Spec-ID: PREVIOUS-RELEASE-ASSET-BOUNDARY-v1
## Updated: 2026-07-12

## Purpose

Record the provenance boundary and suite-level decisions for previous-release
functional coverage so Track A does not promote skipped compatibility tests as
required gates.

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

## Coinstats Compatibility Decision

The 2026-07-12 source audit found no authentic artifact that can satisfy this
suite's intended PQBTC compatibility claim:

- the fork releases still expose no executable PQBTC assets
- the exact `v1.0.0` workflow run retained only an expired Windows executable
  bundle, while the `v1.0.0-rc1` run produced no executable artifact
- both PQBTC v1 tags identify as v30.2 and already contain the fixed
  `indexes/coinstatsindex` path, so they cannot supply the old v28.2
  `indexes/coinstats` format under test
- public artifact search found no separate archived PQBTC binaries
- the repository's `v28.2` tag remains inherited Bitcoin Core source, not a
  PQBTC release

`feature_coinstatsindex_compatibility.py` is therefore classified as
`legacy_only`. It remains useful as inherited Bitcoin Core reference coverage,
but it is not a PQBTC previous-release guarantee and must not enter
`pq_required` by placing unrelated binaries under a `v28.2` directory name.

## Reconsideration Boundary

Reopen this decision only if an authentic PQBTC release predating the fixed
coinstats-index path is found and its version and chain parameters match the
test's compatibility assumptions. Record the source tag or commit, build
recipe, target platform, and SHA256 checksums before rerunning the suite. Do not
commit large generated binaries or downloaded release payloads.

## Remaining Asset-Dependent Suites

After the coinstats compatibility decision, four `pq_backlog` suites remain
previous-release or prior-fixture dependent and require separate decisions:

1. `feature_unsupported_utxo_db.py`
2. `mempool_compatibility.py`
3. `wallet_backwards_compatibility.py`
4. `wallet_migration.py`

## Validation Snapshot

Current local validation without previous-release assets:

- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts: `pq_required: 120`, `pq_backlog: 4`, `legacy_only: 10`
- `build/test/functional/test_runner.py --jobs=1 feature_coinstatsindex_compatibility.py`
  - result: skipped
  - skip reason: previous releases not available or disabled
  - interpretation: confirms that this run is not evidence for a required PQ
    gate
