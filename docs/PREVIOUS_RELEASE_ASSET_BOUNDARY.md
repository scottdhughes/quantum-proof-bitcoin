# PQBTC Previous-Release Asset Boundary

## Status: ACTIVE
## Spec-ID: PREVIOUS-RELEASE-ASSET-BOUNDARY-v1
## Updated: 2026-07-16

## Purpose

Record the provenance boundary and suite-level decisions for previous-release
functional coverage so Track A does not promote skipped compatibility tests as
required gates.

## Observed Harness Shapes

The resolved coinstats decision covers
[feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py).
That suite calls `skip_if_no_previous_releases()` and starts two nodes with
`versions=[None, 280200]`.

Under the current functional-test framework, `280200` maps to `v28.2`, so the
default local layout is:

- `releases/v28.2/bin/pqbtcd`
- `releases/v28.2/bin/pqbtc-cli`

The unsupported-UTXO decision covers
[feature_unsupported_utxo_db.py](../test/functional/feature_unsupported_utxo_db.py).
That suite also calls `skip_if_no_previous_releases()` and starts its legacy
node with `version=140300`. The framework maps that version to:

- `releases/v0.14.3/bin/pqbtcd`
- `releases/v0.14.3/bin/pqbtc-cli`

The mempool serialization decision covers
[mempool_compatibility.py](../test/functional/mempool_compatibility.py). That
suite starts its legacy node with `version=200100`, which maps to:

- `releases/v0.20.1/bin/pqbtcd`
- `releases/v0.20.1/bin/pqbtc-cli`

The wallet backwards-compatibility decision covers
[wallet_backwards_compatibility.py](../test/functional/wallet_backwards_compatibility.py).
That suite calls `skip_if_no_previous_releases()` and starts six historical
nodes with versions `250000`, `240001`, `230000`, `220000`, `210000`, and
`200100`. The framework maps them to `v25.0`, `v24.0.1`, `v23.0`, `v22.0`,
`v0.21.0`, and `v0.20.1`, with `pqbtcd` and `pqbtc-cli` expected under each
version's `releases/<tag>/bin/` directory.

The wallet migration decision covers
[wallet_migration.py](../test/functional/wallet_migration.py). That suite calls
`skip_if_no_previous_releases()` and starts a current node plus an old node with
`version=280200` and `-deprecatedrpc=create_bdb`. The old node therefore uses
the same expected v28.2 binary layout:

- `releases/v28.2/bin/pqbtcd`
- `releases/v28.2/bin/pqbtc-cli`

If `PREVIOUS_RELEASES_DIR` is set, the same versioned layouts are expected below
that directory instead.

## Current Local State

Current inspection found no usable previous-release PQBTC binary assets:

- `PREVIOUS_RELEASES_DIR` is unset
- the repo-local `releases/` directory is empty
- the fork's GitHub releases currently expose no executable release assets:
  - `v1.0.0` has no assets
  - `v1.0.0-rc1` has only `RELEASE_V1_RC1.md` and `RUNBOOK_V1_RC1.md`
- the checked `v28.2`, `v0.14.3`, `v0.20.1`, `v0.21.0`, `v22.0`, `v23.0`,
  `v24.0.1`, and `v25.0` tags are inherited signed Bitcoin Core releases, not
  PQBTC release-asset sources
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

## Unsupported UTXO DB Decision

The 2026-07-12 repository audit confirms that `v0.14.3` is an inherited signed
Bitcoin Core release. Its source tree builds `bitcoind` and `bitcoin-cli` and
contains no PQBTC or PQ signature implementation. The functional suite uses it
to create an old Bitcoin chainstate database before checking current-node
rejection and `-reindex-chainstate` recovery.

Track A launches PQBTC as a new chain at block 0 and does not support migrating
a Bitcoin Core 0.14 datadir into PQBTC. Building or renaming the inherited
Bitcoin binaries could exercise the old database mechanics, but it would not
prove a prior-PQBTC compatibility guarantee. `feature_unsupported_utxo_db.py`
is therefore classified as `legacy_only` reference coverage and remains
outside `pq_required`.

## Mempool Compatibility Decision

The 2026-07-12 repository audit confirms that `v0.20.1` is an inherited signed
Bitcoin Core release whose source tree builds `bitcoind` and `bitcoin-cli` and
contains no PQBTC or PQ signature implementation. The suite moves
`mempool.dat` from the old node to the current node, adds current serialization
state, then moves the file back to the old node and requires both transactions
to load.

That bidirectional contract protects a Bitcoin Core upgrade and downgrade path
that PQBTC never shipped and does not support. Building or renaming the
inherited Bitcoin binaries could exercise the file-format mechanics, but it
would not prove prior-PQBTC compatibility. `mempool_compatibility.py` is
therefore classified as `legacy_only` reference coverage and remains outside
`pq_required`.

## Wallet Backwards-Compatibility Decision

The 2026-07-15 repository audit confirms that the suite's six historical tags
are inherited signed Bitcoin Core releases, while the fork's only PQBTC release
tags are `v1.0.0-rc1` and `v1.0.0`. Both PQBTC tags identify as v30.2, neither
provides the historical binaries required by this harness, and the published
releases expose no executable PQBTC assets.

The suite protects Bitcoin Core wallet transitions that PQBTC never shipped:

- current descriptor wallets are copied to v0.21.0 through v25.0 and reopened
  on the current node while preserving transaction and keypool state; v0.20.1
  rejects those wallets, and v0.21.0 rejects wallets containing `tr()`
  descriptors
- descriptor wallets created by v0.21.0 through v25.0 are restored on the
  current node and copied back to their source release without an automatic
  incompatible upgrade
- legacy BDB wallets created by v0.20.1 through v25.0 must be migrated rather
  than loaded directly; the suite also checks v22 inactive-HD-chain keypool
  cleanup during migration and current-node startup handling of legacy wallets

These cross-version load, upgrade, downgrade, and migration contracts do not
represent a supported prior-PQBTC wallet path. Building or renaming the
inherited Bitcoin binaries could exercise the upstream wallet mechanics but
would not prove PQBTC compatibility. `wallet_backwards_compatibility.py` is
therefore classified as `legacy_only` reference coverage and remains outside
`pq_required`.

## Wallet Migration Decision

The 2026-07-16 repository audit confirms that the old node is the inherited
signed Bitcoin Core v28.2 release, not a PQBTC release. Its source and generated
manuals identify Bitcoin Core, `bitcoind`, and `bitcoin-cli`, and contain no
PQBTC or post-quantum implementation. The fork's `v1.0.0-rc1` and `v1.0.0`
tags instead identify as v30.2 and provide no executable prior-release assets
for this v28.2 harness.

The suite creates legacy BDB wallets through the v28.2 node and tests current
Bitcoin Core migration mechanics across a broad inherited surface:

- conversion to SQLite descriptor wallets with timestamped legacy backups,
  address, balance, transaction, metadata, keypool, encryption, and wallet-flag
  preservation
- partitioning imported scripts and partial-key multisig state into spendable,
  watch-only, and solvables wallets across raw scripts, P2WSH, miniscript, and
  Taproot cases
- named, unnamed, direct-file, absolute, relative, and nested wallet paths,
  plus restoration of the BDB backup on the old node
- rollback and cleanup for migration, destination-wallet, cross-chain load,
  and pruned-history failures while preserving the original BDB wallet

Those checks protect migration from a Bitcoin Core v28.2 wallet format that
PQBTC never shipped and does not support as an upgrade source. Building or
renaming the inherited binaries could exercise the upstream migration
mechanics, but it would not prove a prior-PQBTC wallet guarantee.
`wallet_migration.py` is therefore classified as `legacy_only` reference
coverage and remains outside `pq_required`.

## Reconsideration Boundaries

Reopen these decisions only if an authentic PQBTC release matching the suite's
historical format, version, and chain assumptions is found. Record the source
tag or commit, build recipe, target platform, and SHA256 checksums before
rerunning the suite. Do not commit large generated binaries or downloaded
release payloads.

## Remaining Asset-Dependent Suites

None. The coinstats, unsupported-UTXO, mempool, wallet-backwards, and wallet
migration suites now have explicit `legacy_only` dispositions, and no suite
remains in `pq_backlog`.

## Validation Snapshot

Current local validation without previous-release assets:

- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts: `pq_required: 120`, `pq_backlog: 0`, `legacy_only: 14`
- `build/test/functional/test_runner.py --jobs=1 wallet_migration.py`
  - result: skipped
  - skip reason: previous releases not available or disabled
  - interpretation: confirms that this run is not evidence for a required PQ
    gate
