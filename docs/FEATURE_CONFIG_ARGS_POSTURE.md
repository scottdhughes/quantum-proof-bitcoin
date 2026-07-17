# PQBTC `feature_config_args.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-CONFIG-ARGS-POSTURE-v2
## Updated: 2026-07-17
## Frozen-By: track-a-default-datadir-namespace-170
## Consensus-Relevant: NO

## Purpose

Define the bounded Track A contract for PQBTC configuration-file discovery,
diagnostics, precedence, and platform default data-directory naming under the
PQBTC operator namespace.

## Current Owned Surface

The current passing
[feature_config_args.py](../test/functional/feature_config_args.py) suite owns
the configuration-namespace boundary selected in
[TRACK_A_RISK_REVIEW.md](TRACK_A_RISK_REVIEW.md):

- the default test-node configuration path is named `pqbtc.conf`
- a directory at that path and a directory reached through `includeconf`
  produce explicit configuration-read errors
- `-noconf` ignores `pqbtc.conf` and reports that exact filename when the file
  exists
- default, explicit, redundant, missing, and conflicting `-conf` paths retain
  their expected startup behavior and identify `pqbtc.conf` where the default
  namespace matters
- a default-directory `pqbtc.conf` that redirects `datadir` logs the actual
  configuration source and detects a second ignored `pqbtc.conf`
- `includeconf`, parser diagnostics, chain sections, and command-line-over-file
  datadir precedence remain functional under the renamed configuration file
- startup reports the PQBTC default data-directory namespace: `.pqbtc` on
  Linux and other Unix-like platforms, `Library/Application Support/PQBTC` on
  macOS, and `PQBTC` under the existing roaming application-data path or the
  fresh local application-data path on Windows

The complete inherited suite also exercises argument logging, network-active
and seed options, parser errors, and selected chain-specific options. Those
checks remain useful gate breadth, but the PQ-specific confidence claim in
this tranche is the configuration namespace above.

## What This Does Not Mean

This posture note does **not** mean:

- synthetic Windows `APPDATA` or `LOCALAPPDATA` overrides are covered; the two
  affected default-directory tests remain skipped because production resolves
  those folders through `SHGetSpecialFolderPathW`, while the cross-platform
  namespace assertion uses the runner's actual shell-folder path
- `pqbtc`, `pqbtcd`, `pqbtc-node`, GUI, service-file, user-agent, or network
  identity surfaces are owned by this gate
- every inherited argument-parser behavior is PQ-specific
- this tranche changes consensus, cryptography, wallet, mempool, mining, or
  P2P behavior

Those surfaces require separate evidence and selection decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-07-17:

- `build/test/functional/test_runner.py --jobs=1 feature_config_args.py`
  - result: passed
  - duration: 15 seconds
  - current posture:
    - `pqbtc.conf` discovery and diagnostics remain stable
    - explicit and ignored configuration-file boundaries remain stable
    - include and datadir precedence remain stable under the PQBTC namespace
    - the macOS default data directory remains
      `Library/Application Support/PQBTC`

The test requires local node RPC listeners. A restricted sandbox run that
blocked local binds failed before the test body; the same commit passed with
local node networking enabled.

## Expected CI Cost

Low. The suite uses the existing functional-test build and completed in 15
seconds locally without an additional build target.

## Interpretation

- `feature_config_args.py` is a required PQBTC configuration-namespace gate
- the promotion closes the concrete gap selected by issue `#165`
- the follow-up under issue `#170` closes the platform default data-directory
  naming gap without changing an inventory policy class
- the inventory remains at zero backlog after this one-for-one move from
  `dual_profile` to `pq_required`
- future operator-identity promotions require a fresh bounded risk decision;
  `tool_bitcoin.py` is not promoted by implication
