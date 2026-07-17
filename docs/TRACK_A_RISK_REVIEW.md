# PQBTC Track A Dual-Profile Risk Review

## Status: SELECT
## Spec-ID: TRACK-A-DUAL-PROFILE-RISK-REVIEW-v1
## Reviewed: 2026-07-17
## Inventory Change: NONE

## Decision

Select `feature_config_args.py` as the next bounded Track A promotion
candidate. The suite closes a launch-facing PQBTC configuration namespace gap
that is not currently owned by a `pq_required` functional gate.

This review PR did not change any inventory policy class. Its reviewed
baseline was:

- `pq_required`: 120
- `pq_backlog`: 0
- `legacy_only`: 14
- `dual_profile`: 142

Promotion, posture documentation, inventory bookkeeping, targeted validation,
and CI evidence belong in a separate PR tracked by issue `#165`.

## Separate Promotion Outcome

The separate bounded promotion slice implements the selected
`feature_config_args.py` contract without promoting either deferred/rejected
candidate. Its resulting baseline is:

- `pq_required`: 121
- `pq_backlog`: 0
- `legacy_only`: 14
- `dual_profile`: 141

The owned contract is recorded in
[FEATURE_CONFIG_ARGS_POSTURE.md](FEATURE_CONFIG_ARGS_POSTURE.md). Further
policy-class changes return to `HOLD` until another bounded risk review selects
a concrete PQ-specific gap.

## Follow-Up Hardening Outcome

Issue `#170` narrows one residual risk inside the already required
`feature_config_args.py` gate without selecting another suite or changing an
inventory policy class. The suite now asserts the startup-reported platform
default data-directory namespace: `.pqbtc` on Linux and other Unix-like
platforms, `Library/Application Support/PQBTC` on macOS, and `PQBTC` under the
Windows roaming legacy path when it exists or the local application-data path
otherwise.

The two tests that rely on synthetic Windows `APPDATA` or `LOCALAPPDATA`
overrides remain excluded on Windows. Production resolves those locations
through `SHGetSpecialFolderPathW`, so a child environment override is not an
equivalent test mechanism. The branch promotion matrix is the acceptance gate
for the actual Windows and macOS paths.

## Review Method

The review used Bitcoin Core v30.2 as the inherited baseline. The live fork
point is commit `314c42b55bda5ea441023d093774beca845dbb8f`; source and
functional changes were compared from that commit through the current Track A
baseline.

The selection process was:

1. map source files changed from the inherited v30.2 baseline
2. compare those implementation areas with current `pq_required` coverage
3. intersect changed functional suites with the `dual_profile` inventory
4. reject suites that only carry inherited, cosmetic, harness, or duplicated
   behavior
5. measure the remaining candidates with the build-tree functional runner

Sixteen changed functional suites remain `dual_profile`:

- `feature_config_args.py`
- `feature_filelock.py`
- `feature_includeconf.py`
- `feature_init.py`
- `feature_settings.py`
- `interface_ipc.py`
- `p2p_addr_relay.py`
- `p2p_tx_download.py`
- `rpc_blockchain.py`
- `rpc_createmultisig.py`
- `rpc_misc.py`
- `rpc_users.py`
- `rpc_whitelist.py`
- `tool_bitcoin.py`
- `tool_wallet.py`
- `wallet_anchor.py`

The other changed functional suites are already classified as `pq_required`,
apart from the completed `wallet_migration.py` `legacy_only` boundary.

## Required-Coverage Map

| PQ implementation area | Current required evidence | Review result |
|---|---|---|
| PQ signature implementation, parser, and script execution | `feature_pqsig_basic.py`, `feature_pqsig_multisig.py`, PQ signature unit and fuzz targets | No dual-profile promotion gap identified |
| PQ wallet manager, descriptors, signing, and PSBT | `wallet_pq_active_ranged.py`, `wallet_pq_descriptors.py`, `wallet_pq_psbt.py`, `wallet_pq_signrawtransaction.py`, and the required PQ send gates | No dual-profile promotion gap identified |
| PQ block, mempool, relay-stress, reorg, and mining envelopes | `feature_pq_block_limits.py`, `feature_pq_reorg.py`, `mempool_pq_limits.py`, `mempool_pq_stress.py`, and the required mining gates | No dual-profile promotion gap identified |
| Taproot replacement deployment and active seams | the five `feature_taproot_replacement_*.py` required gates | `rpc_blockchain.py` is overlapping evidence, not an uncovered gate |
| PQBTC operator namespace | source changes in `src/common/args.cpp` select `pqbtc.conf`; `NAMING.md` treats configuration separation as a launch contract | No required functional gate currently owns the `pqbtc.conf` path |

The original selection contract was deliberately narrower than all operator
naming and did not claim complete binary, GUI, service-file, default-datadir,
or network identity coverage. Issue `#170` subsequently closes only the
platform default-datadir namespace part of that residual boundary.

## Candidate 1: `feature_config_args.py`

### Disposition

`SELECT`

### Concrete Confidence Gap

PQBTC changes the default configuration filename from `bitcoin.conf` to
`pqbtc.conf`. Loading the wrong configuration namespace can mix operator
settings between consensus-incompatible chains. No current `pq_required`
functional suite owns that boundary.

### Affected PQ Path

- `src/common/args.cpp`: default configuration filename
- PQBTC configuration discovery and explicit `-conf` selection
- `-noconf`, `includeconf`, and datadir/config precedence diagnostics

### Ownership

- owner: `@scottdhughes`
- tracking issue: `#165` (open)
- prior generic inventory issue: `#15` (closed)

### Bounded Test Contract

The suite must continue to verify:

- default and explicit configuration paths use `pqbtc.conf`
- `-noconf` diagnostics identify the PQBTC configuration file
- conflicting default and explicit `-conf` paths are rejected using the PQBTC
  filename
- `includeconf` and datadir precedence remain functional after the namespace
  change
- inherited configuration parsing remains available under the renamed file

The original promotion contract did not directly prove platform default
datadir names such as `.pqbtc` or `Library/Application Support/PQBTC`. Issue
`#170` subsequently adds that bounded assertion to the already required gate.

### Targeted Test

```sh
build/test/functional/test_runner.py --jobs=1 feature_config_args.py
```

### Expected CI Cost

Low. The measured build-tree run completed in 15 seconds on 2026-07-17 and
requires no additional build target.

### Promotion Criteria

- the targeted functional test passes on the promotion branch
- a bounded configuration-namespace posture document is added
- only `feature_config_args.py` changes from `dual_profile` to `pq_required`
- inventory, completeness, and Track A status bookkeeping remain consistent
- post-merge CI is green

### Rejection Criteria

Reject or narrow the promotion if the suite cannot isolate the `pqbtc.conf`
contract, requires unrelated config-parser behavior changes, becomes
platform-flaky, or materially expands the required CI cost.

## Candidate 2: `tool_bitcoin.py`

### Disposition

`DEFER`

### Concrete Confidence Gap

The `pqbtc` wrapper dispatches the monolithic node as `pqbtcd` and the
multiprocess node as `pqbtc-node`. That is launch-facing operator behavior, but
it is narrower than configuration namespace separation.

### Affected PQ Path

- `src/bitcoin.cpp`
- `src/init/bitcoind.cpp` and multiprocess initialization
- `src/ipc/interfaces.cpp` process naming

### Ownership

- owner: `@scottdhughes`
- tracking issue: `#15` (closed generic epic)

A dedicated open issue is required before promotion.

### Bounded Test Contract

- default and `-M` wrapper modes dispatch `pqbtcd`
- `-m` and `-ipcbind` dispatch `pqbtc-node` when IPC is compiled
- invalid `-ipcbind` use is rejected in monolithic mode

### Targeted Test

```sh
build/test/functional/test_runner.py --jobs=1 tool_bitcoin.py
```

### Expected CI Cost

Very low. The measured run completed in under 1 second.

### Promotion Criteria

Require a dedicated open issue, an explicit decision that wrapper dispatch is
part of the required launch gate, and an accepted cross-platform boundary for
the current Windows skip and optional IPC assertions.

### Rejection Criteria

Do not promote it merely because it is cheap or renamed. Reject promotion if
the platform skip or optional IPC branch leaves the claimed required contract
materially untested.

## Candidate 3: `rpc_blockchain.py`

### Disposition

`REJECT`

### Concrete Confidence Gap Considered

The suite reports the `taproot_replacement` deployment through
`getblockchaininfo` and `getdeploymentinfo`.

### Affected PQ Path

- replacement deployment values in `src/kernel/chainparams.cpp`
- deployment reporting through blockchain RPCs

### Ownership

- owner: `@scottdhughes`
- inventory tracking issue: `#15` (closed)
- replacement-path tracking issue: `#23` (open)

### Bounded Test Contract

The relevant portion checks the replacement deployment name and active state
inside the broader inherited blockchain RPC suite.

### Targeted Test

```sh
build/test/functional/test_runner.py --jobs=1 rpc_blockchain.py
```

### Expected CI Cost

Low to moderate. The runner executes v1 and v2 transport variants, measured at
10 and 11 seconds respectively.

### Promotion Criteria

Promotion would require unique launch-critical replacement reporting not
already owned by a required suite.

### Rejection Criteria

The rejection criterion is met. Required
`feature_taproot_replacement_deployment.py` already verifies the default
dormant deployment plus defined, started, locked-in, and active reporting.
Promoting the much broader RPC suite would add cost without closing a distinct
PQ confidence gap.

## Measured Functional Evidence

The build-tree runner produced:

| Test | Result | Duration |
|---|---:|---:|
| `feature_config_args.py` | passed | 15 s |
| `tool_bitcoin.py` | passed | less than 1 s |
| `rpc_blockchain.py --v1transport` | passed | 10 s |
| `rpc_blockchain.py --v2transport` | passed | 11 s |

An initial restricted run failed before the node-based test bodies because the
sandbox prevented the local RPC servers from binding. No lingering PQBTC
processes were present. The same commit passed all four runner entries when
local node networking was enabled, so the restricted-run failures are
environment evidence, not product failures.

## Residual Risks And Non-Goals

- The suite does not emulate alternate Windows shell-folder locations through
  synthetic `APPDATA` or `LOCALAPPDATA` child environments; it validates the
  actual shell-folder path selected on the Windows runner.
- It does not validate all binary, service, GUI, user-agent, or network-magic
  naming surfaces.
- It does not add cryptographic or consensus evidence; those areas already
  have dedicated required gates.
- `tool_bitcoin.py` remains a possible future operator-hardening candidate,
  but it must be selected through another explicit risk decision.
- No other `dual_profile` suite is promoted by implication.

## Promotion Slice Contract

The separate promotion PR for `feature_config_args.py` under issue `#165`:

1. add a configuration-namespace posture document
2. change exactly one inventory policy class to `pq_required`
3. update CI completeness and Track A status bookkeeping
4. run inventory validation and the targeted functional test
5. merge only after required checks are green

If that bounded contract cannot be maintained in a future revision, revert to
`HOLD` and preserve the zero-backlog baseline.
