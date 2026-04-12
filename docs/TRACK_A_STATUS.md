# PQBTC Track A Status

## Status: ACTIVE
## Spec-ID: TRACK-A-STATUS-v1
## Updated: 2026-04-12
## Current Phase: Phase 1 - Wallet Surface Expansion

## Purpose

Operational status for the ninety-day Track A plan.

This file is the working handoff for Aineko. When no more specific repo task is
active, use this file to choose the next safe step for `quantum-proof-bitcoin`.

## Current Objective

Freeze the owned `rpc_psbt.py` PQ subset for `#23`, keep inherited classical
PSBT finalize as an explicit deferred legacy boundary, then move the next owned
follow-on to descriptor/address creation surfaces.

## Current Working Thesis

- `quantum-proof-bitcoin` stays on Track A: native post-quantum Bitcoin.
- Track A assumes PQBTC launches as a new chain at block 0, not as an in-place
  continuation of inherited Bitcoin chain history.
- Blockstream's Liquid/Simplicity work is a benchmark and adjacent migration
  reference, not a reason to reset the repo.
- The best progress in this window is one owned product-facing migration slice,
  not broad speculative redesign.

## Current Candidates For First Owned Slice

Chosen first owned tranche:

1. `rpc_psbt.py` / PQ-native PSBT semantics
   - Why first: user-facing, testable, narrow enough to finish, and directly
     connected to wallet/signing maturity.

Next likely follow-ons:

2. `wallet_createwalletdescriptor.py`
3. `wallet_address_types.py`
4. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
5. `wallet_miniscript.py`

## Current Queue

1. This slice freezes `rpc_psbt.py` as:
   - one narrow PQ-owned wallet PSBT subset
   - one explicit inherited classical negative control at `finalizepsbt`
   Minimum validation only:
   - `python3 test/functional/rpc_psbt.py`
   - `python3 test/functional/wallet_pq_psbt.py`
   Stays deferred:
   - broad inherited PSBT rehabilitation
   - dual-mode classical/PQ signature finalize compatibility
   - broad inherited backup/recovery migration rehab
   - broad inherited `wallet_signrawtransactionwithwallet.py` rehabilitation
   - broad `wallet_fundrawtransaction.py` rehabilitation
2. Recommended next PR after this slice:
   - preferred: `wallet_createwalletdescriptor.py`
   - lower-risk alternate: `wallet_pq_descriptors.py`
   Why next:
   - moves past the PSBT tranche
   - keeps momentum on wallet-owned migration surfaces
   - avoids reopening inherited classical PSBT behavior
3. Use `PSBT_REPLACEMENT_TRANCHE.md` as the current owned slice.
4. Use `PQ_DESCRIPTOR_WATCHONLY_CONTRACT.md` as the fixed public descriptor
   contract.
5. Treat the `rpc_psbt.py` classical `finalizepsbt` failure as an intentionally deferred
   inherited classical-PSBT compatibility gap under the all-PQ Track A stance.
6. Use `GENESIS_AND_NETWORK_POSTURE.md` as the launch-level interpretation for
   a fresh block-0 chain with its own network identity.
7. Use `CREATEWALLETDESCRIPTOR_POSTURE.md` to keep inherited descriptor
   creation separate from the PQ-native creation path.
8. Use `PQ_WALLET_MANAGER_SETUP.md` as the current setup-path contract for
   active PQ receive/change managers.
9. Use `PQ_ADDRESS_RPC_POSTURE.md` as the current inherited-address boundary
   for PQ-only active wallets.
10. Use `TEST_COST_POSTURE.md` to choose the cheapest defensible validation tier
   for each tranche before running tests.
11. Re-run and inspect the current required PQ-first functional gate strategy at
    a targeted level.
12. Reproduce the current `OPS_SLO` evidence flow only when the work has
    actually reached milestone-evidence scope.

## Autonomous Scope

Aineko may do these without asking:

- read code, tests, and docs in this repo
- tighten or add strategy/status docs
- rank backlog items and propose tranche scope
- run low-cost targeted tests and validation commands
- update this file with decisions, results, and blockers

Aineko must ask before:

- consensus-rule changes
- broad signature-stack changes or cryptographic-family pivots
- destructive actions
- long expensive build/test campaigns
- public claims, releases, or external messaging
- changing the Track A thesis itself

## Phase 1 Deliverables

- first tranche named
- tranche semantics written down
- backlog ranking tightened
- current gate health summarized
- ops evidence path sanity-checked

## Reference Pack

- `TRACK_A_NATIVE_PQ_BITCOIN.md`
- `TRACK_A_90_DAY_ROADMAP.md`
- `GENESIS_AND_NETWORK_POSTURE.md`
- `RESEARCH_INDEX.md`
- `PSBT_REPLACEMENT_TRANCHE.md`
- `PQ_DESCRIPTOR_WATCHONLY_CONTRACT.md`
- `PQ_WALLET_MANAGER_SETUP.md`
- `PQ_ADDRESS_RPC_POSTURE.md`
- `CREATEWALLETDESCRIPTOR_POSTURE.md`
- `TEST_COST_POSTURE.md`
- `POST_RC_EPICS.md`
- `CI_COMPLETENESS.md`
- `TAPROOT_MIGRATION_MATRIX.md`
- `OPS_SLO.md`

## Decision Log

- 2026-04-06: Track A confirmed as the repo anchor. No Liquid/Simplicity reset.
- 2026-04-06: Launch posture clarified: PQBTC is intended as a fresh chain
  starting at block 0, not as a retrofit onto inherited Bitcoin history.
- 2026-04-06: `GENESIS_AND_NETWORK_POSTURE.md` added to freeze the practical
  launch interpretation of that thesis: new history, new network identity, no
  assumed Bitcoin UTXO inheritance, and no obligation to preserve broad
  classical wallet compatibility by default.
- 2026-04-06: Initial ninety-day roadmap added.
- 2026-04-06: First owned tranche chosen: `rpc_psbt.py` / PQ-native PSBT semantics.
- 2026-04-06: `PSBT_REPLACEMENT_TRANCHE.md` added as the tranche semantics note.
- 2026-04-06: Follow-on queue tightened: `wallet_pq_descriptors.py` ahead of `wallet_createwalletdescriptor.py`, with address/miniscript surfaces later.
- 2026-04-06: Targeted confidence pass: `pqsig_script_tests` passed, `wallet_pq_psbt.py` passed, `rpc_psbt.py` failed at `finalizepsbt` with `Signature is not a valid encoding`.
- 2026-04-06: Root cause narrowed: `src/script/interpreter.cpp` currently makes
  `CheckSignatureEncoding()` PQ-only for all pre-taproot paths, so classical
  PSBT `partial_sigs` created for `pkh(...)` inputs decode-fail even when the
  wallet signs them correctly.
- 2026-04-06: Track A stance confirmed as all-PQ. Restoring inherited
  classical PSBT decode/finalize compatibility is not current owned work.
- 2026-04-06: Fixed watch-only `pq(...)` descriptor contract confirmed with
  both unit and functional coverage; `wallet_createwalletdescriptor.py` is now
  the next descriptor-facing follow-on.
- 2026-04-06: `wallet_createwalletdescriptor.py` verified green, but confirmed
  as inherited xpub-to-`wpkh/tr` descriptor creation rather than a PQ-native
  creation path.
- 2026-04-06: Recommended direction: keep PQ wallet-manager creation on the
  dedicated `pqpriv(...)` path for now instead of overloading the inherited
  `createwalletdescriptor` RPC early.
- 2026-04-06: Active `pqpriv(...)` manager coverage now explicitly rejects both
  inherited `bech32` and `bech32m` `createwalletdescriptor` paths as HD-xpub
  creation flows, including after backup/restore.
- 2026-04-06: `createwalletdescriptor` now returns a PQ-specific error on
  PQ-only wallets instead of the generic HD-key ambiguity message.
- 2026-04-06: Dedicated `createpqwalletmanagers` RPC landed for PQ-native
  receive/change setup on descriptor wallets with no active managers.
- 2026-04-06: `wallet_pq_active_ranged.py` now covers the dedicated setup RPC
  directly.
- 2026-04-06: `wallet_pq_psbt.py` now runs the main PQ-native PSBT path through
  `createpqwalletmanagers`, while retaining one lower-level `importdescriptors`
  check so raw `pqpriv(...)` setup stays exercised.
- 2026-04-08: `wallet_pq_psbt.py` now also covers `fundrawtransaction` on a
  PQ-only wallet, freezing the current expectation that automatic change stays
  on the active internal `pqpriv(...)` manager rather than re-entering
  inherited change-address semantics.
- 2026-04-08: `wallet_pq_psbt.py` now also covers automatic-input
  `walletcreatefundedpsbt` on a PQ-only wallet, freezing the current
  expectation that the PSBT funding path keeps automatic change on the active
  internal `pqpriv(...)` manager and emits one PQ proprietary partial-signature
  field per funded PQ input.
- 2026-04-08: The same PQ-owned `walletcreatefundedpsbt` tranche now covers the
  `changePosition` and `subtractFeeFromOutputs` option edges, with automatic PQ
  change still staying on the active internal `pqpriv(...)` manager.
- 2026-04-08: `wallet_pq_create_tx.py` now owns the narrow PQ-only direct
  wallet create-tx posture: inherited anti-fee-sniping stays in force on
  `sendtoaddress`, old tips keep `locktime = 0`, recent tips keep
  `0 < locktime <= height`, and the current wallet tx version stays `2`.
- 2026-04-08: `wallet_pq_send.py` now owns the narrow PQ-only `send` RPC
  posture: default recent-tip anti-fee-sniping stays in force, an explicit
  `locktime = 0` override disables it, and the current wallet tx version stays
  `2`.
- 2026-04-08: `wallet_pq_sendall.py` now owns the narrow PQ-only `sendall`
  RPC posture: default recent-tip anti-fee-sniping stays in force, an explicit
  `locktime = 0` override disables it, and the current wallet tx version stays
  `2`.
- 2026-04-08: `wallet_pq_sendmany.py` now owns the narrow PQ-only `sendmany`
  RPC posture: default anti-fee-sniping stays in force, the current wallet tx
  version stays `2`, and one multi-recipient `subtractfeefrom` edge is now
  owned in the required PQ gate.
- 2026-04-08: `wallet_pq_descriptors.py` now owns the fixed watch-only
  `pq(...)` descriptor boundary strongly enough for the required PQ gate:
  import/introspection, reload persistence, watch-only tracking, and a
  non-signing PSBT-preparation path with no PQ proprietary partial signatures.
- 2026-04-08: Wallet RPC metadata now exposes an explicit
  `has_private_keys` field on `getaddressinfo` and `listunspent`, so fixed
  public `pq(...)` descriptors and active `pqpriv(...)` managers no longer
  need to overload deprecated `iswatchonly` / `spendable` fields to express
  signing capability.
- 2026-04-09: Remaining-slice map refreshed after the send-path / CI and CLI
  hotfix work. Recommended next PR is a docs-only Track A strategy and
  launch-posture pack in `docs/TRACK_A_NATIVE_PQ_BITCOIN.md`,
  `docs/TRACK_A_90_DAY_ROADMAP.md`,
  `docs/GENESIS_AND_NETWORK_POSTURE.md`, `docs/RESEARCH_INDEX.md`,
  `docs/PSBT_REPLACEMENT_TRANCHE.md`, `docs/TEST_COST_POSTURE.md`,
  `docs/TRACK_A_STATUS.md`, `docs/README_PQBTC.md`, `docs/Spec.md`, and
  `docs/DECISION_DEFERRAL_LEDGER.md`, with minimum validation limited to
  doc-only review and repo-relative links. Product identity/Qt naming work,
  `OPS_SLO` evidence/artifact updates, broad inherited address-type rehab, and
  inherited classical PSBT compatibility remain deferred.
- 2026-04-10: After merging the docs, identity, and `OPS_SLO` slices and
  resyncing the old dirty worktree to current `main`, no further real tranche
  remained in that worktree. The next clean owned slice is now a PQ-specific
  `signrawtransactionwithwallet` contract, implemented as a dedicated
  `wallet_pq_signrawtransaction.py` surface plus a matching posture doc and PQ
  gate/inventory updates. Broad inherited `wallet_signrawtransactionwithwallet`
  and `wallet_fundrawtransaction` rehab remain deferred.
- 2026-04-11: The next owned wallet surface remains a PQ-specific
  `signrawtransactionwithwallet` slice: direct wallet-owned raw spends,
  default/`ALL` parity, explicit non-`ALL` rejection, and fixed PQ witness
  shape, without reopening the broad inherited raw-signing matrix.
- 2026-04-11: The PQ-only raw-signing slice is now owned explicitly through
  `wallet_pq_signrawtransaction.py` and
  `PQ_WALLET_SIGNRAWTRANSACTION_POSTURE.md`, with required-gate promotion in
  `pq_functional_tests.txt` and `functional_suite_inventory.json`. The next
  wallet follow-on should extend active PQ manager restore semantics rather
  than reopening the inherited raw-signing matrix.
- 2026-04-06: Full `OPS_SLO` evidence bundle refreshed at
  `docs/artifacts/ops-slo/2026-04-06` and validated at signoff.
- 2026-04-06: Targeted `OPS_SLO` sanity check completed without running the full
  soak capture. The frozen `2026-03-30` bundle still validates at sign-off, the
  validator self-test passes, and a live `mempool_pq_limits.py` run still emits
  the expected summary contract with `pass=true`, `crash_assert_hang=false`, and
  stable restart counts.
- 2026-04-06: Current targeted Track A gate snapshot is green for
  `wallet_pq_active_ranged.py`, `wallet_pq_psbt.py`,
  `wallet_pq_create_tx.py`, `wallet_pq_send.py`,
  `wallet_pq_sendall.py`, `wallet_pq_sendmany.py`,
  `wallet_pq_descriptors.py`,
  `wallet_createwalletdescriptor.py`, and `pqsig_script_tests`.
- 2026-04-06: PQ-only active wallets now reject inherited `getnewaddress` and
  `getrawchangeaddress` outright, including explicit legacy-style address-type
  requests, and direct operators to `getnewpqaddress` /
  `getrawpqchangeaddress` instead.
- 2026-04-06: `keypoolrefill` is now explicitly treated as a supported PQ
  maintenance path: on PQ-only active wallets it expands the receive/change
  `pqpriv(...)` ranges rather than acting as an inherited address-family UX.
- 2026-04-06: `wallet_address_types.py` remains an inherited `dual_profile`
  suite. Its current failure is still in classical `sendmany` signing flow, so
  broad address-type rehabilitation is not the owned Track A wallet milestone.
- 2026-04-06: Launch-facing operator identity is tighter on the main CLI/RPC
  path: `pqbtcd`, `pqbtc-wallet`, and `pqbtc-util` help/version output now use
  PQBTC naming, and wallet/RPC error/help strings now prefer `PQBTC address`,
  `pqbtc-wallet`, and `pqbtcd` over inherited Bitcoin tool names on the active
  operator surfaces.
- 2026-04-06: The same identity cleanup now extends across the active Qt
  source surfaces: `pqbtc-qt` entrypoint naming, PQBTC address/network wording,
  payment/request UI text, and GUI metadata no longer default to inherited
  Bitcoin branding on the main operator path. The current build tree does not
  have the Qt target enabled, so this pass is source-level verified rather than
  GUI-built in this environment.
- 2026-04-06: `TEST_COST_POSTURE.md` added to freeze the development rule that
  PQBTC should validate by tranche, not by tiny commit, and that expensive CI
  or soak work should be paid only at explicit promotion or sign-off boundaries.

## Blockers

- `rpc_psbt.py` currently fails in the inherited broad PSBT RPC surface at `finalizepsbt` with `Signature is not a valid encoding`.
- This is no longer just a hypothesis. The narrowed failing case spends
  classical `pkh(...)` coinbase-style inputs, and the resulting ECDSA-looking
  `partial_sigs` are rejected because global pre-taproot signature encoding
  validation now requires fixed-size PQ signatures.
- The owned PQ-native `pqpriv(...)` PSBT path is still healthy. The blocker is
  only for inherited classical compatibility surfaces. Under the current Track A
  stance, that legacy path stays explicitly deferred rather than restored.
- There is no current `OPS_SLO` blocker. The refreshed `2026-04-06` evidence
  bundle satisfies the frozen signoff thresholds.
