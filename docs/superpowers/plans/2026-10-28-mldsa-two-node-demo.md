# ML-DSA real-node two-node spend and restore

> Execute inline with superpowers:executing-plans. The owner authorized the
> isolated demo and Claude review; do not add another design-approval stall.

**Goal:** Two actual daemons enforce CONTRACT-1 on a separate, valueless,
explicit experimental regtest; a distinct-UID signer signs actual UTXO spends,
then an encrypted-record restore can spend again. No public deployment.

**Spec:** docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md and
docs/ML_DSA_44_OWNER_CONTINUATION.md. Base86052dac53177dcb891b44bce9256d87eb3a4189.
Use the existing isolated branch; primary main and all old packets stay intact.

## Global constraints and review focus

- Default-OFF builds and ordinary chain identities/rules stay unchanged.
- New mode is explicit `-mldsa44demo=1 -regtest`, full frozen GENESIS-v1 identity,
  separate `mldsa44-regtest-v1` data namespace, no seeds. No production H.
- Demo H=1 is fixed, not operator-configurable. Its admitted manifest binds the
  frozen spec SHA, full network B, H-1 genesis, and empty pre-H UTXO inventory.
  Genesis is unspendable and is the sole pre-H block. Identity/inventory mismatch
  is a deployment error; no grandfathering. Do not generalize this proof to a
  nonempty production chain. Reindex/reorg must apply the same guard.
- Script closures share the actual CTransactionRef and one immutable actual-Coin
  snapshot. Never deep-copy witness storage and reuse another snapshot.
- Cache keys include flags. Policy and consensus both select the new mandatory
  flag in demo mode; do not strip it on policy retry. Unknown-version discourage
  behavior is non-monotone. The H=1 profile never has preactivation mempool txs.
- Public node IPC code only; no private wallet/key-owner/libcrypto in daemon.
  Distinct UID, operator-only passphrase FD and encrypted durable state survive.
- Public node wallet metadata records derivation paths/high-water only. Restore
  uses a retained public manifest and explicit scan; never claim seed-only/gap
  limit recovery or rollback protection. Signer requests must bind actual Coins.
- Functional proof must cover invalid signature/changed output/wrong context,
  actual relay/block validation, restart/restore, reorg/reindex and default mode.
- Native tests/builds only offline bounded Linux. ARM is supplemental, not x86.
  No public seed/listener, real funds, push/merge, production admission or hold
  metadata flip. External human review NOT PERFORMED under owner exception.
- One fresh Claude review of the new whole patch; one required RED/GREEN fix
  pass; exhaustive dispositions/costs. Preserve all old ledgers and failed runs.

### Task 1: Frozen experimental network and daemon validation

**Files:** chainparams/base/kernel params; validation.h/cpp; crypto/mldsa44
deployment and build wiring; actual C++ and functional tests.
**Interfaces:** Produces explicit demo params, activation guard and actual shared
transaction Script closures; Task2 RPC consumes that identity/active Coin view.

1. Fresh baseline in retained-image offline Linux. Expected: existing node and
   Python suites pass, or exact preexisting failures are diagnosed first.
2. RED actual params/genesis/namespace and validation tests, including corrupted
   witness and copied transaction/output substitution. Expected: missing mode or
   current unknown witness behavior fails the new assertions.
3. Wire full frozen regtest params, fixed H=1 manifest/absence guard, strict
   option rejection elsewhere and default OFF. Wire shared snapshot into actual
   CScriptCheck and CheckInputScripts, flag selection and node link target.
4. GREEN narrow tests, full configured node/Python suites and default mode checks.
   Record actual observed counts, commands and limits. Commit verified slice.

### Task 2: Actual UTXO-bound public node wallet and signer IPC

**Files:** new experimental RPC/client adapter and registration; public manifest
storage; functional test and signer harness documentation.
**Interfaces:** Consumes Task1 actual demo params/Coins and existing signer
HELLO/address/SIGN_TX/LOCK/STATUS protocol; produces raw signed transaction and
public recovery records for Task3. No secret-owning signer code in daemon.

1. RED actual RPC tests for disabled mode, address reservation, exact public
   wallet identity/path joins, missing/changed/spent Coins, locked/wrong-UID
   signer, malformed response and metadata restore. Expected: RPC absent first.
2. Implement bounded public-only RPC adapter; node rebuilds request from actual
   transactions and Coins under lock, releases lock during IPC, rechecks against
   fresh Coins before returning; caller broadcasts through normal admission.
3. Public records are durable before return; explicit restore/scan inputs and
   signer high-water floors are retained. No passphrase in RPC/argv/env/log.
4. GREEN relevant tests and configured full suites. Commit verified slice.

### Task 3: Two-node spend, encrypted restore, review and evidence

**Files:** test/functional/feature_mldsa44_demo.py, demo runner/docs; new packet
and this plan's ignored ledger; source only for necessary verified repairs.
**Interfaces:** Consumes both prior tasks and existing encrypted signer service.

1. Run actual two daemons on namespace-local loopback with direct peers, no DNS
   or public interfaces. Fund a signer address, sign/broadcast/mine a spend and
   assert both nodes' actual UTXOs/tips agree. Invalid mutations must reject.
2. Stop signer; retain ciphertext and public high-water; restore in a separate
   directory, reconnect same authorization boundary, scan and spend again.
   Exercise node restart, invalidate/reconsider and reindex acceptance.
3. One tools-disabled Claude whole-patch review with full source/diff/contract;
   grade findings by effect, one RED/GREEN required-fix pass, record all rulings.
4. Fresh exact-source GCC/Clang builds/tests and binary/dependency/source joins;
   run x86_64 where genuinely available, otherwise explicitly leave it OPEN and
   retain ARM results only as supplemental. No false production-ready claim.
5. Seal a new evidence receipt/source hash set and checkpoint. Preserve worktree,
   branch, ignored ledger and old evidence. Handoff working demo or exact remaining
   failing boundary, never present a standalone checker as a two-node proof.
