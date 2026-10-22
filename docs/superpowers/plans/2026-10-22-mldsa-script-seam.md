# ML-DSA native witness-v2 Script checker integration

> Execute inline with superpowers:executing-plans. Owner said just continue;
> do not add a design-approval loop or repeat the sealed bridge review.

**Goal:** Make the real Script interpreter's explicitly enabled native-v2/32
branch call a public checker bound to the actual transaction/Coin snapshot.
No network enables this flag in this slice; deployment/absence manifest, cache
transitions, actual wallet/cross-node path and x86 qualification follow.

**Spec:** docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md and owner continuation.
Base5838b9c8e737a225f5061dd16a0006ba5c05d4d5, same isolated feature worktree.
Previous native/signer/bridge packets remain immutable and commit-scoped.

## Constraints / review focus

- Default accepted rules, flags selected by validation/policy, rc2/Taproot and
  generic520-byte/stack rules unchanged. Only an explicit internal new flag
  enters ML-DSA semantics; no production/admission/release flag change.
- Exactly native witness2/program32; nested P2SH and other versions/lengths keep
  their existing unknown-program behavior. No numeric ALG_ID allocation.
- Dedicated branch checks exactly2items2420/1312 and invokes public callback;
  default checker fails closed. No signer/private/OpenSSL link into consensus.
- Checker compares the exact provided program/witness to its owned actual input
  and snapshot; a valid fixture must not authorize a different script/witness.
- Applicability must be explicit for mixed input dispatch; nonapplicable is not
  a reason to reject unrelated inputs. Delegated legacy checker methods survive.
- Binding is complete effective B, not label/genesis-only or cached hash.
- Native/full tests ONLY retained bounded offline Linux; ARM results cannot be
  relabeled x86. Full external human review still NOT PERFORMED, owner exception.
- No source/capsule/old-proof weakening, real funds, public servers, deployment,
  push/merge or cleanup. New code gets one complete separate Claude review.

### Task 1: Explicit Script branch and actual-snapshot checker

**Files:** src/script/interpreter.h,interpreter.cpp; src/crypto/mldsa44/node.h,
node.cpp; src/test/mldsa44_node_tests.cpp. Add public test fixture only if needed.

- [ ] Read real interpreter/base/deferred checker and actual bridge; preserve
  transaction/Coin ownership and new snapshot nonmovable invariant.
- [ ] RED tests for flag-on native-v2 actual public fixture, malformed two-item
  shapes, default-checker fail-closed, program/witness substitution, inherited
  wrong network; flag-off unknown behavior and other-length/nested behavior.
- [ ] Implement internal SCRIPT_VERIFY_MLDSA44 flag and public virtual callback
  with defaultfalse/deferred forwarding. Dedicated interpreter branch before
  unknown handling; no generic stack-limit relaxation or network flag selection.
- [ ] Add explicit Snapshot applicability and bound ScriptChecker; provided
  bytes must match the stored program and transaction witness before verification.
  Add checker context tests and legacy-method forwarding controls.
- [ ] Narrow actual Script tests GREEN, full configured node+Python suites and
  defaultOFF profile GREEN. Commit only the verified source; record actual counts.

Expected: missing flag/checker RED initially; active branch actual valid fixture
passes; malformed/substituted/unsupported-checker rejects; old flags unchanged.

### Task 2: Review, clean compiler evidence and carry forward deployment work

**Files:** new evidence packet/ignored plan ledger; source only for required fixes.

- [ ] One tools-disabled Claude review of entire NEW patch and full context.
  Regrade actual effect, ONE required fix pass with RED/GREEN/full suite; record
  every declined-item disposition, deferred minor and cost. No unchanged rereview.
- [ ] Exact clean supported GCC/Clang source/binary/Script/default-profile joins,
  separate packet/source hashes/seal; label ARM supplemental only.
- [ ] Carry separately into actual registered experimental-regtest parameters,
  absence-guarded manifest/H transition, cache invalidation, mempool/funding policy,
  public wallet+signer IPC, cross-node spend/restore/reorg/reindex, then x86/system
  qualification. This checklist is NOT evidence those later obligations passed.
