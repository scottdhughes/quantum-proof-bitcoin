# Registered TEST Peer Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. Steps use checkboxes for tracking.

**Goal:** Recover an already signed TEST transaction through its registered peer within the original payment deadline.

**Architecture:** The host controller runs a bounded RPC helper in the exact current container ID. The helper uses existing H APIs and public peer policy, so baseline and upgraded images share the same host recovery path. The workload renews one declared route and reannounces the same known bytes.

**Tech Stack:** Python standard library, existing native JSON-RPC, Linux Docker, unittest, pinned Ruff 0.5.5, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-17-registered-peer-recovery-design.md`.

## Global Constraints

- Preserve the original 60-second payment deadline; use only its remaining budget.
- No additional receive, sign, send, address reservation, or payment during repair.
- Saved and native networking must both be on; no policy write or implicit resume.
- Operate only on an already saved and natively registered endpoint and owned container ID.
- Preserve existing v1/v2 transport choice; do not force product traffic to v1.
- Existing H images need no new worker opcode or binary.
- Research compute stays within the shared hard two-CPU limit; C/C++ runs only in Linux Docker or CI.
- Preserve every prior failure, original dataset, wallet identity, volume, and partial-time exclusion.

## Review Focus

- Policy replacement, wrong owner, orphan temporary file: refuse before mutation (Task 1).
- Either network-off flag: refuse without disconnect, connect, or resume (Task 1).
- Peer disappearance, automatic reconnect, ambiguous response: observe without replaying mutations (Task 1).
- Stale pong, changed container, expired budget: cannot produce successful recovery proof (Tasks 1 and 2).
- A renewed peer still lacks the transaction: original acceptance checks continue to fail (Tasks 2 and 3).

### Task 1: Host renewal action

**Files:** Create `contrib/ml-dsa-console/public_peer_recovery.py` and `ci/test/test_ml_dsa_public_peer_recovery.py`; modify `contrib/ml-dsa-console/public_controller.py`.

**Interfaces:** Consume the current manager/descriptor and public saved policy. Produce `PublicController.action("renew_peer", {"endpoint": str, "budget_seconds": float}, include_status=False)` with public fields `endpoint`, `renewed`, `network_active`, `old_peer_ids`, `new_peer_id`, `transport_protocol_type`, `fresh_pong`, and ping/pong counter proof.

- [ ] Write tests for unknown/unregistered endpoints, policy file guards, either off flag, ambiguous peers, ID changes, stale pong, exhausted budget, and no worker `_request` forwarding.
- [ ] Run the new tests and retain the relevant failures before implementation.
- [ ] Implement the contained helper and mutex-protected host action. Bound the budget to at most 10 seconds and carry one local deadline through inspection, RPC and Docker execution.
- [ ] Run the focused tests, related controller tests, and pinned Ruff. Audit source-build/inventory inputs for the new helper.

### Task 2: Workload integration

**Files:** Modify `contrib/ml-dsa-qualification/public_soak_agent.py`, `contrib/ml-dsa-qualification/run_public_soak.py`, `ci/test/test_mldsa_public_soak_agent.py`, and `ci/test/test_mldsa_public_soak.py`. Bind the new helper in `contrib/ml-dsa-console/container/build_native.sh` and `contrib/ml-dsa-runpod/run_public_soak.py` source inventories.

**Interfaces:** Consume Task 1's compact host action. Request at most one renewal per payment, on follower endpoint `127.0.0.1:23834`, after ten seconds of recipient absence. Reannounce only the original known TXID and retain `action_deadline`.

- [ ] Add failing tests for compact host dispatch, persistent receiver absence, endpoint selection, exhausted original budget, and unsuccessful renewal/receipt.
- [ ] Implement the bounded renewal and same-known-transaction reannouncement without changing payment issuance or settlement checks.
- [ ] Run the two focused test modules and related public console/transport tests; run pinned Ruff and whitespace checks.

### Task 3: Native registered-peer regression

**Files:** Create `contrib/ml-dsa-qualification/run_public_peer_recovery_ci.py`, `contrib/ml-dsa-qualification/peer_recovery_proxy.py`, and `ci/test/test_mldsa_public_peer_recovery_ci.py`; modify `.github/workflows/ml-dsa-44-assembled-system.yml`. Retain existing external L reproducer and every raw outcome unchanged. The coordinator binds the two new qualification tools in the native source inventory.

**Interfaces:** Use a saved and natively registered disposable endpoint, one dropped INV, fresh native pong proof and Task 1. Bind exact TXID/raw hash, floors, recipient mempool, both-node block proof, full state agreement and stopped PID0 cleanup.

- [ ] Demonstrate the unchanged baseline cannot recover the dropped announcement within its original 60-second clock.
- [ ] Prove the repaired flow confirms the same bytes inside that clock, with no extra issuance, on both baseline-H and current native images.
- [ ] Independently inspect receipts and retained ownership; preserve any fixture startup failures separately.
- [ ] Run the portable regression in both assembled CI compiler jobs. Include a native v2 renewal control and a deliberate network-off refusal; this private experiment gives zero public-soak time.

### Task 4: Qualification, public run and integration

**Files:** Update the dated qualification record and selected evidence packets only after actual results exist.

- [ ] Review the complete functional diff, run required host checks, commit and push the tested candidate under the repository identity.
- [ ] Freeze a clean public clone; qualify exact-source ARM/x86 GCC/Clang and current CI. Fix actual failures and preserve their records.
- [ ] Run a fresh 900-second public preflight, then a separate complete 86,400-second soak with all declared phases and final recovery. Partial time gives zero credit.
- [ ] Publish truthful receipts, merge the draft only after its actual gates pass, then test a fresh clone/install/main flow and current main CI.
