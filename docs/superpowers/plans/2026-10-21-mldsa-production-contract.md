# ML-DSA staged contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. No subagent dispatch is authorized for this execution.

**Goal:** Correct circular gates and produce the first reviewable production-contract draft with executable serialization/domain vectors.

**Architecture:** Separate stage permission from historical prototype admission. Keep the draft byte model in a new contrib directory with no node linkage; use exact literal vectors and an independent test serializer.

**Tech Stack:** Python3 standard library, JSON, Markdown; all test execution in the existing bounded offline Linux container.

**Spec:** docs/ML_DSA_44_STAGED_ADMISSION.md and docs/ML_DSA_44_PRODUCTION_CONTRACT.md.

## Global Constraints

Linux x86_64 software signing, GCC/Clang, hardware wallets deferred. Current native source, capsule, backend-admission JSON, pointer, resource ceilings and consensus accepted set stay unchanged. Draft domains are not algorithm allocation or activation. New vectors prove serialization only; review and production gates remain open. Preserve all older sealed packets/worktrees; no pushes, PRs, deployments or cleanup.

## Review Focus

- Duplicate/unknown JSON fields and bool-as-int must reject, not silently normalize.
- Nonminimal lengths, truncation and trailing binary bytes must reject.
- Every transaction/prevout/network/key/input-selector field must bind the message.
- Empty/duplicate/over-budget/unfunded requests must reject before serialization.
- Literal expectations must be checked by a reference path not calling the model encoder.

## Task 1: Stage ordering and draft

**Files:** docs/ML_DSA_44_STAGED_ADMISSION.md; docs/ML_DSA_44_PRODUCTION_CONTRACT.md; docs/PQSIG_PRODUCTION_READINESS.md; docs/ML_DSA_44_EXTERNAL_REVIEW.md; docs/ML_DSA_44_BACKEND_ADMISSION.md.

**Interfaces:** stage ordering and exact draft byte grammar consumed by Task2. Human prose needs source/diff review, not substring tests that bless the prose.

- [ ] Preserve all substantive obligations; move full-node audit/measurements/soak after experimental integration and hold removal to the final production decision.
- [ ] Keep draft choices, approved scope and unresolved integration decisions distinct.
- [ ] Review the complete diff for any admission/accepted-set change; expected none.

## Task 2: Executable model and vectors (RED/GREEN)

**Files:** Create contrib/ml-dsa-production-contract/contract_model.py, vectors.json, README.md; ci/test/test_ml_dsa_production_contract.py.

**Interfaces:** `encode_request(dict) -> bytes`; `decode_request(bytes) -> dict`; `signing_message(dict) -> bytes`; `signer_input(dict) -> (message32, context)`; `key_commitment(network, bytes) -> bytes`; `read_request(str) -> dict`; all malformed inputs raise `ContractError(ValueError)`. CLI `--vectors PATH` returns strict JSON counts/result or exits nonzero.

- [ ] First add real-behavior tests, including `test_model_present`, literal/reference vector equality, all bound-field mutations, exact binary roundtrip, all truncations and trailing bytes, nonminimal CompactSize, duplicate/unknown JSON, bool/int/range/hex checks and malformed CLI corpus. Expected RED: assertion that the new model is missing, not import-error success.
- [ ] In the contained checkout run `python3 -m unittest ci.test.test_ml_dsa_production_contract`; preserve the failing log before writing the implementation.
- [ ] Implement only the grammar above. Generate public synthetic fixtures with a separate literal/reference encoder; commit expected bytes/digests, never derive expectations using the model under test.
- [ ] Run the narrow suite and CLI corpus; expected all tests and both vector classes PASS. Preserve failures and repair code, not expectations, if they disagree.

## Task 3: Regression and handoff

**Files:** this plan, new packet progress/receipts; no older ledgers.

- [ ] Full contained `python3 -m unittest discover -s ci/test -p 'test_*.py'`, both frozen preflights, baseline validator, manifest, inventory and indexed filename/UTF8/whitespace checks.
- [ ] Assert primary exact clean0b, feature diff contains only this slice, unchanged capsule/control/pointer hashes and workflow-exact guarded diff EMPTY.
- [ ] Author self-check, explicitly not independent review. Leave the branch/worktree available for independent contract review. Do not merge or claim the remaining protocol choices or human review complete.

The initial design intentionally stops at a reviewable envelope model. Network wire/address/ALG_ID/deployment, persistent wallet/HD and signer IPC must be finalized before runtime integration; this is a first draft, not a completed production specification.
