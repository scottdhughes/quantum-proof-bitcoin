# ML-DSA-44 staged admission

## Status: CANDIDATE_DESIGN - NOT PRODUCTION ADMISSION
## Spec-ID: MLDSA44-STAGES-v0
## Scope decided: 2026-10-21

The approved initial signing scope is Linux x86_64 software custody, built with
GCC and Clang. Hardware wallets are deferred, not implicitly supported. This
records permission to correct the stage ordering, draft a production contract,
and implement executable design vectors. It does not authorize experimental
node integration, an algorithm allocation, deployment, or production activation.

The destination is a working production backend and an explicit release decision
that removes the hold. `NONE` and `RELEASE_HOLD` describe current admission, not
a permanent product objective. Changing metadata alone does not implement or
qualify a backend.

## Stages and advancement

| Stage | Work allowed after its entry decision | Evidence needed to leave |
| --- | --- | --- |
| Candidate/design (current) | Isolated candidate assurance, production-contract proposals, executable non-consensus vectors, human review intake and isolated measurements | Versioned contract and vectors; qualified independent human candidate/design review; findings and residual risks dispositioned; explicit approval of the experimental scope |
| Experimental integration (not admitted) | Only the reviewed node/build/Script/wallet changes on an explicitly isolated, valueless ML-DSA testnet path | Actual node wallet spend/restore and cross-node agreement; strict parser and malformed-input tests; source-to-binary identity; independent integration/consensus audit and remediation |
| System qualification (not admitted) | Exact supported-release-binary leakage/fault/entropy/erasure tests, hostile aggregate resource workloads and dedicated public ML-DSA testnet operation | Accepted binary/platform results; reviewed final budgets; real elapsed soak under predeclared success/abort criteria; operator/recovery/upgrade evidence; all release findings dispositioned |
| Production activation (not admitted) | Enable the reviewed production backend and remove the hold through a separate explicit go/no-go | Approved exact release dossier and consistent protocol, registry, admission, packaging, checklist and warnings; proof that shipped binaries use that backend |

All twelve obligations in [production readiness](PQSIG_PRODUCTION_READINESS.md)
remain production exit criteria. Contract drafting precedes its approval; code
audit follows reviewed experimental implementation; full-block measurements and
public soak follow a working testnet; hold removal follows qualification. None
is a prerequisite to creating the artifact it must assess.

Human review under issue181 is required before authorizing experimental
integration. No unresolved Critical/High finding may pass; every Medium needs
verified remediation or explicit justified acceptance under the review contract.
The author or an automated model cannot manufacture human independence. A
stage document, vector PASS, JSON flag, or green CI is not an advancement decision.

## Evidence and scope rules

- Preserve rc2 accepted-set semantics, the frozen network/genesis identity and
  existing algorithm registry. No numeric ML-DSA ALG_ID is selected here.
- The existing backend-admission JSON remains the historical/current isolated
  prototype record. Its source pins, booleans and open-gate statuses are unchanged.
  Design permission is documented here, not by falsifying prototype admission.
- Old results retain exact source, binary, platform and workload identities.
  New results need their own source/delta assessment; do not relabel old evidence.
- Resource `PENDING_BASELINE_OBSERVATION`, trusted false, promotion false remains
  bounded numeric/DATA evidence. The review and resource guards are distinct.
- SHRINCS issue240 is not an ML-DSA soak. Its thirty-day period does not silently
  define the ML-DSA acceptance period or provide ML-DSA operator receipts.
- Additional signing platforms, hardware wallets, physical attacker exclusions,
  dependency changes, new network identities and real-value activation require
  their own reviewed scope decisions. No current test constitutes general
  platform, constant-time, FIPS, whole-system erasure or operational approval.

The initial byte model and its unresolved integration choices are in
[the draft production contract](ML_DSA_44_PRODUCTION_CONTRACT.md).
