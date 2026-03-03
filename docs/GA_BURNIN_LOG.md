# PQBTC v1 RC Burn-in Log

## Status: TRACKED
## Spec-ID: GA-BURNIN-LOG-v1
## Frozen-By: ga-governance-20260223
## Consensus-Relevant: NO

## Window

- Start: 2026-02-24
- End: 2026-03-09
- Cadence: weekly checkpoints

## Post-Stack Baseline (After #44/#45/#46)

- Date (UTC): 2026-03-03
- Baseline merge commit (`main`): `7c07609f414dce5546257837a539a63c7ce32bd5` (PR #46)
- Stack merge commits:
  - `4f2f88338ba55b6559655273e9b97951eb0d7d3f` (PR #44)
  - `3caffa2319d67772bc31e9f4ae67e7abad6ba0f0` (PR #45)
  - `7c07609f414dce5546257837a539a63c7ce32bd5` (PR #46)
- PR evidence:
  - PR #44 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22526800151>
  - PR #44 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22526800160>
  - PR #45 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22549996865>
  - PR #45 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22549996838>
  - PR #46 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22606688905>
  - PR #46 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22606688908>
- Main baseline runs for `7c07609f414dce5546257837a539a63c7ce32bd5`:
  - CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154224>
  - Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154206>
- Notes:
  - PR #46 merged via admin path due repository base-branch policy behavior.
  - `CI / test each commit` is non-required and was still in progress at merge time.
  - All protected required status-check contexts for PR #46 were green at merge time.

## Checkpoint Template

- Date (UTC):
- Commit / tag under test:
- Environment:
- Summary:
- Soak artifacts path:
- Soak summary (`runs/passed/failed`):
- Findings:
  - `priority:P0`:
  - `priority:P1`:
  - `priority:P2`:
- Actions opened:
- Gate status:
  - [ ] deterministic artifacts
  - [ ] bench envelope
  - [ ] unit suites
  - [ ] functional suites
  - [ ] fuzz smoke
  - [ ] gatekeeper on merge commit

## Week 1 Checkpoint (2026-03-02)

- Date (UTC):
- Commit / tag under test:
- Environment:
- Summary:
- Soak artifacts path:
- Soak summary (`runs/passed/failed`):
- Findings:
  - `priority:P0`:
  - `priority:P1`:
  - `priority:P2`:
- Actions opened:
- Gate status:
  - [ ] deterministic artifacts
  - [ ] bench envelope
  - [ ] unit suites
  - [ ] functional suites
  - [ ] fuzz smoke
  - [ ] gatekeeper on merge commit

## Week 2 Checkpoint and GA Decision (2026-03-09)

- Date (UTC):
- Commit / tag under test:
- Environment:
- Summary:
- Soak artifacts path:
- Soak summary (`runs/passed/failed`):
- Findings:
  - `priority:P0`:
  - `priority:P1`:
  - `priority:P2`:
- Actions opened:
- Gate status:
  - [ ] deterministic artifacts
  - [ ] bench envelope
  - [ ] unit suites
  - [ ] functional suites
  - [ ] fuzz smoke
  - [ ] gatekeeper on merge commit
- Decision:
  - [ ] Promote to `v1.0.0`
  - [ ] Hold and cut `v1.0.0-rc2`
- Decision notes:
