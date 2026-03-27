# ALG_ID Registry

## Status: FROZEN
## Spec-ID: ALG-ID-REGISTRY-v1
## Frozen-By: issue-24-alg-id-registry-20260326
## Consensus-Relevant: YES

## Purpose
Define the assigned script-layer `ALG_ID` values, their lifecycle states, and the change-control rules for future allocations.

## Lifecycle States
- `RESERVED_INVALID`: permanently invalid sentinel value; MUST fail in current releases.
- `ACTIVE`: valid for current releases and bound to a frozen wire/internal spec set.
- `ALLOCATED_FUTURE`: allocated for future work but not valid until a later consensus/deployment decision activates it.
- `RETIRED`: no longer valid and MUST NOT be reused for different semantics.
- `UNALLOCATED`: no assignment exists; value is invalid.

## Current Registry

| ALG_ID | Profile | State | Owning Specs | Activation Notes |
| --- | --- | --- | --- | --- |
| `0x00` | none | `RESERVED_INVALID` | none | Permanent invalid sentinel; MUST fail. |
| `0x01` | `rc2` | `ACTIVE` | `PQSIG_WIRE_FORMAT.md`, `PQSIG_INTERNALS.md`, `Spec.md` | Current GA PQSig profile. |
| `0x02` | `future-0x02` | `ALLOCATED_FUTURE` | `PQSIG_0X02_WIRE_FORMAT.md`, `PQSIG_0X02_INTERNALS.md` | Allocated for fixture and harness work only; still invalid in current releases. |
| `0x03-0xff` | none | `UNALLOCATED` | none | Invalid until a future allocation freezes the profile and activates it later. |

## Allocation and Governance Rules
- Only `ACTIVE` `ALG_ID` values are valid in current releases.
- A new `ALG_ID` requires a dedicated child issue under epic [#14](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/14).
- Before allocation, the new profile MUST have a frozen wire-format spec and a frozen internal-parameter spec.
- Allocation moves an entry to `ALLOCATED_FUTURE`; it does not make that value valid in running releases.
- Moving an entry from `ALLOCATED_FUTURE` to `ACTIVE` requires a separate consensus/deployment decision and implementation tranche.
- `RETIRED` values remain permanently reserved and MUST NOT be reassigned to different wire semantics.
- `UNALLOCATED` values are invalid and MUST fail parser and script validation until a later frozen allocation exists.
