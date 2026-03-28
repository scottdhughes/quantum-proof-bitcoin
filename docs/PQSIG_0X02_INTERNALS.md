# PQSig 0x02 Internals

## Status: FROZEN
## Spec-ID: PQSIG-INTERNALS-future-0x02
## Frozen-By: issue-26-forward-path-20260327
## Consensus-Relevant: YES

## Scope
Freeze only the minimum internal assumptions needed to allocate `ALG_ID=0x02` as `future-0x02`.

## Frozen Internal Assumptions
- `PK_core` remains an opaque 32-byte payload for fixture purposes.
- The signature remains an opaque 4480-byte payload for fixture purposes.
- The harness may classify `ALG_ID=0x02` as `ALLOCATED_FUTURE` and assert present-day rejection under active-profile-only parsing, signing, and verification.

## Present-Day Rejection Contract
- `future-0x02` defines no active structural parse semantics.
- `future-0x02` defines no signing semantics.
- `future-0x02` defines no verification semantics.
- Current releases MUST reject `ALG_ID=0x02` until a later tranche explicitly defines activation and interoperability behavior.

## Non-Goals
- No active parameter set
- No compatibility negotiation
- No wallet/tooling round-trip acceptance
- No activation or deployment rules
