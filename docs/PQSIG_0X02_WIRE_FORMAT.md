# PQSig 0x02 Wire Format

## Status: FROZEN
## Spec-ID: PQSIG-WIRE-future-0x02
## Frozen-By: issue-26-forward-path-20260327
## Consensus-Relevant: YES

## Scope
Freeze only the outer envelope for the neutral `future-0x02` allocated-future profile.

## Frozen Envelope
- `ALG_ID = 0x02`
- `PK_script` length is exactly 33 bytes
- Layout: `ALG_ID(1 byte) || PK_core(32 bytes)`
- Signature length is exactly 4480 bytes
- Fixture vectors reuse the current PQSig outer field names:
  - `msg32`
  - `pk_script33`
  - `sig4480`

## Present-Day Semantics
- `future-0x02` is allocated for fixture and harness coverage only.
- Current releases MUST reject `ALG_ID=0x02` in parser, verifier, signer, descriptor, wallet, and PSBT paths.
- This spec exists so the allocated-future path is frozen and testable without broadening acceptance.

## Non-Goals
- No activation rules
- No signing semantics
- No consensus validity
- No wallet, descriptor, or PSBT acceptance
- No interoperability guarantees beyond present-day rejection
