# ALG_ID Parser Compatibility Contract

## Status: FROZEN
## Spec-ID: ALG-ID-PARSER-COMPAT-v1
## Frozen-By: issue-25-parser-compat-20260327
## Consensus-Relevant: YES

## Scope
Current-release parser and version-handling rules for PQBTC `PK_script` inputs.

## Current Contract
- Parsing is `length -> registry classification -> active-profile structural parse`.
- Classification is length-first and MUST NOT inspect `pk_script[0]` unless the input is exactly 33 bytes.
- Only `ACTIVE` `ALG_ID` values are accepted in current releases.
- `RESERVED_INVALID`, `ALLOCATED_FUTURE`, `RETIRED`, and `UNALLOCATED` values all reject deterministically.
- There is no downgrade, fallback, or alternate signature-family probing.
- Current version negotiation is explicit non-negotiation: unsupported `ALG_ID` values fail.

## Registry-State Handling
- `RESERVED_INVALID`: reject.
- `ACTIVE`: permit active-profile structural parsing.
- `ALLOCATED_FUTURE`: reject until a later activation tranche defines compatibility behavior. Current allocated-future example: `future-0x02` (`ALG_ID=0x02`).
- `RETIRED`: reject permanently.
- `UNALLOCATED`: reject.

## Structural Parsing Boundary
- Classification answers what kind of `PK_script` bytes were supplied.
- Structural parsing remains profile-specific.
- In current releases, only the active `rc2` profile may structurally parse and consume a classified `VALID_ACTIVE` `PK_script`.

## Observable Behavior
- This contract does not broaden acceptance.
- Invalid `PK_script` encoding continues to fail script evaluation as invalid public-key encoding.
- Wrong PQ signature length continues to fail independently as invalid signature encoding.
- Descriptor, PSBT, and wallet cache paths remain strict rejectors for any non-active `ALG_ID`.
