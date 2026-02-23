# PQSig Internals

## Status: FROZEN
## Spec-ID: PQSIG-INTERNALS-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Scope
Consensus-locked internal parameterization for PQSig v1 in PQBTC.

## Fixed Parameter Set
- `q_s = 2^40`
- `h = 44`
- `d = 4`
- `a = 16`
- `k = 8`
- `w = 16`
- `l = 32`
- `S_{w,n} = 240`
- Signature size: `4480` bytes

## Hash and Domain Separation
- Internal output size `n = 128` bits.
- `PRFmsg` output size is 32 bytes.
- `Hmsg` uses SHA-512 output expansion to derive instance selector and per-signature indices.
- Domain separation is mandatory across all internal hash invocations.

## Deterministic Signing Rule
- Signing uses deterministic grinding with an explicit counter inside PRFmsg input derivation.
- Counter evolution is monotonic and bounded.
- Exceeding the configured bound is a hard signing failure.

## Safety Properties
- Parser treats signature and key inputs as hostile.
- Parameter values are immutable consensus constants.
