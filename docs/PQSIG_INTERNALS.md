# PQSig Internals

## Status: TRACKED
## Spec-ID: PQSIG-INTERNALS-rc2
## Frozen-By: issue-48-rc2-reprofile-20260306
## Consensus-Relevant: YES

## Scope
Consensus-locked internal parameterization for the PQSig rc2 profile in PQBTC.

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
- Signing is deterministic and exact-root bound.
- `R = Hash32("PQSIG-PRFMSG", sk_seed, msg32, pk_script33)`.
- The 4-byte per-layer count field is reserved and MUST be all-zero in rc2.
- `max_counter` remains a signer API bound, but signing no longer grinds for acceptance.

## Exact Public-Root Binding
- `PK.root` is the exact message-independent public root derived from the fixed top hypertree layer.
- WOTS signatures reconstruct fixed leaf public keys from the signature, message nibble schedule, `pk_seed`, `layer`, and `leaf_index`.
- Hypertree auth paths bind those leaf public keys to an exact Merkle root.
- Verification succeeds only when the reconstructed final layer root matches `PK.root` byte-for-byte.

## Safety Properties
- Parser treats signature and key inputs as hostile.
- Parameter values are immutable consensus constants.
- Unknown `ALG_ID` is invalid.
- Any nonzero count field is invalid.
