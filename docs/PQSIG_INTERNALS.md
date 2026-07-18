# PQSig Internals

## Status: FROZEN IMPLEMENTATION - RELEASE HOLD
## Spec-ID: PQSIG-INTERNALS-rc2
## Frozen-By: issue-48-rc2-reprofile-20260306
## Consensus-Relevant: YES

## Scope
Consensus-locked internal behavior for the PQSig rc2 research profile in
PQBTC. "Frozen" describes compatibility with the currently implemented parser
and verifier; it does not mean the construction is cryptographically validated
or approved for production. The controlling decision is
`PQSIG_PRODUCTION_READINESS.md`.

## Conformance Warning

The behavior below diverges from security-critical rules of the cited WOTS+C
and PORS+FP construction. In particular, rc2 does not enforce the WOTS+C fixed
digit sum, does not grind for distinct PORS indices or a bounded authentication
set, and does not implement the cited hypertree addressing model. The claimed
`q_s=2^40` and security level therefore do not follow from these constants.

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

## Parser And Encoding Properties
- Parser treats signature and key inputs as hostile.
- Parameter values are immutable consensus constants.
- `ALG_ID` classification and parser/version-handling rules are defined in `ALG_ID_PARSER_COMPAT.md`; assigned values and lifecycle state are governed by `ALG_ID_REGISTRY.md`.
- `future-0x02` is frozen only as an allocated-future fixture profile and defines no active signing or verification semantics in current releases.
- Any nonzero count field is invalid.
