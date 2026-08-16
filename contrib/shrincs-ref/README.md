# SHRINCS reference-reproduction lane

## Status

Research-only, consensus-disabled, production release hold.

This directory contains reproducibility tooling for the pinned SHRINCS candidate. It does not provide a production cryptographic backend, a node verifier, a wallet signer, an opcode, or an activated transaction type.

## First qualified component: libshrincs WOTS+C

The first executable component is the stateful WOTS+C leaf implementation from `remix7531/libshrincs`.

The evidence chain is intentionally narrow:

1. `SHRINCS/shrincs-bip` at the pinned draft commit is the executable specification.
2. `libshrincs/test/wots/gen_vectors.py` defines eight deterministic test cases and the committed `wotsc.kat` answers.
3. `check_libshrincs_wotsc.py` recomputes every KAT field with the current pinned draft and requires byte-for-byte equality.
4. `libshrincs`' own C test suite compiles `shrincs_wots_pubkey_gen`, `shrincs_wots_sign`, and `shrincs_wots_pubkey_from_sig` and compares their outputs with the same committed KATs.
5. The PQBTC workflow also runs the libshrincs ASan/UBSan test target.

This establishes current-draft compatibility for the WOTS+C leaf component only. It does not establish compatibility or correctness for FXMSS, the stateless path, the combined 48-byte public key, full SHRINCS serialization, transaction sighashing, signer state, or consensus integration.

## Pinned inputs

The controlling pins are in `contrib/shrincs/manifest.json`:

- `SHRINCS/shrincs-bip` — `acc6bda51dc3b94848d118967247ad0f3cd7a80e`
- `remix7531/libshrincs` — `53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5`
- committed libshrincs KAT source — `SHRINCS/shrincs-bip@4795244c4208f5de69dc386f6e6a451b7aa0c4e2`

The compatibility check is necessary because the committed KATs were generated from the older draft commit. A passing run proves that the selected WOTS+C behavior did not drift between that source and PQBTC's current draft pin.

## Reproduction

With the two upstream repositories checked out at the pinned commits:

```bash
python3 contrib/shrincs-ref/check_libshrincs_wotsc.py \
  --libshrincs /path/to/libshrincs \
  --shrincs-bip /path/to/shrincs-bip \
  --json

make -C /path/to/libshrincs clean test
make -C /path/to/libshrincs check-asan
```

The GitHub Actions workflow `.github/workflows/shrincs-wotsc-oracle.yml` performs these steps from fresh pinned checkouts.

## What the result means

A pass supports the following bounded statement:

> The pinned libshrincs C implementation of the SHRINCS stateful WOTS+C leaf produces the same public keys and signatures, and performs the same public-key recovery, as the pinned current SHRINCS executable draft for the eight committed KAT cases.

It does not prove:

- that the entire current SHRINCS construction is secure;
- that the full draft has an independent compatible verifier;
- that the libshrincs formal proofs have been independently reproduced by PQBTC;
- that the provisional C API is stable;
- that the `libshrincs` `fxmss` branch is ready for use;
- that stateful signing is safe without a monotonic durable state machine;
- that any code is ready to protect real value.

## Why the FXMSS branch is not admitted

The `libshrincs` `fxmss` branch adds an abstract multi-leaf theorem, but its own documentation says the theorem is paper-level and is not connected to the C or shared WOTS model. Its current tip also records a backed-out SSProve soundness fix pending a proper port across the refactored proof chain. PQBTC therefore treats it as useful upstream research, not an implementation or proof artifact that closes a production gate.

## Next boundary

The next component tranche should connect an independently implemented FXMSS verifier to this WOTS+C leaf contract, then differentially test complete stateful signatures against the pinned draft. Until that exists, the full `differential_verifiers` and `independent_kats` gates remain false.
