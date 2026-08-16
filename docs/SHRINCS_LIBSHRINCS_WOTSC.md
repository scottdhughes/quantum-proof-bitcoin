# libshrincs WOTS+C Component Qualification

## Status: COMPATIBLE COMPONENT ORACLE - NOT A FULL SHRINCS VERIFIER
## Spec-ID: SHRINCS-LIBSHRINCS-WOTSC-v1
## Evidence-Updated: 2026-08-16
## Consensus-Relevant: NO

## Decision

Admit the pinned `remix7531/libshrincs` WOTS+C implementation as the first compatible independent component oracle for the pinned current SHRINCS draft.

This qualification is limited to the stateful WOTS+C leaf. It does not admit a full SHRINCS implementation, production backend, signer, wallet, Script path, consensus rule, or network activation.

## Exact Pins

| Artifact | Commit | Role |
| --- | --- | --- |
| `SHRINCS/shrincs-bip` | `acc6bda51dc3b94848d118967247ad0f3cd7a80e` | Current executable draft |
| `remix7531/libshrincs` | `53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5` | Independent C WOTS+C implementation and proof corpus |
| Original KAT source | `4795244c4208f5de69dc386f6e6a451b7aa0c4e2` | Draft commit from which libshrincs committed vectors were generated |

## Compatible Contract

The common component contract is:

| Property | Value |
| --- | ---: |
| Hash output `n` | 16 bytes |
| Winternitz base `w` | 16 |
| Chain count | 32 |
| Fixed chain-index sum | 240 |
| Grinding counter | 16 bits |
| Message digest | 32 bytes |
| WOTS public key | 16 bytes |
| WOTS signature | 514 bytes |
| Serialized address | 22 bytes |

The qualification covers:

1. public-key generation;
2. deterministic lowest-counter grinding;
3. signature generation;
4. signature-to-public-key recovery;
5. exact address and tweak behavior exercised by the committed KAT cases.

## Reproduced Evidence Chain

The CI workflow establishes the following chain:

```text
pinned current shrincs-bip executable draft
        |
        | recompute all fields for eight deterministic cases
        v
pinned libshrincs committed WOTS+C KATs
        |
        | compile and run libshrincs C tests
        v
libshrincs C pubkey_gen / sign / pubkey_from_sig outputs
```

The workflow then runs the libshrincs ASan/UBSan test target.

The KAT comparison includes each case's seeds, address, message, winning counter, chain digits, grinding hash, 514-byte signature, and 16-byte public key. Any byte drift fails the workflow.

## Formal-Evidence Boundary

The pinned libshrincs repository states that:

- VST/CompCert proves functional correctness of the C against its shared model;
- SSProve proves the WOTS+C one-time known-message unforgeability result under enumerated hash assumptions;
- a model bridge connects the WOTS+C security result to the model implemented by the C.

PQBTC pins that upstream evidence but does not independently reproduce the Rocq/VST/SSProve proof suite in this tranche. The manifest therefore keeps `formal_proofs_reproduced_by_pqbtc=false` and the project-wide `security_proof_reviewed=false` gate open.

## Why This Does Not Close Phase 1

A complete current-profile verifier still requires independently implemented and cross-checked support for:

- FXMSS tree parsing and authentication;
- balanced and unbalanced tree shapes;
- stateful signature serialization and leaf-position rules;
- FORS and the stateless hypertree;
- the 48-byte combined public key;
- stateful/stateless mode selection;
- contexts and complete SHRINCS message binding;
- strict full-signature parsing and resource bounds.

The existing Blockstream C++ and Simplicity lines remain incompatible with the pinned current draft. Consequently, the full `differential_verifiers` and `independent_kats` gates remain false.

## FXMSS Branch Finding

The `libshrincs` `fxmss` branch is important upstream research but is not admitted by this record:

1. its README says the FXMSS theorem is paper-level and is not connected to the C or shared WOTS model;
2. its current tip says a proof-soundness fix was backed out pending a proper port through the refactored hybrid chains;
3. it does not provide a complete current-draft C verifier.

The strongest next attack is therefore not to vendor that branch as finished. It is to connect a small independent FXMSS verifier to the now-qualified WOTS+C leaf contract, first for a tightly bounded UXMSS profile, and differentially test complete stateful signatures against the pinned draft.

## Validation

```bash
python3 contrib/shrincs/check_manifest.py --json
python3 -m unittest discover -s ci/test -p 'test_shrincs_candidate.py'
python3 -m unittest discover -s ci/test -p 'test_shrincs_wotsc_oracle.py'
```

The end-to-end upstream reproduction is executed by:

```text
.github/workflows/shrincs-wotsc-oracle.yml
```

## Release Posture

`consensus_enabled=false`, `production_backend=NONE`, and `release_hold=true` remain controlling. No real-value use is authorized.
