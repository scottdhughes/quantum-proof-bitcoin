# SHRINCS v1 frozen research profile

Status: RESEARCH ONLY - CONSENSUS DISABLED - RELEASE HOLD.
The production backend is NONE. ML-DSA-44 remains the separate primary engineering candidate; this reconciliation does not select SHRINCS for production.

## Exact authorities

- Profile: `pqbtc-shrincs-v1`.
- Executable draft: `SHRINCS/shrincs-bip@a5891ec5b360a732c097e1d6af1ae59515a2560a`.
- Native leaf recovery and SHA-256: `remix7531/libshrincs@911c583cc9c4e5e54a91695a1c6d2a114968715c`.
- Controlling research policy: [manifest](../contrib/shrincs/manifest.json).
- The parameter explorer is parameter-only. The old C++ and Simplicity lineages remain incompatible historical references, not interchangeable verifiers.

The v0 draft `acc6bda51dc3b94848d118967247ad0f3cd7a80e` and native `53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5` receipts retain their original sources. No old branch image, CI campaign, proof claim, or retained artifact becomes v1 evidence by renaming a pin.

## Semantic migration

The upstream draft advanced by 146 commits. This migration includes the stateful message-hash ordering fix, indicator-based serialization, variable-width leaf indexes, tree-structure-bound secret derivation, typed addresses, and state-selection boundary corrections.

For stateful hashing, let `leaf = height[1] || index[8]` in big-endian order:

```text
inner = SHA256(R || PK.seed || PK.sf_root || leaf || M)
H_msg_sf = SHA256(R || PK.seed || inner || leaf)
M = 0 || context_length[1] || context || PK.sl_root || message
```

The old order placed `leaf` before `inner` in the outer hash. Golden preimage tests distinguish the two. This is an upstream semantic correction, not a demonstrated exploit or security proof from this repository.

### Canonical wire format

| Mode | Indicator | Serialized signature |
| --- | --- | --- |
| Stateful | height h in 0..254 | h || R[16] || index[k] || WOTS+C[514] || authentication_path[16d] |
| Stateless | 255 (0xff) | 0xff || SLH-DSA component[5776] |

For stateful mode, `d = 255-h` and `k = ceil(min(d,64)/8)`. Exact length is `531+k+16d`: 548..4619 bytes. The stateless total is exactly5777 bytes. A key remains48 bytes. Every indicator byte has a defined role; there is no reserved indicator invented by this implementation.

The parser rejects empty/truncated/extended inputs, mismatched indicator/length, redundant index bytes and indexes outside `[0,2^min(d,64))` before cryptographic work. It avoids shifts by64 or greater. There is no automatic v0 fallback.

The research ABI retains its existing eight arguments and strict0/1 return values. It accepts messages up to4096 bytes and contexts up to255 bytes. These are research limits, not selected consensus rules.

### Key derivation and native scope

The stateful PRF address binds `tree_balanced` and `tree_depth` into its first payload word:

```text
int(tree_balanced) * 2^24 + tree_depth * 2^16
```

Consequently, old signing/key-generation vectors cannot be relabeled current-profile results. The native component's signer/keygen API still uses the old zero-structure PRF. Its eight historical KATs remain a labeled legacy self-test. Eight additional current-draft-generated cases qualify native public-key recovery only. They do not qualify the native signer for the new structure contract.

Typed addresses serialize to22 bytes. The checker compares every address family, both shape values, nonzero depths and nontrivial indexes against independently composed expected bytes. UXMSS includes the terminal left leaf; depth-zero keys select only stateless signing. Signer state is not implemented here.

## Frozen data and required campaigns

| Corpus | Cases | Raw JSON SHA-256 |
| --- | ---: | --- |
| Stateful | 7 | `bbc5e7aaa56f95496a361e936a933091653fcd78ffaea8a1a26431a86ba35278` |
| Stateless | 2 | `cfca4a6624358fc2e3a9497dc06955c6981ca2bfe84d5cd92179d027bc5b4ad0` |
| Maximum envelope | 2 | `95165cddca970a16f7c65b0870172b4dfb65b2b91dc5fcb9711956650e0f286d` |

Raw bytes and per-vector key/signature identities are locked independently in the committed checkers. Rehashing substituted bytes does not authorize a new corpus. Sources must match frozen Git blobs, including files hidden by index flags; untracked/ignored/staged substitutions fail before importing or compiling upstream inputs.

The stateful campaign requires7 valid signatures,32352 signature-bit rejections,2688 key-bit rejections,42 structural/binding negatives and14 native ABI checks. Stateless requires2 valid signatures,46312 signature-bit rejections,384 key-bit rejections,12 structural/binding negatives and14 ABI checks. The strict combined campaign covers all nine valid signatures and60 negatives plus28 ABI checks.

Normal corpus bytes are retained for combined and stateless ASan/UBSan replay. The standalone stateful sanitizer run regenerates deterministic cases and must yield identical retained bytes. Current recovery is checked normally and under sanitizers.

Seven additional depth1/8/9/63/64/65/255 FXMSS component cases exercise maximum encoded indexes with real native WOTS recovery and Merkle hashes. Their fixture fixes only the message digest; they are explicitly SYNTHETIC_FXMSS_RECOVERY_FIXED_MESSAGE_DIGEST, not full-SHRINCS signing KATs or generated balanced trees of enormous size. Normal and sanitizer records must agree byte-for-byte.

Resource evidence checks all11 locked valid vectors,11 zero-work parser negatives, bounded allocation, and every emitted function in all nine object/stack-file pairs. The4096-byte ceiling is per emitted function, not aggregate call-stack usage. The one-shot compression model is implementation-specific; upstream midstate/average estimates are separate. Bounded sanitizer fuzzing must retain every locked valid seed and publish complete logs/findings. A120-second smoke test is not sustained fuzzing.

## Execution and evidence boundaries

Execute third-party Python/C only in disposable isolated environments without credentials, wallet state, public servers, or real-value data. Local tooling containers are not deployed node images.

The full-workflow artifact contains stateful/stateless corpora, the separately labeled synthetic FXMSS boundary report, and corpus checksums. The resource artifact contains exactly the three corpora, resource report/model, complete stack report and six-entry internal checksum file. Fuzz evidence is separate.

A successful PR synthetic-merge run proves only that runtime source. After merge, qualify the distinct actual-main runtime, all relevant workflows, the full platform/fuzz matrix, raw logs and artifact API/upload/download hashes. Local or prior-source receipts do not substitute.

The upstream Rocq/VST/SSProve infrastructure and new SHA-256 implementation are pinned, but PQBTC does not claim to have reproduced or audited that formal proof suite. Library authenticity, readable nonnull pointers, valid disjoint buffers, and concurrent hostile host mutation remain caller/build obligations.

## Path toward production: open obligations, not automatic promotions

All14 admission gates remain false and release_hold=true. Research-profile pinning is not production-profile admission.

| Gates | Evidence still needed before production consideration |
| --- | --- |
| exact_profile_frozen, strict_parser, independent_kats, differential_verifiers | Explicit production profile/encoding decision, independent review of the exact normative bytes and parser limits, broader independently sourced KATs and differential implementations. This bounded profile is input, not closure. |
| resource_envelope, sustained_fuzzing | Production workload/limits, architecture-complete and aggregate-stack review, prolonged structure-aware fuzzing, regression retention and independently reproduced bounds. |
| security_proof_reviewed, external_cryptographic_review | Qualified independent cryptographic review of the exact construction/parameters/proof assumptions and the implementation boundary. A code-review pass or upstream theorem label does not supply this. |
| side_channel_review, fault_review, hardware_signer_evidence | Selected backend/platform assurance, realistic leakage/fault tests, entropy and zeroization guarantees, signing-device evidence and key lifecycle. |
| state_machine_crash_tests, consensus_audit, zero_value_labnet_soak | Reviewed durable reserve-before-sign/burn-on-attempt/recovery design, transaction and consensus proposal/audit, independent operators and the full30-day zero-value soak in issue240. |

A practical sequence is:
1. Complete this v1 reconciliation, independent review and actual-main qualification.
2. Reconcile the old-profile transaction/native/labnet draft stack separately; none is automatically approved or advanced here. PR233 remains a parallel alternative.
3. Obtain external cryptographic review and make an explicit production-candidate/backend choice, considering the separate ML-DSA-44 track.
4. Close the signer/device/lifecycle, sustained-fuzz/resource and consensus/operational obligations with their own reviewed evidence.
5. Consider a separate release/admission decision only after those gates are satisfied. Never infer production readiness from green CI.

Reserve state durably before invoking signing, burn on attempt, prohibit rollback after reorg/rejection, require fresh state for replacement signing, reject uncoordinated clones, and restore conservatively through recovery. The upstream state guide is useful design input, not a deployed state machine or proof of safety.
