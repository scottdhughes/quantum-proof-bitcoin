# Project Completion Plan

Assessment date: 2026-10-11. Protected-main revision observed:
`93a46456c647118dd76a2a7107a5cc714a8714df`.

This is an engineering work sequence. The controlling production decision
remains [PQSIG_PRODUCTION_READINESS.md](PQSIG_PRODUCTION_READINESS.md).
Production backend remains `NONE` and the release hold remains in force.

## Progress

The Bitcoin integration and CI inventory baseline are established. The October
5 Promotion Matrix run
[37313739622](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/37313739622)
completed successfully on this main revision. The inventory still requires
121 PQ tests and 141 dual-profile tests, with 14 legacy-only tests and no PQ
backlog. The existing rc2 signature path remains a research fixture; its known
design deficiencies require a replacement before any real-value release.

ML-DSA-44 is the selected engineering candidate. Its isolated evidence includes
70 official ACVP cases, three implementation oracles, strict malformed-input
regressions, sustained differential/verifier/signer fuzzing, resource policies,
200 reproduced upstream CBMC proofs, portable Miri, static analysis, calibrated
Valgrind checks, and bounded concurrent verification with calibrated TSan.
These results have explicit source, toolchain, platform, and campaign bounds.
The wrapper is not connected to the node or wallet.

The October 7 scheduled sustained run
[37611714495](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/37611714495)
completed successfully. Its artifacts have not been independently audited in
this assessment, so the run status alone is not a new evidence receipt.

The SHRINCS track remains a separate draft research stack, including draft PRs
#227, #229-#234, #236-#239, and #241. A public zero-value labnet and its soak
obligations are tracked in #240. These drafts do not supply ML-DSA production
acceptance or authorize merging the alternative signature track into main.

## Immediate Maintenance

1. Repin the isolated OpenSSL oracle from 3.6.4 to the security release 3.6.5.
   Scheduled advisory run
   [37337066507](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/37337066507)
   correctly rejected thirteen affecting CVEs. The new source commit, tree,
   annotated tag, release archive, runtime version, vector provenance, and
   historical advisory records must agree. The exact cryptographic vectors
   and selected ML-DSA profile remain unchanged.
2. After that PR merges and its required checks pass, verify the exact merge
   commit and create a separate pointer-only PR. Advance
   `contrib/ml-dsa-ref/review_baseline_commit.txt` to that merge commit.
   Require an empty guarded diff and preserve the baseline validator.
   Scheduled review run
   [37617963623](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/37617963623)
   stopped because the current pointer predates the merged concurrent tests.
3. After the pointer PR merges, record its exact main commit and dispatch:
   - `ML-DSA-44 wrapper prototype`, including calibrated Linux TSan;
   - `ML-DSA-44 verifier resource envelope` for GCC and Clang;
   - `ML-DSA-44 advisory ledger` for current feeds, SBOM, and portable Miri;
   - `ML-DSA-44 sustained verifier fuzzing`, four retained-corpus
     1,800-second sanitizer campaigns;
   - `ML-DSA-44 review reproduction`, the retained-corpus 1,800-second
     three-oracle campaign.
4. Independently verify artifact identity, expiry, archive size/digest, safe
   member paths, complete internal checksums, source ancestry, positive novel
   corpus import, requested duration, and zero crash/disagreement results.
   Commit a versioned receipt and update the issue-owned status using only
   those verified results.

## Remaining Deliverables

| Deliverable | Tracking | Required result |
| --- | --- | --- |
| Wallet and key representation | #190 | Reviewable specification for canonical key encodings, key ownership, derivation, backup/recovery, descriptors, PSBT, and hardware-signer boundaries; negative serialization and migration fixtures before integration. |
| Secret lifetime and erasure | #187 | Exact ownership and cleanup guarantees across wrapper, caller, compiler, allocation, failure, and supported-platform boundaries; reviewed limits for copies and snapshots. |
| Entropy and signing lifecycle | #184 | Bind the hedged-signing contract to the eventual production interface; validate supported OS entropy failures, lifecycle behavior, and module/build isolation. |
| Fault and leakage assurance | #185, #186 | Expand the explicit leakage and fault models, calibrate controls, test the supported binaries/platforms, and disposition common-mode and self-check limitations. |
| Resource and interoperability assurance | #188 | Broader platform/toolchain and Rust sanitizer coverage; sign/verify coexistence, adversarial interleavings, concurrent aggregate limits, and production parser/block-cost limits. |
| Dependencies and reproducibility | #189 | Keep exact-source advisory coverage and reproducible-build evidence current; review any backend repin or optimized-path admission separately. |
| Independent cryptographic review | #181 | Written, exact-revision review by a qualified independent cryptographer; answer required questions and resolve or explicitly disposition findings. |
| Protocol and product integration | Readiness gates 1-3 and 8-10 | Separate reviewed design for context/sighash encodings, algorithm registry, activation/agility, consensus/Script, wallet, fee/mempool policy, reorg/reindex, and migration. |
| Public soak and release decision | Readiness gates 11-12 | Zero-value testnet observations, supported-platform release evidence, completed acceptance record, and an explicit production go/no-go decision. |

After immediate maintenance, prioritize the wallet/key-format contract and
secret ownership. These define the interfaces needed for later production
work; repeated runs of an unchanged Linux harness do not complete them.
Independent review can proceed alongside these deliverables. Engineering
work does not need to wait for a reviewer, but the review gate requires its own
evidence before production activation.

## Completion Rule

The project is ready for a real-value release only when the replacement
signature design, system integration, supported-platform evidence, review,
and soak gates have explicit acceptance records. Green CI, a successful scan,
or a growing count of fuzz executions does not substitute for any missing
deliverable. No percentage-complete estimate is used because these gates have
different scope and cannot be added as interchangeable units.
