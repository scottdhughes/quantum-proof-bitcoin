# Project Completion Plan

Assessment date: 2026-10-15. Protected-main evidence revision observed:
`1c3fccfe1fc68e6e779d9e3bbf4b6779de19266d`.

This is an engineering work sequence. The controlling production decision
remains [PQSIG_PRODUCTION_READINESS.md](PQSIG_PRODUCTION_READINESS.md).
Production backend remains `NONE` and the release hold remains in force.

## Progress

The Bitcoin integration and CI inventory baseline are established. The October
13 Promotion Matrix run
[38457326871](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/38457326871)
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

The October 14 scheduled sustained run
[38543015542](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/38543015542)
completed four retained-corpus 1,800-second sanitizer campaigns on this exact
head. Scheduled review run
[38550795835](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/38550795835)
reproduced OpenSSL 3.6.5 conformance and completed the fifth 1,800-second
campaign. The [versioned receipt](reviews/evidence/ml-dsa-44-trusted-main/1c3fccfe1fc68e6e779d9e3bbf4b6779de19266d/SOURCE.json)
records independently checked archive digests, internal checksums, retained
source artifacts and ancestry, nonzero imports, durations, and zero crash
results. Resource run `38457326603` passed its GCC and Clang numeric policies
on the same head. These are bounded engineering results, not release approval.

The SHRINCS track remains a separate draft research stack, including draft PRs
#227, #229-#234, #236-#239, and #241. A public zero-value labnet and its soak
obligations are tracked in #240. These drafts do not supply ML-DSA production
acceptance or authorize merging the alternative signature track into main.

## Immediate Maintenance

1. Completed: PR #257 repinned the isolated OpenSSL oracle from 3.6.4 to the
   security release 3.6.5 at
   `e44a19f352181b3f0aab090d122e2a4562e95512`. Scheduled advisory run
   [37337066507](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/37337066507)
   correctly rejected thirteen affecting CVEs. The source commit, tree,
   annotated tag, release archive, runtime version, and vector provenance now
   agree, while historical advisory records and the exact cryptographic
   vectors remain unchanged.
2. Completed: PR #258 separately advanced the review pointer to that merge
   commit. The post-pointer main head above has an empty guarded baseline
   diff; scheduled frozen-baseline reproduction has resumed successfully.
3. Record the completed resource and retained-corpus evidence above. Current-
   feed advisory/SBOM/Miri run `38795613101` also passed and its artifact was
   independently checked: zero affected OpenSSL 3.6.5 feed entries, the exact
   reviewed Rust scanner dispositions, and portable Miri `3/3`. Finish
   collecting the separately dispatched exact-main wrapper run `38795609463`
   before describing the whole refresh as complete. Portable GCC/Clang and
   calibrated TSan jobs have passed; their direct lifecycle/concurrency scope
   must remain distinct from fuzzing.
4. Merge the tested evidence/admission-status bookkeeping, then advance the
   guarded baseline in a separate pointer-only PR. The machine-readable
   OpenSSL conformance entry must cite the verified main report, while its
   disposition stays `ORACLE_ONLY`. Do not weaken the baseline guard to make
   bookkeeping pass. Record subsequent main observations under their own
   exact revisions rather than relabeling earlier evidence.

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
