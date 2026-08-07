# ML-DSA-44 Advisory Ledger and Dependency Refresh

Status: engineering contract implemented; exact-commit workflow evidence and
independent re-review remain required. This document does not change the
production backend (`NONE`) or the release hold.

## Purpose and Scope

`contrib/ml-dsa-engineering/advisory_ledger.json` is the machine-readable
adjudication contract for the pinned libcrux 0.0.10 research oracle. The
scheduled workflow fails closed if a selected-package RustSec entry, scanner
finding, package version, dependency graph, architecture, backend, SBOM
component, or required evidence file differs from that reviewed contract.

The ledger also inventories the exact OpenSSL 3.6.3 and mldsa-native beta2
source pins. Their dated rows name the official OpenSSL 3.6 feed and the
mldsa-native repository-advisory feed, respectively. Cargo advisory scanners
apply only to the libcrux crate and its published `Cargo.lock`; an empty Cargo
result is not claimed for either C source oracle.

The global dependency snapshot and the mldsa-native/libcrux rows retain their
2026-07-21 date. The OpenSSL row was separately refreshed on 2026-08-06 after
CVE-2026-54876 was published, while every relevant workflow run continues to
acquire and validate both public machine feeds. OpenSSL is checked from the
current Git head of the official `openssl/release-metadata` `secjson` corpus.
The validator requires the reviewed 273-record completeness floor, all 38
reviewed OpenSSL 3.6 records, supported CVE 5.0/5.1 structures, and exact
semver evaluation for the 3.6.3 pin. A missing record, ambiguous range,
malformed schema, unreviewed affecting advisory, or change to the reviewed
CVE record or path disposition fails closed.
The sole reviewed upstream irregularity is CVE-2023-2650's empty exclusive
`3.1.1` to `3.1.1` row; it is outside 3.6, exactly allowlisted, and retained in
the normalized report. Any other empty range fails pending review.

The mldsa-native public GitHub repository-advisory response is required to be
HTTP 200, JSON, API-version pinned, non-paginated, and an empty array. Any
published advisory stops the job for review. This feed does not expose private
draft advisories or replace monitoring of disclosures published outside the
repository. Cargo advisory scanners still apply only to the libcrux crate and
its published `Cargo.lock`; no package-ecosystem result is claimed for either
C source oracle.

Three dependency scopes remain separate:

1. The published crate contains a 139-package lock universe. `cargo-audit` and
   OSV scan this complete file, including development, benchmark, optional,
   and target-specific packages.
2. The x86_64 portable execution contract selects 16 normal/build packages
   with `--no-default-features --features std,mldsa44`.
3. cargo-cyclonedx 0.5.9 emits a conservative 24-component, 23-node/41-edge
   normal-dependency/target closure, including optional normal packages and the
   root library target. It is retained as an SBOM, not mislabeled as the
   executed graph.

The workflow records all three. A finding outside the selected graph is not
discarded; it must have an exact package/version disposition in the ledger.

## Backend and Architecture Contract

The retained lane is Linux `x86_64-unknown-linux-gnu`. It calls
`ml_dsa_44::portable` and requires:

```text
LIBCRUX_DISABLE_SIMD128=1
LIBCRUX_DISABLE_SIMD256=1
```

Those variables are security-relevant. libcrux's build script otherwise
enables SIMD by architecture even when Cargo default features are disabled.
The report records runner architecture, Rust target, compiled backend, and
called backend independently. SIMD128, SIMD256/AVX2, and every production
backend remain unadmitted.

## Dated Advisory Inventory

The 2026-07-21 ledger covers every RustSec entry currently present across all
16 packages in the selected execution graph:

| Advisory | Package | Pin disposition | Exact test disposition |
| --- | --- | --- | --- |
| RUSTSEC-2025-0133 | libcrux-intrinsics 0.0.8 | not affected; above fixed 0.0.4 and current runner is not AArch64 | not applicable to current architecture |
| RUSTSEC-2026-0074 | libcrux-sha3 0.0.10 | not affected; above fixed 0.0.8 and affected incremental API is outside ML-DSA | not applicable |
| RUSTSEC-2026-0076 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.8 | PASS for two exact ML-DSA-44 portable malformed-hint rejections; upstream retained test is separately labeled ML-DSA-65 |
| RUSTSEC-2026-0077 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.8 | PASS for pinned Wycheproof ML-DSA-44 tcIds 125 and 126 with positive and negative signer-response coefficients at the infinity-norm boundary across all three oracles; upstream retained test is separately labeled ML-DSA-65 |
| RUSTSEC-2026-0125 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.9 | PASS in trusted-main test-only SIMD256 evidence for exact ML-DSA-44 tcIds 147 and 148; not applicable to the current portable path |
| RUSTSEC-2026-0126 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.9 | PASS in trusted-main test-only SIMD256 evidence for all three exact shipped inverse-NTT regressions in debug and release; not applicable to the current portable path |
| RUSTSEC-2026-0207 | libcrux-sha3 0.0.10 | not affected; at fixed 0.0.10 and advisory excludes ML-DSA use | not applicable |
| RUSTSEC-2026-0208 | libcrux-sha3 0.0.10 | not affected; at fixed 0.0.10, SIMD256 disabled, and advisory excludes ML-DSA output lengths | not applicable |
| RUSTSEC-2026-0212 | libcrux-secrets 0.0.6 | not affected; at fixed 0.0.6 and current runner is not AArch64 | not applicable to current architecture |
| RUSTSEC-2026-0097 | rand 0.10.1 | not affected; at the first fixed release | not applicable to the reviewed feature/API contract |
| RUSTSEC-2019-0035 | rand_core 0.10.1 | not affected; above fixed 0.4.2 | not applicable to the legacy BlockRng API |
| RUSTSEC-2021-0023 | rand_core 0.10.1 | not affected; above fixed 0.6.2 | not applicable to the legacy seeding helpers |

`affected_status` and `test_status` are deliberately separate. A version above
a fixed range is not represented as a regression-test PASS. `UNTESTED` is
permitted only when the pin is not affected or the current path is not
applicable and a future admission block is explicit.

### OpenSSL CVE-2026-54876

OpenSSL 3.6.3 is version-affected by
[CVE-2026-54876](https://openssl-library.org/news/secadv/20260805.txt); the
ledger does not relabel the pin as unaffected. OpenSSL rates the issue Low and
describes a TLS-client memory leak in X.509 OCSP response checking. Exploitation
requires an application to enable `X509_V_FLAG_OCSP_RESP_CHECK` or
`X509_V_FLAG_OCSP_RESP_CHECK_ALL`, accept an attacker-controlled OCSP response
with no single-response entries, and repeat handshakes to accumulate a denial
of service. OCSP response checking is not enabled by default.

The current research path is explicitly `NOT_APPLICABLE`. The two reviewed
OpenSSL adapters use the default provider and EVP ML-DSA key generation,
signing, and verification only; they contain no TLS, X.509-verification, OCSP,
certificate, or network path. Their exact local source/include closure and the
exact official CVE-record hash are part of the machine contract. The validator
rejects any unbound quoted include. The OpenSSL FIPS modules are
also outside the affected boundary, but that is supporting context rather than
the applicability basis because this oracle uses the default provider.

The official fix for the 3.6 branch is commit
`155b5fe0f93365e6df1c56ee3606b121080c6c12`, targeted at 3.6.4. No 3.6.4
release tag was available at the 2026-08-06 review. A signed, reproducible
3.6.4-or-later release is the repin trigger; the full oracle and campaign
evidence must then be rerun. Any future TLS/X.509/OCSP use or production
linkage requires explicit re-review before admission. The production backend
remains `NONE`, and this disposition does not change the release hold.

## SIMD256 Regression Promotion Boundary

The test-only x86_64 AVX2 workflow now encodes the exact regression tranche
needed before the 0125/0126 ledger rows can be reconsidered:

- RUSTSEC-2026-0125 uses pinned Wycheproof ML-DSA-44 tcIds 147 and 148 and
  requires identical expected valid/invalid results from explicit
  `portable::verify` and `avx2::verify` calls;
- RUSTSEC-2026-0126 runs the exact shipped
  `inv_ntt_unreduced_max`, `inv_ntt_reduced`, and
  `inv_ntt_reduced_large` AVX2 libtests in debug and release profiles from the
  verified 0.0.10 crate;
- the crate archive, Wycheproof source manifest, vector file, harness, case
  semantics, and case payload hashes are fixed; and
- the extracted crate remains read-only and byte-identical through execution.

The lane fails closed when x86_64 or AVX2 is unavailable. Pull-request output
is explicitly untrusted. Trusted-main push run `30242969373`, attempt `1`,
passed at exact commit
`f301227089086dad6918a76814d7227e61e2d71b`. The retained artifact has GitHub
artifact ID `8643946330`, 20 members, 10,700 bytes, and outer SHA-256
`3c7e4bb5ce00e04186b295c9e1272b9440c5e77627cc3b320f256dd9038305a5`.
`SOURCE.json` preserves the workflow identity and source hashes; the
fail-closed validator reads the archive without extracting it and requires
its exact structure, checksums, logs, report semantics, and backend/release
disposition.

The checked-in 0125/0126 rows now record exact regression `PASS`, but current
path applicability remains `NOT_APPLICABLE`: `production_backend` remains
`NONE`, `simd256_admitted` remains false, and the release hold remains true.
A re-pin must rerun the regressions, and any future SIMD256 admission requires
a separate review.

## Current Full-Lock Findings

The reviewed lock is not scanner-empty. The exact current set is retained and
classified:

- RUSTSEC-2026-0204: `crossbeam-epoch 0.9.18`, a criterion/rayon benchmark
  dependency outside the selected graph;
- RUSTSEC-2024-0436 and RUSTSEC-2026-0162/0163/0166: unmaintained
  paste/pqcrypto test dependencies outside the selected graph;
- RUSTSEC-2026-0173: unmaintained `proc-macro-error2 2.0.1`, present in the
  broad lock but absent from the exact selected cargo tree; and
- RUSTSEC-2026-0190: unsound `anyhow 1.0.102`, a target/unselected locked
  dependency absent from the exact Linux selected tree.

The scanners therefore return nonzero. The workflow captures their complete
JSON and exit codes without suppressing warnings; the local driver then
requires exact equality with the reviewed finding set. A new, removed, or
changed finding fails until it is explicitly reviewed.

## Retained External-Tool Evidence

The read-only workflow pins and hashes cargo-audit 0.22.2, OSV Scanner 2.4.0,
and cargo-cyclonedx 0.5.9. Each run also retains:

- the raw OpenSSL `secjson` archive, current repository commit/root/subtree
  identities, normalized 3.6 ranges, and exact 3.6.3 affected-ID result;
- the raw mldsa-native advisory body, response headers, curl metadata, request
  contract, exit code, and normalized published-ID result;
- the current RustSec database commit and every database entry found across all
  16 selected package names;
- the exact OSV crates.io database ZIP, response headers, and SHA256;
- raw cargo-audit and OSV reports and exit codes;
- the published Cargo.lock, its exact 139-package inventory, selected cargo
  tree, Cargo metadata, exact-target CycloneDX component/dependency graph,
  source/tool identities, and tool binary hashes;
- the original and prepared Miri locks, prepared manifest and exact example
  source, preparation report, logs, and result;
  and
- a normalized adjudication report plus verified `SHA256SUMS`.

The workflow runs for relevant pull requests, pushes to `main`, a weekly
schedule, and manual dispatch. Evidence is uploaded even on failure and kept
for 90 days.

## Supplementary Miri Lane

The Miri lane uses `nightly-2026-07-20` and the exact published libcrux crate.
It first verifies the original crate and lock, removes six dev-dependency
sections from an execution-only manifest, and proves that the resulting cargo
tree still equals the reviewed 16-package graph. The original 139-package lock
continues to be scanned and retained.

The PQBTC-owned smoke calls only the portable ML-DSA-44 API and checks fixed
key generation/signing/verification, a commitment-hash bit-flip rejection,
and a malformed final hint-counter rejection. Miri is supplementary portable
Rust undefined-behavior evidence. It does not cover SIMD, C FFI, compiler
output, timing, leakage, or production integration, and it is not used to
claim closure of issue #189 by itself.

## Review and Release Disposition

This tranche may be engineered and merged after its required checks pass; it
does not need to wait for an external reviewer. The exact test-only SIMD256
regressions for RUSTSEC-2026-0125 and RUSTSEC-2026-0126 are implemented and
promoted from trusted-main evidence. Issue #189 remains open pending the
exact-commit independent re-review required by issue #181. Production
admission, optimized-backend admission, and any release-hold decision remain
separate and unchanged.

Primary machine inputs are:

- `contrib/ml-dsa-engineering/advisory_ledger.json`
- `contrib/ml-dsa-engineering/run_advisory_ledger.py`
- `.github/workflows/ml-dsa-44-advisory-ledger.yml`
- `contrib/ml-dsa-engineering/run_libcrux_simd256_regressions.py`
- `contrib/ml-dsa-engineering/libcrux_simd256_regression.rs`
- `.github/workflows/ml-dsa-44-simd256-regressions.yml`

The prior checksummed technical review and its JSON evidence are immutable
historical artifacts. This dated follow-up supersedes only the old generator's
package-wide advisory PASS wording; it does not rewrite the historical files.
