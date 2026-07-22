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

The C-oracle rows are a frozen manual review dated 2026-07-21. The weekly job
refreshes RustSec and OSV evidence, but it does not yet query or semantically
compare the OpenSSL and mldsa-native feeds. A new advisory in either feed must
be handled by a dated ledger refresh (or future feed automation). This
freshness limitation is one reason issue #189 remains open; the workflow must
not be described as proving current all-oracle advisory status.

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
| RUSTSEC-2026-0077 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.8 | UNTESTED for an exact ML-DSA-44 regression; retained upstream test is ML-DSA-65 |
| RUSTSEC-2026-0125 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.9 | UNTESTED and not applicable to portable; blocks SIMD256 admission until an exact regression passes |
| RUSTSEC-2026-0126 | libcrux-ml-dsa 0.0.10 | not affected; above fixed 0.0.9 | UNTESTED and not applicable to portable; blocks SIMD256 admission until an exact regression passes |
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
does not need to wait for an external reviewer. Issue #189 remains open for
the exact-commit independent re-review required by issue #181. Production
admission and any release-hold decision remain separate and unchanged.

Primary machine inputs are:

- `contrib/ml-dsa-engineering/advisory_ledger.json`
- `contrib/ml-dsa-engineering/run_advisory_ledger.py`
- `.github/workflows/ml-dsa-44-advisory-ledger.yml`

The prior checksummed technical review and its JSON evidence are immutable
historical artifacts. This dated follow-up supersedes only the old generator's
package-wide advisory PASS wording; it does not rewrite the historical files.
