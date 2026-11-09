# GitHub publication and assembled-system CI

On 2026-11-09 the owner authorized committing and pushing the tested changes,
running the GCC and Clang GitHub CI jobs, and fixing failures. This supersedes
the local-only publication status recorded in the earlier checkpoint reports.

The publication branch includes the previously implemented native ML-DSA node,
signer and wallet integration, followed by the durable browser console,
clean-checkout installer, assembled-system workflow, tests and documentation.
The native integration ancestry is preserved; no production admission or merge
is implied by publishing the branch.

The workflow checks out the exact pull-request head, builds the pinned source
with GCC and Clang inside Linux containers, verifies native test receipts,
and runs real wallet spending/recovery and container recreation. Results must
identify the tested commit and run; local ARM64 receipts are retained separately
in [clean-checkout validation](CLEAN_CHECKOUT_VALIDATION.md).

Current run results are available in the
[assembled-system workflow history](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ml-dsa-44-assembled-system.yml).
Check the run's head commit and both compiler conclusions; an older or local
pass does not qualify a later commit. This initial publication record itself
does not assert a GitHub-hosted pass.
