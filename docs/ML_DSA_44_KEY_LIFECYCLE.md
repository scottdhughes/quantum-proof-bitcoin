# ML-DSA-44 owned-key lifecycle readiness prototype

ML-DSA-44 is the production-readiness priority; SHRINCS remains a zero-value
research pilot. This module supplies one missing integration primitive, not a
production backend. `production_backend=NONE`, `consensus_enabled=false`,
`release_hold=true` / `RELEASE_HOLD`, and all admission gates remain unchanged.

## What this delivers

`contrib/ml-dsa-key-lifecycle/key_lifecycle.h` exposes one opaque owned key and
seven operations: generate, import a seed, reveal the public key, explicitly
export the seed, hedged sign, strict verify, and destroy. The private allocation
contains the 32-byte key-generation seed, 1,312-byte public key, and 2,560-byte
expanded secret key. Signatures are 2,420 bytes. There is no expanded-key import,
export, clone, deterministic signer or caller-supplied signing randomizer in
the normal export surface.

This separate translation unit composes the unchanged held wrapper and frozen
portable mldsa-native v1.0.0-beta2 capsule at
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. It does not change the original
two-symbol wrapper artifact or its review baseline. The new library has its own
module state: do not treat separately loaded old/new signer libraries as one
coordinated entropy or lifecycle domain.

## Ownership contract

- Constructors take the address of a valid, initially NULL owning pointer.
  Failure leaves it NULL; a live owner is never overwritten. Import takes
  exactly 32 seed bytes and rejects overlap with the owner storage.
- Only one owner exists. Borrow it during operations, but never race destruction
  against any use. Copying the pointer does not create another owner. Destroy
  wipes the entire allocation before freeing it and sets the owner to NULL;
  destroying that NULL owner again is safe.
- Public-key and seed outputs require exact-size buffers and reject overlap
  with the entire owned allocation without writing. Signing rejects output
  overlap with the allocation and otherwise retains the held wrapper's
  validation, self-verification and accepted-output clearing on failure.
- The seed export is an explicit sensitive caller-owned copy. The caller must
  protect and wipe it. Import deterministically regenerates the standardized
  keypair, so the caller cannot supply an inconsistent public/secret pair.
  Imported seeds must have been cryptographically generated; length checking
  cannot establish seed quality.
- Owner, input and output pointers must designate accessible storage of their
  declared lengths. Arbitrary unreadable/stale pointers, hostile concurrent
  mutation and memory inspection are not authenticated by an opaque C pointer.

Generation obtains exactly 32 bytes from the existing OS entropy adapter and
fails on source failure, short output, all-zero output or an immediate repeated
generation sample. It keeps only a SHAKE256 digest for repeat detection,
independent of signing's randomizer state. An accepted generation sample is
consumed even if subsequent allocation/key generation fails; deterministic
recovery import is intentionally not treated as duplicate generation. Temporary
generation seed/digest buffers and failed allocations are wiped. Sign and import
honor the existing module lifecycle gate.

Result codes retain the wrapper taxonomy: 0 success; -1 argument; -2 entropy
source; -3 short entropy; -4 all-zero entropy; -5 repeated entropy; -6 backend;
-7 signing attempts; -8 signature length; -9 verification; -10 lifecycle.
The owned-key module adds -11 allocation failure.

## Reproduction and bounded evidence

Native proof currently supports isolated Linux. Do not execute this new native
prototype on a daily workstation or infer macOS/Windows support from portable
source. A data-only preflight is safe without compiling/loading native code:

```sh
python3 contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py --preflight-only
python3 -m unittest ci.test.test_ml_dsa_key_lifecycle
```

In the approved isolated Linux toolchain:

```sh
python3 contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py \
  --cc gcc --expect-commit FULL_CHECKOUT_SHA --output-dir /tmp/new-evidence-dir
```

The destination must not already exist. The runner checks fixed wrapper and
manifest hashes, the complete portable capsule file set and aggregate digest
before compilation. It rejects symlinks, substitutions and self-rehashed
manifests. Normal dynamic exports must be exactly the seven owned-key functions;
a real unfiltered build is rejected as a negative control. The public synthetic
ACVP seed must yield public-key SHA256
`451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34`.

Injected-failure and real OS entropy builds run normally and with ASan/UBSan.
Tests cover recovery identity, two hedged signatures, wrong key/message/context/
signature, ownership/alias failures, entropy/allocation/key-generation/signing
failures and observed all-zero allocation bytes immediately before free. A
temporary test mutant omits that wipe and must fail the observation gate. This
calibrates the test; it is not shipped as a selectable library mode. No secret
seed or expanded-key bytes are printed or saved.

Constructor owner/seed overlap uses aligned accessible storage. Output aliases
include nonzero offsets and tail-contained buffers across public/secret regions;
test-only whole-allocation snapshots check every byte stayed unchanged. Separate
compiled controls remove the constructor alias check or narrow output protection
to only the seed prefix; both must fail the corresponding boundary assertion.

CI runs GCC and Clang at the exact PR head and separately on actual main. Each
artifact contains a source/runtime/compiler-bound report, complete native command
transcript and internal SHA256 checksums. Local source-hash evidence without Git
metadata is labeled as such, never as trusted-main proof. Original guarded
wrapper/capsule bytes remain unchanged.

## Remaining production finish line

This partially advances secret ownership (issue #187) and seed representation
(issue #190); neither issue is closed. It does not supply encrypted persistent
backup, a wallet derivation tree, network/version encoding, descriptors/PSBT,
transaction binding or consensus activation. It promises no memory locking,
swap/hibernate/core-dump protection, general concurrency, fork/snapshot-safe
application use, physical fault resistance or whole-system secret erasure.
Compiler-output and supported-platform lifecycle assurance remain open.

The next concrete milestone is an explicitly versioned wallet/backup and
transaction-binding contract, followed by zero-value application integration
exercising generate → backup → restore → sign → verify → destroy. In parallel,
independent human cryptographic/security review must assess the assembled
ML-DSA path (issue #181); automated code review and bounded tests do not replace
it. Operational entropy policy (#184), resource/platform assurance, independent
operators and the issue #240 30-day soak remain gates with their own evidence.
Real-value release needs separate explicit admission. Bounded lifecycle tests
are not cryptographic, constant-time, formal or production qualification.
