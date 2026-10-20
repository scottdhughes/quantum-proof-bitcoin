# ML-DSA-44 owned-key lifecycle readiness prototype

ML-DSA-44 is the production-readiness priority; SHRINCS remains a zero-value
research pilot. This module supplies one missing integration primitive, not a
production backend. `production_backend=NONE`, `consensus_enabled=false`,
`release_hold=true` / `RELEASE_HOLD`, and all admission gates remain unchanged.

## What this delivers

`contrib/ml-dsa-key-lifecycle/key_lifecycle.h` exposes one opaque owned key and
eight operations: initialize the dedicated runtime, generate, import a seed, reveal the public key, explicitly
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
  wipes the entire writable mapping body before unmapping it and sets the owner to NULL;
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

## Explicit Linux runtime and protected owners

Call `pqbtc_mldsa44_key_runtime_init()` explicitly at dedicated pilot-process
startup, before threads or secret operations. It sets and verifies both soft and
hard `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`. This costs ordinary core/debugger
diagnostics process-wide; partial failure may leave stricter policy and is not
rolled back. Loading the artifact only records its origin PID; it does not apply
the dump policy. Healthy repeated init rechecks policy without resetting entropy
history. Failed state cannot be revived. Non-Linux secret runtime is unsupported.

Each owner has inaccessible guard pages around a page-rounded writable body.
Linux mmap/mprotect, kernel `SYS_mlock`, `MADV_DONTDUMP` and `MADV_DONTFORK` must
all succeed before seed or bookkeeping writes; no heap fallback or memlock-limit
escalation. The direct Linux locking syscall avoids ASan's no-op mlock interceptor
in every build, not just sanitizer builds. Resource limits can legitimately make
construction fail. Full-body alias checks include metadata and rounded padding.

Secret operations check original PID and dump policy before key dereference or
inherited locks. A standard fork child has no owned body and must exec before
secret use; re-init cannot bypass this. Child destroy only clears its accessible
owner pointer. Public-only strict verification needs no runtime initialization.
Policy drift fails further secret use but original-process destruction still
wipes. Failed unmap clears the owner, latches failure, and may leave only a zeroed
residual mapping until exit; no retry through erased bookkeeping is attempted.

Generation obtains exactly 32 fresh bytes from the held Linux getentropy adapter
directly into the protected seed field, after policy/allocation protection. It
fails on source error, short test-interface output, all-zero or immediately
repeated samples. Generation and signing share the held module lock and one
SHAKE256 last-sample digest in this selected artifact. Acceptance is consumed on
later backend failure, but protection failure consumes no sample. Deterministic
recovery import requests no entropy. Zero/repeat guards are misuse checks, not
source certification; real getentropy is all-or-error and may block at early boot.
No userspace entropy pool, custom DRBG, deterministic fallback or caller
randomizer is added. Vendor stack/register, backup/OpenSSL scratch and caller
password/seed/export copies are not all locked by the owned mapping. Caller
serialization and erasure/protection of exported seeds remain mandatory.

Result codes retain the wrapper taxonomy: 0 success; -1 argument; -2 entropy
source; -3 short entropy; -4 all-zero entropy; -5 repeated entropy; -6 backend;
-7 signing attempts; -8 signature length; -9 verification; -10 lifecycle.
The owned-key module adds -11 allocation failure, -12 runtime policy,
-13 process origin and -14 unsupported platform. Runtime errors precede output
acceptance and leave it untouched; accepted entropy/backend failures retain the
held output-clearing contract. Use one selected key OR composed backup artifact
per pilot process, not multiple independently loaded signer DSOs.

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
manifests and changed admission/baseline/SHRINCS controls. Normal dynamic exports must be exactly the eight owned-key functions;
a real unfiltered build is rejected as a negative control. The public synthetic
ACVP seed must yield public-key SHA256
`451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34`.

Injected-failure and real OS entropy builds run normally and with ASan/UBSan.
Tests cover recovery identity, two hedged signatures, wrong key/message/context/
signature, ownership/alias failures, entropy/allocation/key-generation/signing
failures and observed all-zero body bytes immediately before unmap. A
temporary test mutant omits that wipe and must fail the observation gate. This
calibrates the test; it is not shipped as a selectable library mode. No secret
seed or expanded-key bytes are printed or saved.

Constructor owner/seed overlap uses aligned accessible storage. Output aliases
include nonzero offsets and tail-contained buffers across public/secret regions;
test-only whole-allocation snapshots check every byte stayed unchanged. Separate
compiled controls remove the constructor alias check or narrow output protection
to only the seed prefix; both must fail the corresponding boundary assertion.

Real kernel-backed mapping policy, standard fork/exec, acquisition/drift/unmap
failures, full-body alias protection, shared generation/sign repeat and concurrent
independent-owner tests run under O2, O3, bounded LTO and ASan/UBSan profiles.
Instrumented builds separately count actual seeded-keypair and inner-sign entries
after OS-adapter error/partial-write faults, with positive calibration. Signing's
high-level randomized entry necessarily runs to request entropy; the claim is
that failure stops before inner signature generation, not before all backend code.
Compiled omission controls for lock, dump/fork advice, origin and body wipe must
fail exact assertions. Unsupported fallback is a hash-bound synthetic branch
fixture, not a foreign-OS build. Optimized symbols and selected release/zeroize
disassembly are retained; they do not prove erasure of all compiler copies.

CI runs GCC and Clang on Ubuntu24.04 x86_64 at the exact PR head and separately
on actual main. Linux arm64 local results are supplemental. Schema2 artifacts
contain a source/runtime/kernel/libc/compiler-bound report, complete native command
transcript, three selected release disassemblies and five internal SHA256 checksums.
Local source-hash evidence without Git
metadata is labeled as such, never as trusted-main proof. Original guarded
wrapper/capsule bytes remain unchanged.

## Remaining production finish line

This partially advances entropy (#184), secret ownership (#187) and seed
representation (#190); none is closed. The separate backup prototype exercises
encrypted recovery and a zero-value process roundtrip, not a node wallet,
derivation tree, network/version encoding, descriptors/PSBT, Bitcoin transaction
binding or consensus activation. Owned-map locking/dump/fork restrictions are
bounded observations, not swap/hibernate/VM-rollback, hostile-host/root/kernel,
general race-destroy safety, physical fault or whole-system erasure guarantees.
Compiler/platform assurance beyond the observed profiles remains open.

In parallel,
independent human cryptographic/security review must assess the assembled
ML-DSA path (issue #181); automated code review and bounded tests do not replace
it. Operational entropy policy (#184), resource/platform assurance, independent
operators and the issue #240 30-day soak remain gates with their own evidence.
Real-value release needs separate explicit admission. Bounded lifecycle tests
are not cryptographic, constant-time, formal or production qualification.
