# Native ML-DSA integration building block

This is real native cryptography over the reviewed CONTRACT-1 transaction
message, not a mock or Python signer. It is **not yet linked into the node** and
does not implement a wallet, IPC service, mempool policy or active witness rules.

The new `src/crypto/mldsa44/verify.c` compiles the unchanged pinned portable
capsule with key generation/signing/randomized APIs absent. The C++ adapter
validates bounded signer-request wire, supplied prevouts, amounts and outpoints.
An immutable prepared transaction owns prevout scripts and computes component
hashes once; per-input verification hashes only a fixed-size preimage. The public
witness verifier does not inherit the signer's 100-item/10,000-byte-script request
caps. The eventual node caller must apply actual transaction/resource rules and
bind the cache to the same transaction and UTXO snapshot it is checking.

The native fixture is a dedicated process that initializes the existing guarded
key owner's runtime policy, imports a PUBLIC `00..1f` test seed, signs with fresh
OS entropy, and verifies the result through the new public-only build. Do not
use the fixture seed or this smoke program for custody. Bad field/context/network,
witness shape, range, duplicate/coinbase and malformed wire cases are exercised.
Multi-input/output, second-input index, long script and immutable-cache checks are
included. Python independently joins native serialization/digest/commitment to the
v1 model and checks all three network bindings against the frozen genesis artifact.
That is a cross-language contract check, not an independent crypto implementation.

In an approved offline bounded Linux container, run:

```
python3 contrib/ml-dsa-integration/run_native_tests.py --cc gcc --cxx g++
python3 contrib/ml-dsa-integration/run_native_tests.py --cc clang --cxx clang++ --sanitize
```

`--expect-head SHA` requires an exact clean checkout before/after. Without it,
actual commit/cleanliness is recorded, not silently claimed clean. Reports retain
source/build-mode/compiler/ELF/binary identities, compiler-discovered non-system
include dependencies, the key-owner reader's source hashes and the frozen capsule
inventory digest. System-header contents are not claimed independently attested.
Any successful-exit diagnostic
on stderr fails qualification, including recoverable sanitizer reports. The
verifier's real dynamic exports and undefined imports are allowlisted. Object
symbol searches are supplemented by compile-negative probes proving that the
configured upstream header does not expose keypair/sign/sign-extmu APIs; symbol
absence alone could be an optimization artifact. A hidden upstream public-data
constant-time barrier is not a public export. These checks are not a formal proof
that no private operation can ever be synthesized from public operations.

Sanitizer child environments override inherited options, retain leak checking and
halt/abort on errors, and use no-recovery builds. Positive ASan heap-overflow and
UBSan signed-overflow controls must produce their intended diagnostics and fail.
Raw addresses replace symbolized stacks because the bounded image lacks LLVM
symbolizer; no diagnostic or error-detection check is disabled.

Normal and ASan/UBSan tests are required for GCC and Clang. Local aarch64 results
do not qualify x86_64 release binaries. No constant-time, FIPS, general erasure,
aggregate-resource, crash durability, wallet/node spend or operational approval
is claimed. Effective node parameters must be joined to GENESIS-v1 before any
actual activation; target artifact identities are not current C++ node settings.

The [owner continuation](../../docs/ML_DSA_44_OWNER_CONTINUATION.md) permits the
engineering work without demanding another human reviewer. Technical testing,
separate automated review, honest risk disclosure and release decision remain.
