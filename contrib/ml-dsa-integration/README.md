# Native ML-DSA integration building block

This is real native cryptography over the reviewed CONTRACT-1 transaction
message, not a mock or Python signer. It is **not yet linked into the node** and
does not implement a wallet, IPC service, mempool policy or active witness rules.

The new `src/crypto/mldsa44/verify.c` compiles the unchanged pinned portable
capsule with key generation/signing/randomized APIs absent. The C++ adapter
validates bounded unsigned transaction wire, supplied prevouts, amounts and
outpoints; calculates network-bound commitment and component-hash message; and
checks an exact native-v2/32 witness against the public-only verifier.

The native fixture is a dedicated process that initializes the existing guarded
key owner's runtime policy, imports a PUBLIC `00..1f` test seed, signs with fresh
OS entropy, and verifies the result through the new public-only build. Do not
use the fixture seed or this smoke program for custody. Bad field/context/network,
witness shape, range, duplicate/coinbase and malformed wire cases are exercised.
Python independently joins native serialization/digest/commitment to the v1 model.
That is a cross-language contract check, not an independent crypto implementation.

In an approved offline bounded Linux container, run:

```
python3 contrib/ml-dsa-integration/run_native_tests.py --cc gcc --cxx g++
python3 contrib/ml-dsa-integration/run_native_tests.py --cc clang --cxx clang++ --sanitize
```

`--expect-head SHA` requires an exact clean checkout before/after. Without it,
actual commit/cleanliness is recorded, not silently claimed clean. Reports retain
source/build-mode/compiler/ELF/binary identities. Any successful-exit diagnostic
on stderr fails qualification, including recoverable sanitizer reports. The
verifier's real dynamic exports are allowlisted; all object symbols are searched
for forbidden keygen/sign/RNG/fork/secret-policy machinery. A hidden upstream
public-data constant-time barrier is not a public export.

Normal and ASan/UBSan tests are required for GCC and Clang. Local aarch64 results
do not qualify x86_64 release binaries. No constant-time, FIPS, general erasure,
aggregate-resource, crash durability, wallet/node spend or operational approval
is claimed. Effective node parameters must be joined to GENESIS-v1 before any
actual activation; target artifact identities are not current C++ node settings.

The [owner continuation](../../docs/ML_DSA_44_OWNER_CONTINUATION.md) permits the
engineering work without demanding another human reviewer. Technical testing,
separate automated review, honest risk disclosure and release decision remain.
