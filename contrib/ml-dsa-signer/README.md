# Isolated ML-DSA signer work

Experimental Linux regtest-only custody engine, not a node-integrated wallet or
production admission. No real funds or real passphrases. Hardware wallets deferred.

The native wallet implements CONTRACT-1 private HD and authenticated167-byte
records, with AES256GCM and fixed scrypt131072/8/1 under a160MiB cap. OpenSSL3.6.5
is statically linked into the signer only, never silently replaced by system
libcrypto. Long-lived root/passphrase and owned secret scratch use guard pages,
kernel mlock, DONTDUMP and DONTFORK. This does not prove OpenSSL's internal KDF
workspace is locked or every transient copy erased; binary/system qualification
is still required. Process core/dump policy is initialized before secret input.

Storage uses a signer-owned0700 directory,0600 record, no-follow component walk,
one flock-held writer and ciphertext-only same-directory temporary files. Record
file fsync, atomic publication and directory fsync precede address return. Any
uncertain save destroys usable root/passphrase state and requires reopening with
explicit recovery inputs. A lost reply skips an index instead of reusing it.

Unlock requires the expected public wallet ID and explicit public high-water
counters, plus optional public branch/index/key/program entries to regenerate
and compare. The operator supplies a retained manifest or an explicitly approved
scan range. There is no seed-only/gap-limit recovery guarantee and no detection
of replacement with an older valid encrypted record or host/VM rollback.

Run only in the approved bounded offline Linux environment:

```
python3 contrib/ml-dsa-signer/run_signer_tests.py --cc gcc --cxx g++ --openssl-prefix /tmp/openssl-install
python3 contrib/ml-dsa-signer/run_signer_tests.py --cc clang --cxx clang++ --openssl-prefix /tmp/openssl-install --sanitize
```

Reports identify actual commit/cleanliness, compiler flags, ELF, dependencies,
static-library/CLI bytes and native observations. `--expect-head SHA` demands
exact clean before/after. Current reused dependency was built with GCC on
aarch64; a Clang caller does not turn it into a Clang-built dependency. The new
objects are instrumented in sanitizer modes; the reused libcrypto is not.

Native tests use PUBLIC fixtures and temporary ciphertext files, not an actual
operator wallet. Compiler controls are strict and actual stderr must be empty.
Fault injection lives only in the test executable's linker-wrapped fsync, not in
production classes. A simulated filesystem error is not a physical power-cut test.

The public IPC codec is a separate object from the secret-owning session. It
enforces request/response direction, nonzero16-byte correlation IDs,32-byte
headers,1MiB bodies, exact lengths, minimal CompactSize and fixed status shapes.
The serial session requires exact network/spec HELLO, rejects reused IDs and
allows at most64 completed operations. The AF_UNIX transport authenticates
peer credentials before giving a session any request bytes.

The explicit `--valueless-pilot` launcher runs as a non-root signer UID distinct
from the configured non-root node UID. A signer-owned0750 socket directory and
0660 socket use an operator-configured common primary group. Both ends check
kernel SO_PEERCRED; this is not protection against root or process-lineage proof.
The node-side client links public verification/framing only, not wallet/key-owner
or libcrypto. The operator supplies the public-fixture password through a separate
inherited descriptor (u16LE byte length, then exact bytes), never argv, environment
or node IPC. Production operator UI/service-manager integration is not provided.

One worker serializes custody operations behind a16-entry waiting queue and
at most64 authenticated connections. Frames and writes have5s deadlines;
operations have60s late-result discard without asynchronously killing secret
work. LOCK prioritizes a wipe barrier, cancels queued address/sign work and
discards older successful private outputs. Already delivered bytes cannot be
retracted. Unlock after LOCK requires operator restart through the separate FD.

Retain builds with `--build-dir /tmp/mldsa-service-UNIQUE` for the host-only
orchestrator `run_service_tests.py --build-report REPORT --checkout CONTAINED_PATH`.
It checks the approved container restrictions and runs all native binaries,
socket fixtures and ciphertext operations inside that container under separate
UIDs. Tests cover actual peer gates, malformed/slow frames, descriptor rejection,
replay,64 completions, signing/lock, restart, restored-record high-water handling
and node inability to read the record. A test-only translation unit exercises
the actual private worker's queue bound, cancellation and deadline flags using a
linker-wrapped pause before real signing; no test hook enters the pilot binary.
This scheduler test does not itself prove real-time scheduling guarantees or
all wire-level races. No claim of node UTXO/Script/RPC integration follows.

SIGN_TX reconstructs messages internally, verifies all issued paths/prevout
commitments and the operator fee cap, then releases one all-or-nothing set of
self-verified signatures. It exposes no arbitrary-digest signing function. Output
policy allows v2/32 or zero-value OP_RETURN with one direct length-minimal push:
length0..75 directly,76..80 via PUSHDATA1. This is local signer policy, not a new
global Script/MINIMALDATA or consensus rule. Metadata comes from the authorized
node; the eventual node must verify against its real UTXO set independently.

Protocol background: [CONTRACT-1](../../docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md).
Implementation references: [OpenSSL3.6 AEAD API](https://docs.openssl.org/3.6/man3/EVP_EncryptInit/),
[OpenSSL3.6 scrypt](https://docs.openssl.org/3.6/man7/EVP_KDF-SCRYPT/).
External human review remains NOT PERFORMED under the disclosed owner exception.
