# Isolated ML-DSA signer work

Experimental Linux regtest-only custody engine with a public wallet companion
and real two-node demo (below), not production admission or inherited CWallet/UI
integration. No real funds or real passphrases. Hardware wallets deferred.

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
of replacement with an older valid encrypted record or host/VM rollback. A live
Wallet object also preserves counters it already knew for that wallet ID, even
across Lock/Unlock; a failed Unlock does not publish lower record counters.
Optional public-entry comparison is a library API; the pilot CLI accepts only
the explicit expected ID and counter floors, not a manifest-entry import.

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
or node IPC. Input and output descriptors must be distinct, already open and
numbered at least3. `--operator-out-fd` emits this public checkpoint after
Create/Unlock and after clean shutdown (never root/passphrase/private seeds):

```
MLDSA_WALLET_STATUS_V1 <wallet_id_hex32> <generation> <next_receive> <next_change>
```

The operator must retain these public records independently/off-host and approve
the recovery scan range. They are not a per-reservation journal: an abrupt crash
can leave the last off-host checkpoint behind the durable file and issued
addresses, so retained address records or an explicit scan range are still
required. Every restart uses `--restore`, not `--create`. Production operator
UI/service-manager integration is not provided.

One worker serializes custody operations behind a16-entry waiting queue and
at most64 authenticated connections. Frames, idle connections and writes have5s
deadlines; clients must reconnect after idle closure. Private results are checked
again for expiry before delivery and every write, not only when signing finishes.
Operations have60s late-result discard without asynchronously killing secret
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

## Actual two-node spend and encrypted restore

The explicit experimental build now supplies actual daemon validation for native
witness2/32, not only a standalone verifier. Use ONLY the prepared offline,
bounded Linux environment. `ENABLE_EXPERIMENTAL_MLDSA44=ON` builds the feature;
`-regtest -mldsa44demo=1` selects the valueless chain. Ordinary/default-OFF chains
keep their old identities and accepted rules. The demo has full GENESIS-v1
regtest identity, HRP`rq`, a distinct `mldsa44-regtest-v1` data directory and no
seeds. Its fixed H=1 manifest requires the complete pre-H UTXO view to be empty,
including cache overlays/tombstones, on startup at genesis and at transition.
This is NOT a production activation manifest or nonempty-chain rollout method.
Crash roll-forward is not a fresh replay of that guard: H=1's pre-H emptiness
relies on the sole genesis being unspendable. Arbitrary database rollback or
corruption recovery is not qualified by the reindex/reorg test.
`mldsa44demo` is command-line only: any occurrence in any configuration section
or settings file is refused, even if a command-line value would override it.
The base data namespace and selected consensus identity must agree. CMake pins
both the exact contract and manifest bytes and reconfigures when either changes;
the actual RPC binding is compared against that manifest by the functional test.

Build `pqbtcd`, `pqbtc-cli`, `pqbtc-mldsa-client` and `test_pqbtc` with CMake.
The public client links framing/verification only, never private wallet/key-owner
or libcrypto. The daemon rebuilds signature messages from the actual transaction
and locked Coins in CheckInputScripts, including asynchronous owned closures.
The new read-only `getblockchaininfo.valueless_mldsa44_demo` object reports its
effective full network binding, frozen spec hash and wallet activation state.

`node_wallet.py` is a PUBLIC companion library, not a replacement for CWallet.
It talks to ordinary RPC and the authenticated native AF_UNIX client. It stores
only public keys, derivation paths, identity and high-water counters in a0700
node-owned directory (0600 files, single writer, strict parsing, fsync/rename).
Limit4096 public entries/16MiB is demo wallet policy, NOT a consensus limit.
Uncertain writes poison the instance and retain the temporary file for explicit
operator recovery. It does not silently clear/overwrite that file. Public import
requires an empty store and a signer already restored with the retained floors.
Do that before status/address operations on a fresh recovery directory.

Only confirmed, owned, mature inputs are supported. RPC Coin reads are individual
observations, NOT atomic cs_main-held snapshots. The companion rechecks after
signing and requires normal testmempoolaccept; actual broadcast/validation is
authoritative. No node-supplied false amount can authorize a valid actual spend.
There is no automatic seed-only scan, unconfirmed-change signing, arbitrary-digest
signing, hardware-wallet support or production operator UI here.
Imported public entries are not regenerated by the signer during import. A
foreign entry may distort a scan/display, but cannot sign as an owned path; an
operator must authenticate retained public recovery records independently.
The public store intentionally requires import before status on a fresh store;
exhausting its entry cap can consume one signer index without returning it.
That fail-closed gap is not index reuse or a seed-only recovery guarantee.

The host-only `run_node_demo.py` checks the approved offline runtime before
launching every node, signer, socket and file operation inside Linux:

```
python3 contrib/ml-dsa-signer/run_node_demo.py --container pqbtc-mldsa-demo-exec-20261028 --source /tmp/mldsa-demo-source --build /tmp/mldsa-demo-build
```

The prepared runtime also needs the isolated `pilot-signer` at
`/tmp/demo-signer-bin/pilot-signer`, built against the pinned OpenSSL3.6.5 static
library. Nodes run asUID1001; the signer asUID1000; the node cannot open the
encrypted record. The only password is a deliberately PUBLIC test phrase sent
over a separate operator descriptor, never argv/env/node IPC. All test directories
and encrypted backups are retained. No Docker ports are published; peers connect
directly over namespace-local loopback. No seed node is needed for this demo.
The node RPC credential is deliberately PUBLIC fixture text on argv/URL. It
does not isolate node RPC from the signer UID; real operator credentials and
production cookie/service-manager authorization are outside this harness.
The reported `active` means the tip has reached H, not softfork next-block
readiness. Pre-H address refusal is tested; at H=0 no spendable Coin exists,
so the pre-H funding policy branch is not a general-chain funding proof.

The runner records exact clean source identity and daemon/client/signer and
script hashes before and after execution. It runs both validation-only and full
spend/restore modes. The test mines valueless funding, signs/broadcasts/mines a
spend, rejects altered signature/output/outpoint and false-prevout-amount/script
variants through BOTH mempool admission and block validation on BOTH real nodes,
requiring the script-verification rejection reason. It separately tests the
signer's path/script refusal, quiesces
the old wallet, restores an encrypted record from BEFORE address issuance using
retained public floors, scans from the second node, spends two restored outputs,
then exercises native LOCKED refusal/reorg/reindex/restart and compares both
whole final UTXO hashes/counts as well as the final output. Reindex completion
is waited for explicitly. CPU-emulated runs use a recorded fourfold timeout
factor (still bounded), not disabled or weakened behavior assertions.
CPU emulation, when used for x86_64 binaries on an ARM Docker VM, is reported
explicitly. It is not physical x86 timing/leakage/resource/erasure qualification.
No result here removes production admission/release holds, establishes FIPS or
cryptographic certification, or supplies an operational public-network soak.
Reports inspect every executable's ELF/dependencies and the pilot's own crypto
version; both the service and node runners check executable hashes before and after execution
and refuses optimized Python rather than allowing stripped checks to print PASS.

Remaining experimental limitations: already-queued private work may still finish
after disconnect (no output delivered; a committed index is not rolled back).
Crash leftovers, a hard-link create interruption or a stale socket can require
explicit offline operator recovery. Preserve the directory and inspect exact
ownership/inodes/links before any manual repair; no automatic cleanup is supplied.
Supported x86_64 release hardening flags, power-cut/fault/load coverage and service
manager recovery remain qualification work, not supplied by this pilot's green
tests. Client backlog error classification/reconnect ergonomics are also pending.

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
