# Isolated ML-DSA Signer and Wallet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan inline, task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A real isolated Linux signer using encrypted durable wallet storage,
native private HD, authenticated local IPC and executable recovery/spend tests.

**Architecture:** Signer-only wallet library owns guarded root/passphrase memory
and the single-writer directory lock. Native CONTRACT-1 verification stays public
and separate. An AF_UNIX service authenticates peers, binds network/spec and
serializes wallet operations. The node never receives root/passphrase/key seeds.

**Tech Stack:** C++20/C11, pinned mldsa-native, existing guarded key owner, pinned
OpenSSL3.6.5 static libcrypto, Linux mmap/mlock/madvise/openat/flock/fsync/SO_PEERCRED.

**Spec:** docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md sections3–6,
docs/ML_DSA_44_OWNER_CONTINUATION.md. Prior native head0f51f45e is the base.

## Global Constraints

- Linuxx86_64 GCC/Clang software signing is the target; local aarch64 is supplemental.
- External human review NOT PERFORMED under disclosed owner exception; no stall.
- No real wallets/passphrases, host-native execution, public deployment or activation.
- All native/full-suite execution in the existing pinned offline bounded Linux image.
- Frozen vendor/wrapper/key-owner/backup/admission/pointer/workflows stay unchanged.
- Reuse the already qualified25MiB OpenSSL prefix with matching lib/CLI hashes;
  record reuse provenance, not a new upstream build or production admission.
- Fixed167-byte record,111-byte AAD, AES256GCM, scrypt131072/8/1,160MiB cap;
  exact UTF8 passphrase1..1024 bytes, no argv/env/node-IPC transport.
- Durably reserve counters before publication; any durability uncertainty locks
  custody. No rollback detection is promised against replacement by older valid data.
- No default node linkage/accepted-rule change. Actual node and release qualification
  follow this service phase and need their own exact-source evidence.

## Review Focus

- Unauthenticated plaintext must never become usable keys, even if GCM update emitted it.
- Failure after rename/fsync must not publish an address or leave usable unlocked state.
- Restoring old counters must not silently lower a supplied public high-water mark.
- Wrong peer UID, wrong network/spec, replay, response-on-request and oversized frames fail closed.
- Lock/deadline/disconnect must not release late/partial signatures or roll back reservations.

### Task 1: Native wallet crypto and durable storage

**Files:** create src/crypto/mldsa44/signer/{secret.h,wallet_crypto.h,wallet_crypto.cpp,wallet.h,wallet.cpp};
create contrib/ml-dsa-signer/{wallet_smoke.cpp,run_signer_tests.py,README.md}.

**Interfaces:** Secret<N> is noncopyable guarded storage; wallet_crypto exposes
DeriveSeed(root,network,branch,index,out), WalletId(root,network), SealRecord and
OpenRecord into caller-owned guarded plaintext. Wallet owns directory lock,
Create(passphrase), Unlock(passphrase,Recovery), Lock(), Reserve(branch),
Public(branch,index), SignTransaction(tx,prevouts,paths,fee_cap) and Status().
Recovery requires expected wallet ID and explicit minimum receive/change counters.

- [ ] Write failing wallet smoke: literal v1 HD/ID vectors; authenticated record
  roundtrip, wrong password/AAD/tag/network/length/KDF failures; no counter wrap.
- [ ] Observe missing implementation RED in contained Linux.
- [ ] Implement guarded root/passphrase/scratch and fixed OpenSSL3.6.5 record crypto.
- [ ] Implement no-follow0700 directory/0600 record, one writer, ciphertext-only
  same-directory temporary file, file fsync/atomic publish/directory fsync.
- [ ] Exercise reserve/restart/restore/high-water/no-reuse, symlink/hardlink/mode/
  second-writer and real permission-induced storage failure with no publication.
- [ ] Run GCC/Clang normal/sanitized and contained full suite, then commit.

### Task 2: Wallet signing and exact public IPC codec

**Files:** create src/crypto/mldsa44/signer/{error.h,ipc.h,ipc.cpp,session.h,session.cpp};
extend wallet and add ipc_smoke.cpp. Public codec stays separate from the secret-
owning Session so a node client never inherits wallet/private-key link dependencies.

**Interfaces:** DecodeRequest(header/body)->Frame, EncodeResponse(Frame,status,payload),
DecodeSignRequest->Transaction/prevouts/branch-index paths. Session binds HELLO,
tracks64 request IDs, validates kind/body/status; wallet signs constructed messages
only and self-verifies each result before one all-or-nothing response.

- [ ] Add failing native tests for valid owned multi-input spend, wrong ownership/
  path/fee/output/metadata, exact v1 frame/model joins and malformed/replay cases.
- [ ] Implement native derive/import/sign/destroy per input, fixed context, no raw
  digest API or root export; signer-only v2/OP_RETURN output policy.
- [ ] Implement bounded32-byte header-first codec and session state with exact
  codes1..13; no negotiation and no passphrase/path/arbitrary context command.
- [ ] Run narrow and full contained tests; commit.

### Task 3: Isolated AF_UNIX service and executable restore/spend path

**Files:** create src/crypto/mldsa44/signer/{transport.h,transport.cpp,client.h,client.cpp,service.h,service.cpp};
create contrib/ml-dsa-signer/{signer_main.cpp,client_smoke.cpp,service_smoke.py,run_service_tests.py} and owned workflow
only after source/review bounds are explicit.

**Interfaces:** operator-only startup imports/unlocks via inherited local FD;
network node interface is solely the five CONTRACT-1 commands. Strict pilot
launcher requires separate configured signer/node UIDs and validates0750 parent/
0660 socket. Client checks configured signer UID via SO_PEERCRED.

- [ ] Write failing real socket tests: unauthenticated peer, wrong server identity,
  partial/slow/oversized/response frames, replay, HELLO mismatch and locked signing.
- [ ] Implement bounded connection handling,5s framing, queue16, one signer worker,
 64 completions/connection, serialized lock and60s late-result discard.
- [ ] Run actual different-UID server/client through container launch controls;
  exercise create/address/spend/restart/restore/address-next/lock over real sockets.
- [ ] Run compiler/sanitizer matrix and full suite; commit.

### Task 4: Independent review, exact-source proof and continuation

**Files:** new evidence packet20261022-mldsa-signer.qhaZUY, review/rulings/receipt/seal;
new plan-specific ledger. Never overwrite the previous sealed native packet.

- [ ] Give complete new source/diff/spec/context to Claude tools-disabled.
- [ ] Grade findings by effect, one required RED/GREEN fix pass and green suite;
  explicitly disposition all declined items, no unchanged review rerun.
- [ ] Validate final clean exact checkout and four actual compiler reports.
- [ ] Seal failed attempts and successful proof separately labeled; preserve source.
- [ ] Continue toward actual node UTXO/Script/build/wallet/RPC and x86_64 release
  qualification. Never equate this isolated service with the whole live system.
