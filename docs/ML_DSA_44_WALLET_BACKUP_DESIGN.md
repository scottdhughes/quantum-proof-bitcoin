# ML-DSA-44 encrypted recovery and zero-value application slice

Status: user-approved design, implementation authorized in this chat on2026-10-18.
This document specifies requirements; it is not itself execution/merge evidence.

User authority: wallet backup/restore and zero-value end-to-end integration,
tests, independent review, green merges and actual-main verification, while
keeping the backend and release hold unchanged. Existing PR263 main verification
continues independently; its proof is not proof for this new slice.

Inspected base: primary and remote main both
`08b6f9f6a143a40a50e7466ced8b62a85f37dbc8`, clean primary checkout.
This proposal is kept in the dated evidence packet pending approval, avoiding
unapproved design edits on the main checkout while its CI finishes. The accepted
design will be committed with the isolated implementation rather than changing
the frozen guarded baseline or an older sealed receipt.

## 1. Intent and honest finish line

Provide an actual native encrypted seed-backup API and a process-separated,
disk-backed zero-value recovery exercise using the merged opaque owned-key API.
The demonstration is generate -> encrypt backup -> destroy/exit -> fresh-process
restore -> sign a canonical zero-value intent -> independent-process verify ->
destroy/exit. This is application-level recovery, not a Bitcoin transaction,
node/regtest-chain spend, wallet RPC, PSBT, descriptor or consensus integration.

The current node wallet uses the old RC2 research signature profile
(`src/crypto/pqsig/pqsig.h`: public script33/signature4480); its existing backup
test does not prove ML-DSA recovery. Linking ML-DSA into that path would conflict
with the held node/wallet admission boundary and requires a separate design.
The explicit proposal is to leave all `src/`, node/wallet/Script/consensus,
algorithm registries, functional-suite inventories and admission controls alone.
Do not describe this contribution as node-wallet integration or live readiness.

Use only disposable zero-value keys and public synthetic fixture passphrases in
automated runs. No real wallet files, user secrets, credentials, network servers,
payments or broadcasts. Existing ML-DSA and SHRINCS artifacts retain source bounds.

## 2. Agent-proposed design calls approved by the user

1. Native C in a separate `contrib/ml-dsa-wallet-backup/` prototype, reusing the
   seven-function key-lifecycle API without modifying that module or its original
   ML-DSA wrapper/capsule, manifests, baseline pointer or normal exports.
2. One seed per recovery package; the persisted private representation is exactly
   the existing32-byte standardized key-generation seed. No expanded-key import,
   export, derivation tree, mnemonic, legacy RC2 migration or production address.
3. Password protection: scrypt N=131072,r=8,p=1, output32; AES-256-GCM with a
   12-byte nonce, 16-byte tag, full authenticated header and fresh16-byte salt.
   Use pinned OpenSSL3.6.5 libcrypto only in the isolated contrib build, not as a
   node dependency or production ML-DSA backend. Its exact source pin is already
   recorded in `contrib/ml-dsa-ref/vectors.json`:
   `c8bd5a57108599ac650bbae77fcabe3109dab2e8`. No handwritten cipher or KDF.
4. Exactly one compiled zero-value pilot domain; no mainnet/testnet selector or
   consensus ALG_ID. Unrecognized versions/suites/domains are rejected, never
   guessed, migrated or downgraded. This format is experimental, not an endorsed
   interoperable production wallet format.
5. Initially Linux GCC/Clang normal and ASan/UBSan only, in contained local Linux
   or ephemeral CI. No native/upstream runtime on the daily host workstation.

The cryptographic and cost choices above were the approval point. They are not
claims of production password strength, independent cryptographic review or FIPS
module validation. Weak passwords remain vulnerable to offline guessing;
minimum length cannot prove entropy. Deliberately prefer one fixed bounded
experimental suite over attacker-selected KDF work or a compatibility matrix.

Official API references consulted: [scrypt](https://docs.openssl.org/3.6/man7/EVP_KDF-SCRYPT/)
and [EVP authenticated encryption](https://docs.openssl.org/3.6/man3/EVP_EncryptInit/).
OpenSSL documents scrypt's memory-hard parameters and explicit memory limit;
GCM authentication failure forbids using the provisional plaintext. Production
advisory acceptance is not inferred merely from these API documents.

## 3. Canonical experimental binary recovery format

Exactly176 bytes: header96, encrypted payload64, tag16. All integers unsigned
big-endian, no native structs/padding/JSON/base64, optional fields or trailing bytes.

| Offset | Bytes | Required value |
| --- | --- | --- |
| 0 | 8 | ASCII `PQBWLT1` followed by one NUL |
| 8 | 2 | format version1 |
| 10 | 2 | header size96 |
| 12 | 2 | experimental suite1 (ML-DSA-44 seed/scrypt/AES-256-GCM) |
| 14 | 2 | flags0 |
| 16 | 32 | SHA256 of ASCII `PQBTC-ZERO-VALUE-PILOT-v1`, no NUL |
| 48 | 16 | fresh random salt |
| 64 | 12 | fresh random GCM nonce |
| 76 | 4 | ciphertext length64 |
| 80 | 4 | scrypt N131072 |
| 84 | 4 | scrypt r8 |
| 88 | 4 | scrypt p1 |
| 92 | 4 | reserved zero |
| 96 | 64 | ciphertext of seed32 concatenated with SHA256(public-key1312) |
| 160 | 16 | full GCM authentication tag |

AAD is the complete96-byte header. Reject every unsupported header field and
length before KDF/allocation. The KDF profile is fixed, not selected from file
parameters. Explicit maxmem is160MiB, with no retry at weaker parameters on
allocation failure. This is a KDF budget, not an aggregate process bound.

Password APIs take counted bytes16..1024 inclusive; no Unicode normalization,
NUL termination or silent newline trimming. Counted input does not imply an
injective KDF: scrypt/HMAC can map trailing-zero-padded passwords to the same key.
Caller owns and wipes its password.
No password/seed/derived-key in argv, environment, logs, artifact reports or
command transcripts. Native demo uses a clearly public test passphrase; this
slice has no general-purpose user-password CLI or user-key migration command.

Obtain the28 random salt/nonce bytes through pinned libcrypto's CSPRNG; fail
closed on entropy failure, an all-zero sample or an immediate repeated sample
within one module instance. No caller-selected normal entropy; injected controls
only in separate test builds. Cross-process collision impossibility, entropy
quality and compromised-host protection are not established by those guards.

On restore, keep provisional decrypted bytes private until GCM finalization
authenticates the full tag. Only then import seed into a fresh initiallyNULL
owner, regenerate its public key and compare the full32-byte public hash with
the authenticated stored value. On any error leave caller ownerNULL; wipe and
free provisional plaintext/derived key/temporary seed and any created key.
Wrong password/tampered package uses one authentication-failure result, no
partial key or plaintext output. No live owner overwrite. All pointer/length,
alias and cleanup rules must be explicit in the planned native API; hostile
same-process mutation and unreadable/stale pointers remain outside its contract.

## 4. Disk and process boundary

The codec operates on fixed-size bytes; file policy is a separate small native
adapter used only in an owned temporary demo directory0700. Backups are regular
files0600, no symlink following or overwrite. Operate relative to a held directory
descriptor with a validated single basename. Stage a fresh exclusive0600 temp
file in that directory, write completely with EINTR/short-write handling, fsync
it, publish with atomic no-replace linking, unlink the owned temporary name and
fsync the directory. Existing destination, directory, symlink, write failure or
insufficient disk must not replace an existing backup. Report a post-publication
durability failure honestly as an indeterminate persisted result, not rollback.

Restore opens no-follow, verifies regular file/owner/restrictive permissions,
and reads exactly176 bytes with a bounded177th-byte rejection. File-size checks
alone do not replace exact read bounds or authentication. Same-UID hostile file
mutation and filesystem/hardware durability guarantees remain unclaimed.

The driver must actually exec new processes, not just free and re-import within
one address space: producer writes encrypted package and public key then exits;
restorer reads package/password and expected challenge, restores/signs, wipes
and exits; verifier has no password, seed or backup input, only public key,
intent and signature. Shared files between phases are only the encrypted
package and public data; no expanded secret/seed handoff. Demo credentials are
public synthetic test material, never a real credential.

## 5. Zero-value binding contract

Canonical intent112 bytes, in order: magic8 (`PQINTN1` then NUL), pilot domain32
as above, SHA256(public-key)32, verifier-provided challenge32, amount8 big-endian
which MUST be zero. No optional fields or trailing bytes. Message to the pure
ML-DSA API is SHA256(intent112); context is ASCII
`PQBTC-ZERO-VALUE-INTENT-v1` without NUL. The pilot adapter validates canonical
intent/domain/key commitment/expected challenge/zero amount before signing or
accepting a signature. Existing generic key API remains generic and unchanged.

Verify after restore with the original public key. Test wrong domain, challenge,
nonzero amount, wrong public key, altered intent/context/signature, truncation
and trailing bytes. This is not the node's Bitcoin sighash or a transaction
encoding and does not prevent arbitrary host-level signing through the existing
generic API. Challenge checking only binds one caller-supplied challenge; no
persistent anti-replay database, rollback counter or chain state is claimed.

## 6. Required implementation evidence

Before implementation: user approval of this full description, then an explicit
small implementation plan. Work in an isolated managed worktree; preserve current
primary/main and all old branches/worktrees/receipts.

TDD/native tests must cover:

- Public synthetic ACVP seed identity and encrypted roundtrip; two backups of
  the same seed differ under real CSPRNG; restore regenerates the original key.
- Public deterministic encryption fixture in a test-only entropy mode, checked
  independently against a separate implementation/API before freezing bytes;
  known scrypt/AES-GCM primitive vectors and normal export isolation.
- Every header field, every ciphertext/tag byte, wrong password, truncation,
  extra bytes, embedded NUL password, bounds, overflow, unknown versions and
  excessive KDF claims; no fallback or key release before authentication.
- Correctly authenticated seed/public-hash mismatch, failure after import,
  allocation/entropy/provider/encrypt/decrypt failures and complete cleanup.
  Real negative-control builds omit authentication/header binding/wiping and
  must fail the corresponding behavioral tests; counters alone are not proof.
- File permissions, owner/type/symlink/existing destination, short read/write,
  EINTR, fsync/publication failures, truncated crash leftovers and cleanup of
  owned temps without deletion or overwrite of pre-existing files.
- Actual process-separated zero-value happy path and all binding negatives,
  not merely mock reports or a same-process roundtrip.
- Unchanged backendNONE, consensusfalse, release_holdtrue, all admission gates,
  baseline pointer and guarded original ML-DSA inputs.

Run focused Python data/preflight tests, native GCC/Clang normal+ASan/UBSan in
isolation, relevant full `ci/test` suite and repository validators. Freeze source
before each qualifying run; do not relabel an earlier proof to a later patch.
Independent whole-candidate review is required. Required findings receive
focused RED/GREEN repair and source-specific review before ordinary push.

CI must prove exact runtime source and pinned dependency identity before compile,
then retain complete commands, observations, source hashes and internal checksums.
No secret serialization in retained reports; fixtures and their public status
are explicit. Qualify exact-head GCC/Clang artifacts and all actual relevant
checks before ordinary exact-match merge, with fresh base/head refs and no bypass
or branch deletion. Then separately verify actual merge parents/tree/scope, safely
FF clean local main, run fresh actual-main tests/validators, qualify distinct
actual-main artifacts and full actual platform matrix including CentOS/fuzz/final
aggregate. Old PR263 main receipts do not cover these additions.

## 7. Explicit exclusions and remaining production obligations

This slice partly advances issues187/190; it does not close them or human review181,
entropy184, leakage/fault/resources/platform, independent operator/issue240 soak
or admission obligations. No full wallet, HD derivation, descriptor/PSBT/hardware
signer, Bitcoin transaction/context/fee/mempool/reorg integration, arbitrary legacy
migration, password rotation/revocation, stale backup detection, online service,
physical/whole-system erasure, swap/dump/hibernate protection or general concurrency
is supplied. KDF/provider copies and optimized wipe behavior need their own bounded
evidence; module cleanup is not system-wide erasure. Lost password has no recovery
bypass. Compromised old backups remain valid after any later password change.

`production_backend=NONE`, `consensus_enabled=false`, `release_hold=true` /
`RELEASE_HOLD` and all admission gates stay unchanged. SHRINCS remains zero-value.
No production/consensus algorithm, network activation or real-value decision is
made by experimental backup suite1 or the green merge of this contrib slice.

Approval question: accept this isolated encrypted recovery/zero-value intent
slice and its proposed experimental format/cryptographic parameters, leaving
actual node-wallet/transaction integration for a separate reviewed design?
