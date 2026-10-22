# ML-DSA-44 production contract v1 — frozen proposal for review

Spec-ID: `PQBTC-MLDSA44-CONTRACT-1`. Status: **REVIEW CANDIDATE, NOT ACTIVE**.
This supersedes draft-0's open format choices, not its retained vector corpus.
The admission JSON, `production_backend=NONE`, `consensus_enabled=false` and
`release_hold=true` are unchanged. Neither this document nor its executable byte
models implement an integrated node backend, wallet, signer, encryption service
or production spend. The staged admission document still governs implementation.

## 1. Scope and trust

Initial target: Linux x86_64, GCC and Clang, single-user software custody, one
wallet per isolated signer process. Hardware wallets, multisignature, BIP32
xpubs/BIP39, external PSBT exchange and mixed-input signing are deferred, with
explicit unsupported errors, not fallback. The existing rc2 path stays separate.
There is no migration/reuse of classical or rc2 secret seeds.

The node validates public data; a separate signer owns secrets. The signer runs
under a different UID, initializes core/dump/memory/fork policy before creating
threads, and performs bounded serial signing. An authorized compromised node can
request spends: the node and operator are in the authorization TCB. This is not
a hardware-wallet confirmation boundary, root compromise defense, or proof of
erasure on all platforms. Human review #181 remains required; automated reviews
do not close it. All #184–190 binary/system qualifications remain open.

## 2. Wire and address decision

Use **native witness version 2**, program length 32, scriptPubKey
`0x52 0x20 <commitment[32]>`. This is a proposed new witness meaning, not a new
value in the existing PQSIG registry: rc2 `0x01` and future `0x02` are untouched.
Nested P2SH wrapping is unsupported by this profile and cannot invoke its rules.

Addresses use Bech32m (BIP350) and existing chain HRPs `pq`, `tq`, `rq` for main,
test and regtest. Encoder emits lowercase; decoder accepts uniform upper/lower
case, rejects mixed case, bad checksum/padding, wrong HRP, version !=2 and program
length !=32. Valid address syntax is NOT evidence of active spend validation.

Let `B = message_start[4] || genesis_hash[32, internal little-endian]` from the
unchanged chain parameters. Let `TH(tag,x) = SHA256(SHA256(tag)||SHA256(tag)||x)`.
Program is `TH("PQBTC/MLDSA44/key/v1", B || public_key[1312])`. No truncation,
compressed public key, alternate parameter set or implicit network is allowed.

Unsigned transaction serialization follows the existing transaction primitives:
`version:i32LE || CS(nin) || inputs || CS(nout) || outputs || lock_time:u32LE`.
Each input is `prev_txid:32 internal-order || prev_index:u32LE || 00 ||
sequence:u32LE` (empty scriptSig). Each output is `amount:u64LE || varbytes(script)`.
`CS` is minimal CompactSize, `varbytes(x)=CS(len(x))||x`; display txids are
reversed when serialized. Full witness wire inserts `00 01` after version and
inserts one witness stack per input before lock_time. Each stack is exactly two
items, **signature[2420] then public_key[1312]**, no annex, script path, extra
item or sighash suffix. All prevouts in a signing request must be owned v2 keys.
The signer verifies derived public key/prevout commitment equality. Outputs are
v2 programs or zero-valued OP_RETURN with one canonical direct push of <=80
bytes (PUSHDATA1 only for 76..80); output policy does not grant new consensus.

The eventual node v2 branch must check exact witness sizes, canonical ML-DSA
encoding, program/key binding and signature. Large v2 items require a dedicated
branch, NOT relaxing the generic 520-byte stack limit or rc2/Taproot rules.
Transaction identifiers retain double-SHA256 non-witness/witness serialization
semantics. The Python model encodes signed wire but does not verify signatures.

### Activation and historical outputs

Current `VerifyWitnessProgram` accepts unknown versions when the discourage flag
is absent. Therefore **do not issue/fund these addresses before activation**.
Proposed deployment is an explicit per-network height H, recorded in a later
reviewed deployment manifest; at/after H, native v2/32 spends use this contract
regardless of prevout creation height. Before H they have only historical
unknown-witness semantics. Chain inventory and treatment of any existing v2/32
UTXOs must be reviewed before approving H; zero such UTXOs is NOT assumed.
No grandfather exception or automatic activation is allowed. Version2/other
lengths retain unknown-version semantics. H, network rollout and chain-budget
values are deployment decisions, not unfilled byte-format choices; absent that
approved manifest a future implementation must refuse activation. No H is
allocated here, and no existing accepted-rule set is changed by this proposal.

## 3. Signature message, mode and bounds

Only ALL (selector `01`) is supported. Pure ML-DSA-44 external signing receives
message = `TH("PQBTC/MLDSA44/sighash/v1", preimage)` and exact FIPS context bytes
`PQBTC/MLDSA44/tx/v1`. This is pure ML-DSA over a protocol-defined 32-byte message,
NOT the distinct HashML-DSA mode. No caller-supplied arbitrary digest/context.

Preimage is `B || version:i32LE || lock_time:u32LE || 01 || nin:u32LE ||
nout:u32LE || Hprevouts || Hamounts || Hscripts || Hsequences || Houtputs ||
input_index:u32LE`. Each H is one SHA256 over, respectively, concatenated
outpoints (`txid32||index4`), input u64 amounts, varbytes input scripts, u32
sequences, serialized outputs. Fixed fields and minimal script lengths make
the components unambiguous. Public key is committed through its prevout script.
All amounts/scripts come from node-validated UTXOs; a dishonest authorized node
is not defeated by binding its supplied metadata. Node verification independently
reconstructs them from the actual UTXO set.

Initial signer/model limits: 1..100 inputs, 1..100 outputs, scripts <=10000 bytes,
raw unsigned transaction <=1MiB; no duplicate outpoints/coinbase, bool-as-int,
unknown JSON members, negative amounts, totals >21e14 or outputs >inputs.
Model JSON hex is exact lowercase/even. The serializer accepts other output
scripts for byte modeling; the signer applies the narrower policy above.
These are local model/signer limits, NOT qualified consensus/block/mempool
aggregate budgets. Fee caps/operator policy must be configured before custody.

Hedged signing requires fresh full OS entropy for every operation, no silent
deterministic fallback, self-verification before releasing a signature and
all-or-nothing transaction responses. No failure releases partial signatures,
secret bytes or expanded-key state. The node verifier never needs secret RNG.

## 4. Wallet, HD and recovery decision

One fresh 32-byte OS-random master root per wallet; private-only project-specific
derivation, **not BIP32** and no claim to its interoperability. Use RFC5869
HKDF-SHA256 extract with salt `"PQBTC/MLDSA44/wallet-root/v1" || B`, IKM=root.
Expand length32 with info `"PQBTC/MLDSA44/keygen-seed/v1" ||
u32BE(branch|0x80000000) || u32BE(index|0x80000000)`.
Branch0=receive,1=change; index0..2^31-1. The result is the exact ML-DSA keygen
seed, not expanded private key. Wallet ID is first16 bytes of
`HMAC-SHA256(root, "PQBTC/MLDSA44/wallet-id/v1" || B)`.
The domain salt is deliberately fixed, not password-hardening entropy.

No public child derivation, xprv/xpub import/export or root in node memory.
Watch-only operation uses an explicit public manifest of branch/index/public
key/program, bound to network and wallet ID. A future restore regenerates and
compares those public entries before installing keys. Address allocation reserves
and durably persists next_index BEFORE returning the address; lost responses
skip indices, never reuse them. Counter 2^31 denotes exhaustion, not wraparound.
Change allocation uses the same transaction and durability discipline.

Recovery requires the encrypted root record AND a retained public high-water
manifest, or an operator-approved explicit scan range. Default gap1000 is only
a discovery convenience: seed alone plus a gap limit cannot guarantee discovery
after arbitrary lost reservations. After restore rescan through every retained
high-water index and keep counters above both manifests and observed history;
never run two custodial clones of the same root. Passphrase loss is unrecoverable.

## 5. Persistence decision and crash model

Signer-only encrypted file, format1, exactly167 bytes. AES-256-GCM with12-byte
nonce/16-byte tag. Password KDF is scrypt N=131072,r=8,p=1,dkLen32; salt16 fresh
OS bytes on every write, nonce12 fresh independent OS bytes. Exact UTF-8
passphrase bytes1..1024, no normalization, argv/env/IPC/log passphrases forbidden.
Only one KDF worker, memory cap160MiB, queue16; benchmark on actual x86_64 builds
before system qualification. Proposed signer-only crypto dependency is pinned
OpenSSL3.6.5, requiring its own reviewed build/dependency admission; this does
not change the current oracle-only OpenSSL role or node consensus dependencies.

Header/AAD (111 bytes, no padding): magic `PQWMLD1\0`8, format:u16LE1,
B36, wallet_id16, generation:u64LE>=1, kdf_id:u8=1,
N:u32LE,r:u32LE,p:u32LE,salt16,nonce12. Payload plaintext40 is
`root32 || next_receive:u32LE || next_change:u32LE`, each counter <=2^31.
Append ciphertext40 and GCM tag16 to the header. Reject unknown parameters,
wrong length/network and trailing bytes BEFORE expensive KDF; authenticate the
entire header, then validate ID derived from root and public manifest before
publishing any key. No parameter downgrade or expanded-key import.

`wallet_v1.parse_record` is **framing only, authenticated=false**. Synthetic
ciphertext/tag fixtures do not test AES, passwords or tamper rejection by AEAD.
Actual crypto, secret allocation, wipe, loader and filesystem implementation
are later reviewed work. The old176-byte research backup is NOT this format.

Signer owns a0700 directory and0600 file, no symlink/path from node. Lock one
writer for the process lifetime. Create same-directory temporary file with
O_EXCL/O_NOFOLLOW, write complete new generation, fsync file, rename over old
record, fsync directory, then release address/signing operation. Crash before
rename preserves old record; crash after rename may preserve old or new until
directory fsync. A surviving record must authenticate; never auto-accept a
partial record or silently recover by lowering a counter. Durability failure
halts custody and requires explicit recovery; temporary files contain ciphertext
only. Secure deletion on SSD/filesystem snapshots is not promised.

Generation and AEAD do NOT detect replacement with an older valid record or
VM rollback. There is no trusted monotonic hardware/remote anchor in this scope.
Host root/storage rollback is outside the guarantee; no active-wallet snapshots
or clones. Operator-controlled restore/reconciliation above is mandatory. This
limitation must be visible to users, not hidden behind a generation number.

## 6. Signer IPC decision

Linux AF_UNIX SOCK_STREAM, separate node/signer UIDs. Signer-owned parent0750,
configured node group without directory-write permission, socket0660. Verify
SO_PEERCRED against an explicit node UID allowlist and configured signer UID
on the client. This authenticates OS credentials, not an unforgeable process
lineage or defense against root. No network listener, descriptor passing,
path-based commands, raw key export, arbitrary digest sign or passphrase IPC.

Frame: magic `PQMSIPC1`8, version:u16LE1, kind:u8, flags:u8=0,
request_id16 (nonzero), body_length:u32LE<=1048576, then exact body. All fields
except the HD path are little-endian. Read header before allocation, exact reads
with5s framing deadline, reject trailing bytes in a single-frame model. A stream
service may then read the next header; truncation/unknown kind/flag closes the
connection. No JSON payload. One in-flight request per connection, global queue16,
one serial signer worker; at most64 completed requests/connection then reconnect.
Reject any reused request ID during that connection; this is correlation and
bounded replay rejection, NOT cross-connection/global anti-replay or intent auth.

Requests (responses use kind|0x80, same ID, status:u16LE plus payload on success
only; error status has no payload):

| Kind | Request body | Successful response payload |
| --- | --- | --- |
| 01 HELLO | B36 + SHA256(exact UTF-8 spec file)32 | same68 bytes |
| 02 GET_ADDRESS | branch:u8 (0/1) | branch:u8,index:u32LE,pk1312,program32 |
| 03 SIGN_TX | wallet_id16,varbytes(unsigned_tx),CS(nin), per-input amount:u64LE,varbytes(prevout_script),branch:u8,index:u32LE | CS(nin), per-input signature2420,pk1312 |
| 04 LOCK | empty | empty after key destruction |
| 05 STATUS | empty | locked:u8(0/1),wallet_id16,next_receive:u32LE,next_change:u32LE |

HELLO must succeed before other operations and bind the configured network/spec
hash exactly. No negotiation/downshift. SIGN_TX count equals tx input count;
signer verifies each derived key/program and ownership, output policy, fee and
lock/unlock state before constructing messages itself. All input results are
self-verified before one response. Administrative unlock/import/export/recovery
requires a separate local operator channel, not node RPC or these five requests.

Statuses1..13: INVALID_FRAME, VERSION, BINDING, AUTH, LOCKED, LIMIT, UNSUPPORTED,
REPLAY, VALIDATION, ENTROPY, SELFVERIFY, STORAGE, INTERNAL (0=OK). Fixed codes,
no secret-bearing diagnostics. Lock is serialized with signing: stop accepting new
work, finish/discard active work, wipe, then reply. A60s signing deadline discards
late output; do not asynchronously kill a thread using secret memory. Disconnect
does not undo committed address reservations. No output cache of signatures.

The executable IPC model validates framing and SIGN_TX payloads, not sockets,
peer credentials, timeouts, state/queue/lock transitions or operator UI. Those
remain executable integration tests required before experimental backend merge.

## 7. Evidence and next gates

The accompanying models only process public fixture data, hashes and bytes.
They are not production libraries and must never handle real root keys.
The fixture root `00..1f` is PUBLIC and permanently unsafe for custody.
No ML-DSA signature KAT, encryption KAT, human cryptographic review, constant-time,
fault/erasure proof, aggregate budget or operational soak is claimed.

Review this exact contract and executable corpus first. Resolve required findings,
obtain #181 human acceptance of the production design, then authorize a reviewed
testnet backend/wallet/restore implementation; qualify actual production binaries
and system behavior, perform the dedicated soak and separately approve activation.
Resource observations retain `PENDING_BASELINE_OBSERVATION`, trusted=false,
promotion=false; there is no pointer advance or admission shortcut here.

Primary references: [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki),
[RFC5869](https://www.rfc-editor.org/rfc/rfc5869.html),
[RFC7914](https://www.rfc-editor.org/rfc/rfc7914.html).
Source anchors: `src/key_io.cpp`, `src/primitives/transaction.h`,
`src/script/interpreter.cpp::VerifyWitnessProgram`,
`src/crypto/pqsig/pqsig_registry.h`. Address/HD choices are project proposals,
not endorsements by those standards or evidence of deployment.
