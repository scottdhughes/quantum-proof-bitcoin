# ML-DSA-44 production contract — draft 0

## Status: DRAFT_FOR_REVIEW - NOT A CONSENSUS SPECIFICATION
## Spec-ID: PQBTC-MLDSA44-DRAFT-0

This is the first concrete design/vector slice under
[staged admission](ML_DSA_44_STAGED_ADMISSION.md), not an approved production
protocol. The executable model lives in `contrib/ml-dsa-production-contract/`.
It pins a proposed signing envelope and key commitment. It does not create a
Bitcoin/PQBTC network transaction, address, signature, private key or wallet.
Its limits bound the design model, not consensus or production resource admission.

## Agreed scope and proposed architecture

Agreed: Linux x86_64 software signing, GCC and Clang; hardware wallets deferred.
Exact release compiler/libc/CPU/OS support floors still require qualification.

Proposal: deterministic public-only verification in the node and a separate local
signer process that initializes core/dump policy before threads, owns guarded key
memory and never releases expanded secret keys. This avoids loading a
process-wide memory policy late into an arbitrary node lifecycle. It adds IPC,
availability and shutdown obligations; it is not automatically approved merely
because the isolated Linux lifecycle module exists.

The future signer must authenticate its local peer, enforce framing and bounded
requests, validate the full request, and release a signature only after strict
self-verification. Exact socket/peer authentication, request authorization,
rate/queue limits and IPC operations must be reviewed before implementation.
Never introduce entropy-dependent consensus verification.

## Proposed key and recovery contract

- Canonical private material is a 32-byte ML-DSA key-generation seed; the
  2560-byte expanded key is derived within the owner and is not imported/exported.
- Generate independent per-key seeds from the approved OS entropy boundary;
  do not quietly reuse the rc2 seed or invent an HD derivation from it. Wallet
  master/HD derivation is not yet specified by this draft and remains a design
  decision, not an implemented or deferred feature claim.
- Restore must derive the public key from the authenticated recovered seed,
  compare its chain/profile-bound commitment, then atomically install the owner.
  A syntactically well-formed record is not proof of seed/public-key consistency.
- Persisted seed material must be authenticated and encrypted, with bounded KDF
  and concurrent restore costs, version/chain/profile binding, crash-safe writes
  and rollback/compromise policy. The existing 176-byte backup pilot is evidence
  to assess, not an adopted production wallet file format.
- Key lifetime and destruction must serialize against use; failure before output
  acceptance may leave output untouched, while later accepted-output failures
  clear it. Consumed entropy stays consumed. No deterministic fallback, secret
  logging, raw expanded-key IPC or silent unsupported-platform downgrade.

## Executable envelope grammar

`contract_model.py` accepts a strict JSON object with exactly these members:

```
schema, network, transaction, input_index, public_key
```

`schema` is exactly `PQBTC-MLDSA44-DRAFT-0`. `network` is `main`, `test` or
`regtest`; these select the already-frozen genesis and message magic, not an
activation. `public_key` is 1312 bytes of lowercase hex. It is an encoding input,
not proof of a generated key or possession. `input_index` selects one input.

`transaction` has exactly `version`, `inputs`, `outputs`, `lock_time`.
`version` is signed32; `lock_time` unsigned32. Each input has exactly
`prev_txid` (32-byte display-order hex), `prev_index` (unsigned32), `sequence`
(unsigned32), `amount` (unsigned64 restricted to the inherited MAX_MONEY), and
`script_pubkey` (lowercase hex). Each output has exactly `amount` and
`script_pubkey`. Booleans are not integers. All arrays must be nonempty; input
outpoints must be unique; input/output totals must each fit MAX_MONEY and outputs
must not exceed inputs. Coinbase requests and arbitrary sighash modes are absent.

The model accepts at most 100 inputs, 100 outputs and 10000 script bytes per
entry. These are provisional model/fixture bounds only; production consensus,
mempool, signer and batch budgets remain unqualified and must be frozen separately.

JSON must reject duplicate keys, NaN/Infinity, unknown/missing members, noncanonical
hex and trailing data. Binary parsing must reject nonminimal CompactSize,
truncation, unknown network/version/schema prefixes and trailing bytes.

### Binary envelope (not transaction wire serialization)

Concatenate, in this exact order:

1. ASCII `PQBTC-MLDSA44-DRAFT0` followed by one zero byte.
2. Frozen network message magic (4 raw bytes).
3. Frozen genesis hash (32 bytes, reversed from display-order hex).
4. Transaction version (signed32 little endian).
5. Sighash selector `01` (ALL only; this is not an ALG_ID).
6. Input index (unsigned32 little endian).
7. Public key (1312 bytes).
8. Minimal CompactSize input count.
9. For each input: reversed txid32, prev_index unsigned32LE, sequence unsigned32LE,
   amount unsigned64LE, minimal CompactSize script length and script bytes.
10. Minimal CompactSize output count.
11. For each output: amount unsigned64LE, minimal CompactSize script length and
    script bytes.
12. Lock time (unsigned32LE).

CompactSize uses one byte below253, `fd` plus unsigned16LE through65535, `fe`
plus unsigned32LE through4294967295, otherwise `ff` plus unsigned64LE. This model's
object bounds reject larger counts before iteration/allocation.

### Proposed hashing and signer binding

Define `TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)`.
Tags are exact ASCII bytes, with no terminator.

- Key commitment tag: `PQBTC/MLDSA44/draft-0/key`.
- Key commitment data: network magic4 || reversed genesis32 || public key1312.
- Signing message tag: `PQBTC/MLDSA44/draft-0/sighash-all`.
- Signing message data: the complete binary envelope above.
- Signing message: exactly the resulting32 bytes, passed as pure ML-DSA's
  message, not as external-mu or HashML-DSA.
- ML-DSA context: exact ASCII `PQBTC/tx-signature/draft-0`.

The envelope binds all input outpoints, sequences, prevout amounts and scripts,
all outputs, version, locktime, input index, network identity and signing public
key. The node must retrieve amounts/scripts from its validated UTXO view; a signer
cannot authenticate them merely because a caller supplied these bytes. The
generic existing wrapper accepts variable messages/contexts: the future
transaction/signer layer must enforce this exact binding. Draft domains differ
from the older `PQBTC/tx-signature/v1` research fixture. They must never be
silently substituted into a deployed profile.

## Vectors and what their execution proves

The checked-in JSON corpus pins exact envelope bytes, signing messages and key
commitments, plus malformed cases. A separately expressed reference serializer
in the tests checks the literal corpus without calling the model's encoder.
Cross-field mutations must change the message or be rejected. The public-key
bytes are synthetic public encoding fixtures, not ML-DSA keygen/signature KATs.
No fresh signing, external implementation interoperability, wallet spend or
cryptographic review is implied by a vector PASS.

## Remaining decisions before experimental integration

This first draft does not allocate numeric ALG_IDs, witness versions/opcodes,
address/descriptor/PSBT encodings, a persisted encrypted-wallet format, HD paths,
final resource budgets or activation heights. Opaque scripts in these vectors
are not a proposed locking-script implementation. Complete those decisions as
one cohesive reviewed specification, including wrong-key/domain/chain/replay,
upgrade/rollback and recovery cases, before authorizing experimental node code.
Also settle signer IPC/authorization and whether optional signer modes enter the
initial launch scope; hardware wallets alone are already explicitly deferred.

Independent human review181 and the production qualification obligations remain
open. This draft intentionally produces no backend-admission change, baseline
pointer advance, resource promotion, node linkage or real-value deployment.
