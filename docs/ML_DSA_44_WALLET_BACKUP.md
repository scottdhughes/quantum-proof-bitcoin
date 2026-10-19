# ML-DSA-44 encrypted recovery and zero-value application pilot

This separate `contrib/ml-dsa-wallet-backup/` prototype exercises a real native
encrypted seed backup and fresh-process recovery. It does **not** replace the
node's old RC2 research wallet, create Bitcoin transactions, implement wallet
RPC/PSBT/descriptors, allocate a consensus algorithm identifier or activate a
production backend. `production_backend=NONE`, `consensus_enabled=false`,
`release_hold=true` / `RELEASE_HOLD` and all admission gates stay unchanged.

The [approved design](ML_DSA_44_WALLET_BACKUP_DESIGN.md) specifies the exact bytes
and scope. This is an experimental recovery format, not a production wallet-file
standard or an assurance that all wallet/key-format obligations are complete.

## Recovery package and API

The176-byte binary package has a96-byte authenticated header,64-byte encrypted
payload (seed32 plus SHA256(public key1312)) and16-byte GCM tag. One experimental
suite uses scrypt N131072/r8/p1/output32/maxmem160MiB and AES-256-GCM with random
salt16/nonce12. The header pins the pilot domain, version, suite, lengths and
costs. Unsupported fields and lengths are rejected before derivation, without
fallback or parameter-controlled resource work. Weak passwords remain susceptible
to offline guessing; neither a length minimum nor these bounded tests prove
adequate password entropy or aggregate-resource safety.

`backup.h` adds create/restore and three zero-value intent operations. Passwords
are counted16..1024-byte inputs, with no C-string truncation or normalization.
This does not make the KDF injective: scrypt/HMAC can map trailing-zero-padded
passwords to the same key. Callers own and must erase their password copies.
The native demo has only a clearly public synthetic fixture credential; there
is no general user-secret/password import CLI, argument or environment channel.

Create exports the seed into private staging, encrypts it and wipes the entire
staging object. Restore does not import any provisional GCM plaintext before tag
authentication. It then regenerates a temporary owned key, checks the complete
authenticated public-key hash and only on success publishes the initiallyNULL
owner. Bad tags/passwords/header encodings and commitment mismatches never
publish a key. Accepted nonalias create failures clear the package output;
invalid or aliased outputs are rejected without writing. Existing live owners
are never overwritten. Accessible-pointer, destruction synchronization and
non-hostile concurrent-memory assumptions remain caller obligations.

The new artifact includes the unchanged owned-key translation unit, permitting
complete allocation alias guards without expanding its original API. Its normal
exports are exactly the existing7 owned-key functions plus5 backup/pilot
functions; raw/test/upstream symbols are hidden. Separately loaded signer
artifacts have separate module entropy/lifecycle state, not one coordinated
signing domain. OpenSSL3.6.5 is statically linked here only for backup cryptography;
ML-DSA still uses the frozen portable mldsa-native capsule. Neither is linked
into the node by this contribution.

## Files and fresh processes

The small POSIX adapter uses a held owned0700 directory and validated basename.
It creates an exclusive0600 temporary file, writes and syncs it, atomically links
without replacing any destination, removes its owned temporary name and syncs
the directory. Failures after publication return `INDETERMINATE`: the file may
exist even though durability/cleanup could not be confirmed. No rollback or
automatic destructive retry is promised. Load requires an owned regular0600
single-link file and an exact bounded176-byte read. Symlinks, extra bytes,
untrusted modes and existing destinations fail closed.

The test driver execs four distinct processes: public-only challenge creation,
producer, restorer/signer and public-only verifier. Producer exits after backup;
restorer regenerates the original public key, signs, destroys the key and exits.
Verifier receives a separate directory containing only public key/challenge/
intent/signature, not the encrypted backup or a password input. Verification
tests reject changed domain/key/challenge/amount/signature and malformed lengths.

The intent is112 canonical bytes with a fixed pilot domain, public-key hash,
caller challenge and amount exactly0. It signs SHA256(intent) as a pure ML-DSA
message with context `PQBTC-ZERO-VALUE-INTENT-v1`. It is **not** a Bitcoin
transaction, sighash encoding, production address or persistent replay database.

## Reproduction and evidence

Safe data-only checks (no new native code loaded):

```sh
python3 contrib/ml-dsa-wallet-backup/run_backup_tests.py --preflight-only
python3 -m unittest ci.test.test_ml_dsa_wallet_backup
```

Native execution is supported only in the approved contained Linux toolchain or
ephemeral CI, never on the daily workstation. Build the exact approved OpenSSL
archive using `build_openssl.sh` in that environment. Then run:

```sh
python3 contrib/ml-dsa-wallet-backup/run_backup_tests.py --cc gcc \
  --expect-commit FULL_CHECKOUT_SHA --openssl-prefix /tmp/new-openssl-prefix \
  --output-dir /tmp/new-evidence-directory
```

The destination must not exist. Source-only local mounts must opt into
`--allow-source-only`; they are not exact-head or trusted-main evidence. Frozen
wrapper/capsule/key/control hashes and module inventory are checked before native
compilation. Pinned archive-build identity, actual libcrypto digest and native
runtime version are recorded; arbitrary library authenticity is still a trusted
build obligation, not authenticated plugin support.

GCC/Clang each run normal+ASan/UBSan codec808, file1034 and process16-check
campaigns. The deterministic public fixture matches separate libgcrypt AES-GCM
and hashlib.scrypt code, calibrated by primitive KATs. Its raw package SHA256 is
`919274349faf698e32052f75e07e4f7e6fbb997f45ca9895902623fe40b46506`.
Real compiled omitted-authentication/header-binding/wipe controls must fail the
specific behavioral assertions. Normal exports and an actual unfiltered build
calibrate symbol isolation. Tests observe owned staging cleanup and injected
file/entropy/allocation/provider failures, not complete provider/OS/physical erasure.

Each successful artifact has `backup-report.json`, `native-transcript.json` and
`evidence-sha256.txt` (two internal checksums), with source/runtime/compiler,
commands and observed results. No generated secret seed or expanded key is
retained. PR proof and actual-main proof must be qualified separately.

## Still required for production

This partly advances issues187/190, not their closure. Human independent
cryptographic review181, entropy184, leakage/fault/resource/platform assurance,
actual wallet/transaction/protocol integration, supported-platform operations,
independent operators/issue240 30-day soak and explicit admission remain open.
There is no HD derivation, mnemonic, legacy migration, password rotation,
revocation/stale-backup detection, hardware signer, swap/dump/hibernate/fork-safe
application guarantee or whole-system erasure. Lost passwords have no bypass;
old compromised backups remain useful. SHRINCS remains a zero-value pilot.
