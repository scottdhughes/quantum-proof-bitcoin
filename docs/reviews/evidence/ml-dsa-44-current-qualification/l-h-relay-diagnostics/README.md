# Selected relay diagnosis: controlled loss and persisted-state acceptance

These are three separate diagnostics on frozen L/H artifacts. **They do not prove
the cause of the earlier public-soak failure, qualify the subsequent M change, or
earn any 900-second preflight or 86,400-second public-soak time.**

| Diagnostic | Preserved outcome | What it establishes |
| --- | --- | --- |
| Private native-v1 loss test | First harness run FAIL; second run reproduced loss with a passing separate control | One dropped transaction announcement can remain unrecovered on the same healthy connection despite five same-known rebroadcasts and fresh pongs |
| Sender extraction | First guard FAIL; second extraction PASS | The stopped sender's persisted public mempool contained the exact pending signed transaction |
| Receiver clone | Initializer FAIL; strict path guard FAIL; third native diagnostic PASS | Frozen H accepts those exact signed bytes in a fresh offline clone of the receiver's persisted public state |

## Controlled native-v1 loss

Two disposable L Linux ARM GCC nodes used a frame-aware proxy forced to native
v1 transport. A baseline cross-node payment confirmed first. The proxy then
dropped exactly one `MSG_WTX` inventory item whose hash matched the target's
wtxid. Both original native peer IDs remained `[0, 0]`; fresh ping-sent and
pong-received counters increased on each node before and after all five
same-known, byte-identical rebroadcasts. The recipient remained absent through
the original 60-second diagnostic budget; the recorded elapsed observation was
60.00774470786564 seconds with 328 absent queries. Address checkpoints stayed
unchanged after the single target send.

A **new, separate** 60-second positive-control budget then disconnected and
reconnected the exact peer, producing IDs `[1, 1]`. The same target bytes
confirmed. The report recorded 3.6860904169734567 seconds; the preceding trace
observation recorded 3.6859056670218706 seconds. These are separately bracketed
measurements, not conflicting values to overwrite. The proxy exited cleanly;
both disposable containers stopped with PID 0 and retained their volumes.

The original run01 FAIL and its two-event trace remain unchanged, including its
`PROXY_CLOSE_FAILED` cleanup note. The startup repair explicitly sets the Unix
control socket to mode 0600: umask 077 had left that socket at 0700 while the
ownership check required 0600. The installed Python script was already mode 0600.
The archived line-feed baseline passed; **no newline defect is claimed**.
The archived and executed fixture versions and regression receipts are retained.
Forced v1 is a diagnostic limit; this does not reconstruct the public route's
original transport or establish the same packet loss in that live attempt.

## Sender's public persisted transaction

The first wrapper stopped at `create_init` with `AUX_IMMUTABLE_IDENTITY`, before
the decoder/source-file read. Its FAIL and failed owned-stop-proof fields are
retained without relabeling them. The second fresh wrapper passed using a
read-only mount of the exact stopped sender and the byte-pinned pure Python
decoder. The original node and signer were never started.

The selected source file was 3,953 bytes, SHA256
`8d7b058ce175a7cbfd0bd05bb18d3c8e210d6ffe176e442819fa3d668bf93763`.
The decoder found one version2 mempool record and rechecked source identity,
metadata and a second file digest. The selected signed transaction was 3,878
bytes, TXID `f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94`,
raw SHA256 `d9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028`.
That raw payload is external and intentionally excluded from this packet.
Saved timestamps and fee-delta metadata are not current time or actual fee
measurements. Both generic helper containers stopped with PID 0.

## Offline receiver acceptance

Receiver01 failed at the initializer boundary with `BOUNDED_DOCKER_JSON_REQUIRED`.
Receiver02 failed strict copying with `PUBLIC_PATH_FILE`; no native verdict was
obtained. A bounded metadata-only inventory identified exactly regular,
single-link UID1001:GID1000 mode 0600 empty `blocks/.lock`. Frozen H source excerpts
show that this is a process lock recreated by native startup. Receiver03 omitted
only that guarded empty process lock and left the original unchanged. The empty
uppercase LevelDB `LOCK` entries remain in the selected database copy.

The third fresh clone copied 14 public data files totaling 18,173,046 bytes. Only
their hash manifest is included here. The actual qualified H node ran with
networking off, zero peers and an empty mempool. Before and after native
`testmempoolaccept`, it remained at height 408, tip
`54a78dadccd74a664b730f09d436f7272b3fda02081deb9915935b0a5a4ff8be`,
full UTXO hash `5e8dbc2dc2a2a945baf0cd994eaaba8e4f02d6d0701b8b4ac60a9ead44aaac0d`,
and UTXO count 547. The native verdict was `allowed=true` for the exact sender
bytes. This RPC tested acceptance; it did not admit or broadcast the transaction.

The original failed receiver remained stopped and unchanged. The clone stopped
with PID 0, temporary helpers were absent, and all diagnostic volumes and failed
records were retained. Independent kernel metadata bound the real `pqbtcd`
process, distinct from the container-init `sleep` process. The shared parent
limit was two CPUs/four GiB/2,048 PIDs; the native leaf was two CPUs/one GiB/256
PIDs. These are historical observations, not current engine-status claims.

Persisted-state acceptance does not restore the original ephemeral peer,
transport, relay, policy or process state. Combined with the private lost-INV
test, it narrows investigation; it still does not prove the live failure's cause.

## Portable verification and custody

Run using Python's standard library from a physical, nonsymlink POSIX path:

```sh
python3 -I -B /path/to/relay-diagnosis-20261117-01/verify.py
python3 -I -B /path/to/relay-diagnosis-20261117-01/negative-controls.py
```

All 66 selected originals are unchanged local members. `SOURCE.json` records their
provenance and explicit exclusions; `SHA256SUMS` covers every member except
itself. The offline verifier checks selected outcomes, trace joins, byte custody,
transaction identities, source preservation, resource limits and cleanup. It
parses fixture code as AST only and never imports or executes a historical
fixture. The negative controls execute only this verifier on temporary copies.

Receiver03's 13 referenced JSON members are locally closed. Receiver02's 11
referenced JSON members are also closed. Older archived hash manifests and
preparation records retain some references to excluded logs or earlier review
artifacts; those references are external, not locally closed. The metadata
receipt's source-excerpt `sha256` fields identify full frozen-H source files,
not excerpt bytes. `SUMMARY.json` separately records excerpt hashes; the full
source files are external to this selected packet.

No raw datasets, raw signed-transaction payloads, wallet/host state, environment
data, RPC cookies, private keys, ordinary logs, binaries or image archives are
included. Numeric LevelDB WAL paths in the public hash manifests identify
database data; their contents are not included. Independent human review and
production admission are not claimed. Experimental valueless TEST use only;
the production release hold remains unchanged.
