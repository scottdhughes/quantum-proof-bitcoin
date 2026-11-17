# Candidate L: failed public soak, first full attempt

**The attempt failed. No partial elapsed time is credited to a replacement run.**
The frozen host runner was L `7223772e76d2d0a0bb7fd1d35e0e16fba61918fd`, tree
`33b36275b1da7f7fbc27fae00d519206b0f7c16f`. The two qualified H native images
were still in use when it failed; the declared later H/L upgrade and rollback
phases had not been reached.

The actual public clock started at **2026-11-17 01:51:39.968062 UTC**. The failure
boundary was **05:14:40.050802 UTC**, after **12,180.020856708 monotonic seconds**
and **12,180.082740 wall seconds** (about 3 hours 23 minutes). This is a partial
clock to failure, not a completed 86,400-second clock. The final cleanup event
occurred later and is not used to inflate that elapsed time.

The retained record contains:

- 24,085 chained events, ending in
  `9a862bbab5586acfd6d4dae26cd16b4f46e8f88da9fffb70c087da88261f1724`.
- 205 unique confirmed payments. Each joins an actual send, recipient mempool
  observation, mined block, both nodes' exact transaction/block proofs, and
  matching height, tip, full UTXO hash and UTXO count.
- 202 completed normal slots, all successful, and zero recorded normal misses.
  The next slot did not complete; it is not relabeled as a declared fault miss.
- One completed fault phase, crash/recovery, out of the seven declared phases.
  The remaining phases, full-clock end probe, terminal old-backup recovery and
  final recovered spend were not reached.

The pending Mac-to-Research transaction was
`f52c9e1538c8f9aa619266c06e5389fa194b724a51a769d0b00de54db6adcb94`.
Mac reported its broadcast at 05:13:42.049880 UTC. All 320 completed recipient
queries before failure reported it absent from Research's mempool and
unconfirmed. Five same-known-transaction rebroadcasts reported the same TXID and
raw-transaction SHA256
`d9216ce739ace40ebbc309eada41f54317d7f48ec7d009e95480cc9f1bd8e028`,
with `known_in_mempool=true` and `reissued_payment=false`. No additional receive
or send action appears after that broadcast. This is an event-level issuance
observation; post-broadcast wallet checkpoints were not independently reobserved.

All 100 peer-status responses from initial payment readiness through failure
(two before broadcast, 98 afterward) reported one transaction peer and active
networking. Those counters do not establish fresh pong delivery or receiver
acceptance. The final recipient query was dispatched at 05:14:39.998312 UTC;
the shared original 60-second payment/action budget then expired with
`Owned agent response deadline; ambiguous operations are not retried`.
The roughly 52.49 milliseconds between that logged dispatch and failure are not a
recorded remaining action budget. The exact payment deadline was not logged.
**The live cause remains unknown. Neither an agent stall nor zero peers is
proved by these records.** No later reproducer or forensic result is included.

Recorded owned cleanup passed for both backends and retained their data. A later
independent Research closeout confirmed its registered processes were gone, its
failed backend was stopped with PID 0, both engines were idle, and the aggregate
two-CPU/four-GiB limit remained unchanged. The registered worker CLI exited 0 at
05:14:42.321440 UTC, **2.270638 seconds after the failure**, during cleanup.
Its exit 0 and the container's cleanup exit 137 do not identify the earlier relay
failure cause. The referenced filtered process trace and other raw closeout
receipts are external; this packet does not claim local custody of them.

The six original report/declaration/inventory/driver/review/closeout files are
unchanged. The deterministic gzip expands exactly to the original inventory-bound
event bytes. The closeout's early missing-datadir feasibility note and the
reviewer's then-pending Desktop note remain historical statements; they are not
current task or permission status. Separate preflight results do not change this
FAIL or provide 24-hour credit, and they are outside this selected packet.

Run offline with Python's standard library on a physical, nonsymlink POSIX path:

```sh
python3 -I -B /path/to/public-soak-l-failed-20261117-01/verify.py
python3 -I -B /path/to/public-soak-l-failed-20261117-01/negative-controls.py
```

`SOURCE.json` records original byte custody and the lossless gzip transformation.
`SHA256SUMS` covers every local member except itself. The verifier checks exact
membership, no-follow bounded reads, checksums, all event hashes, native payment
evidence, the failed-payment timeline, declared and observed coverage, and cleanup.
It parses the frozen driver only as AST and checks its fixed bytes; it never
imports, compiles executable code from, or runs that driver. The controls use
temporary copies within this directory and execute only the offline verifier.

No private wallet records, passwords, RPC cookies, environment files, binaries,
image archives, raw transaction payloads, or process logs are included.
Experimental valueless TEST use only. Human review and production admission are
not claimed; the production release hold remains unchanged.
