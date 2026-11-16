# G 4339d436 failed public-soak attempt 02

This selected public packet records **FAIL**, not a completed 24-hour qualification. The receiver did not observe the final Research-to-Mac transaction in its mempool before the shared 60-second payment deadline. No mine was dispatched for that transaction. The clock has a start boundary only. Partial elapsed time earns **zero credit** and cannot be resumed or combined with F or the 900-second G preflight.

The packet contains 59,862 verified chained events, 1,010 confirmed payments, 1,002 successful normal slots, three fault-attributed missed slots, and six completed PASS phases. Rollback and the final 24-hour recovery gate were not reached. Both owned-backend stop proofs report STOPPED, with successful owned-agent cleanup. These are preserved reported proofs; this packet performs no native or network execution and establishes no production admission or independent human cryptographic review.

## Portable read-only verification

From this directory, using Python 3 and its standard library:

```sh
python3 -B verify.py
```

Expected result is `VERIFIED_FAILED_ATTEMPT`, with `report_result=FAIL`, `events=59862`, `confirmed_payments=1010`, `normal_successes=1002`, `fault_misses=3`, `completed_phases=6`, and `elapsed_seconds_credited=0`. The verifier validates every packet checksum, original inventory resolution, full canonical event chain, source/scope bindings, counts, incomplete clock, and reported cleanup. It does not run a node, access a network, or write files.

An additional shell checksum check is optional:

```sh
shasum -a 256 -c SHA256SUMS
```

On systems with GNU coreutils, `sha256sum -c SHA256SUMS` is equivalent. The SHA256SUMS file hashes SOURCE.json and every payload member; SHA256SUMS itself is the external sealing root returned to the integrator. SOURCE.json lists payload sizes/hashes and original-to-copy provenance. Self-referential manifest hashes are deliberately not claimed.

## Original byte resolution

- report.json, declaration.json, and evidence-sha256.json are unchanged copies of the sealed public originals.
- events.jsonl.gz is deterministic gzip (level 9, mtime 0, empty filename). Decompress in memory before checking the original `events.jsonl` digest in evidence-sha256.json. No raw event file needs to be written.
- failure-timeline.json and failure-timeline.md are unchanged derived analyses. Their absolute custody/source links are historical references, not dependencies of verify.py. Resolve original event references to the decompressed events in this packet; sequence N is line N+1.
- public-transport/ contains exactly three authorized public JSONLs, their exact-copy manifest, and the unchanged correlation report. It contains no other state files or unrelated process dump.

The transport logs contain seven TLS connection records and six `peer_closed` disconnections. They have **no per-event timestamps** or exception-class fields. The latest file's final mtime is a last-write correlation, not the disconnect event's timestamp. The correlation report preserves its own inference limits and does not prove a TLS root cause for this connection. Reported bridge PIDs are log identities, not proven host PID namespaces.

SOURCE.json pins G head 4339d436cdcfce9724476b9786994d347f1a4b06, tree b9923bede37da41119ac69a39d57f16a8a89b3eb, and driver SHA256 62a2a8af09ead25ff8a0d1cf379dd60bf5b70643611e8c1c0f2a86199bdce616. Runtime versions in the declaration distinguish the F baseline images from the G upgrade images. The original F failed packet and G frozen source were left unchanged.
