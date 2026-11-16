# K controlled source supersession

The original public TEST run remains **FAIL / KeyboardInterrupt**, with owned
cleanup confirmed. The recorded operator stopped exact coordinator PID10537
to fix a separate P2 one-click launcher issue: a surviving HTTP server could
bypass Docker Desktop readiness after Desktop stopped or was restarting.
This is controlled source supersession; no earlier network/workload failure
was observed in the preserved event history. The reason is not substituted
into the original report.

The partial run records 16,164 chained events, 143 successful normal slots,
zero missed slots, 146 unique confirmed payments and one completed crash
recovery. Its partial clock is about 2h23m; the declared 86,400-second clock
never completed. There is **zero 24-hour soak credit**, no final post-clock
recovery-spend result and no production admission.

Run using Python3 standard library from any directory:

    python3 -I -B /path/to/packet/verify.py

The verifier checks exact flat membership/no symlinks, byte checksums, original
report/declaration/inventory and lossless deterministic event gzip, all event
hashes/sequences, partial clocks, stop-before-interrupt ordering, partial
workload/crash recovery and both owned backend cleanup proofs. It neither
executes native programs nor contacts a host/network. Original machine paths
in provenance and receipts are historical references, never fetch instructions.
No wallet/key/backup/cookie/operator/credential files or deployment config are
included. Public TEST protocol keys/transaction identifiers remain unchanged
in the original public event chain. Scope: selected record verification only.

The fixed source needs fresh native qualification, a separate 900-second
preflight and a new complete 86,400-second soak starting at zero. This capsule
does not claim those future results. The separate successful K preflight and
H/K native qualification records retain their own original scopes.
