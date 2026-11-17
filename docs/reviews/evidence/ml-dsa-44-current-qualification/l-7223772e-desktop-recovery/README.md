# Candidate L: actual Docker Desktop recovery

The second fresh run passed the complete Docker Desktop recovery flow on source
`7223772e76d2d0a0bb7fd1d35e0e16fba61918fd`, tree
`33b36275b1da7f7fbc27fae00d519206b0f7c16f`. It used the qualified native Linux
ARM GCC image `sha256:fc470f630a0eaa679aa49563d13b1a1e1d183528eb4348877c7cbb60b3c0e6f3`.

The six recorded stages are:

1. Fund a disposable TEST wallet, confirm its first spend, and pause networking.
2. Actually restart Docker Desktop and reopen the existing host app.
3. Stop Desktop while the existing HTTP app stays alive.
4. Launch once to start Desktop and reuse the app, wallet, backups, and chain.
5. Stop Desktop and the host app, then launch a new host-app process once.
6. Recover the older backup, advance both address counters, and confirm a new spend.

The original wallet's identity, counters, backups, volume, and confirmed chain
state matched before and after the test. The disposable backend stopped with
PID 0, its volume was retained, and the disposable host app exited cleanly after
an intentional SIGINT. This was a real Docker Desktop restart and cold-app test.
**The operating system was not rebooted.** It contributes zero public-soak time.
The historical top-level `original_app_pid` label actually contains the newly
started disposable app PID. The verifier uses explicit `original_before` and
`original_after` records for original-wallet custody, and the cold-app event's
`old_app_pid`/`new_app_pid` pair for process replacement; it ignores that label.

The first run's original FAIL report is retained. It completed the first five
recorded stages, then returned a sanitized `ValueError`. The static driver diff
and recorded 24-test review identify a redundant unlock immediately after
successful recovery: recovery already returns an unlocked wallet. The corrected
external driver checks that postcondition instead. Its only other changes select
a fresh container and two fresh ports. The 14 non-main functions are unchanged.
The verifier proves that exact byte transformation and parses the historical
drivers without importing them, generating executable code, or executing them. The first report itself
does not contain the rejected HTTP response body or a more specific inner error.

The owner authorized stopping the eleven November-15 Musashi containers and
performing this scoped test. The authorization and launch records are unchanged.
`authorization/musashi-stop-public-projection.json` contains selected public
fields from the separate stop receipt: the eleven IDs, before/after running
states, PID 0, and retention results. Its original SHA256 is recorded. Unrelated
project bind paths, mounts, names, image inventories and volume inventories are
excluded. **That projection is derived; the full stop receipt is not a local
packet member.** The owner/order record's earlier pending state remains unchanged
as historical evidence; the two later launch records and final report close it.

Run the offline checks from any location, using Python's standard library:

```sh
python3 -I -B /path/to/desktop-recovery-20261117-01/verify.py
python3 -I -B /path/to/desktop-recovery-20261117-01/negative-controls.py
```

`SHA256SUMS` covers all local members except itself; `SOURCE.json` records byte
custody and derivations. The verifier checks the exact file set, regular files,
size bounds, checksums, source/image bindings, six ordered stages, transaction
confirmation, wallet/counter/backup continuity, cleanup, and explicit exclusions.
The negative controls use temporary copies inside this directory and restore it
on exit. They never launch Docker or a historical driver.

This selected packet does not reproduce the original native builds, independently
attest hardware events, establish a complete 24-hour public run, prove the cause
of any public-soak failure, or claim human review or production admission.
Experimental valueless TEST use only; the production release hold is unchanged.
