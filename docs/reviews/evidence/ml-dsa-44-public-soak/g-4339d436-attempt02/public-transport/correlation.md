# Exact Research G02 public transport correlation

Three authorized JSONL files were copied byte-for-byte (2282bytes), with source hashes/metadata in manifest.json and local files0600. No other state file or wallet/cookie/key/backup/environment file was read.

| Public log | Reported bridge PID | Approximate creation from filename/boot mapping* | Final source mtime | TLS connect/disconnect records |
|---|---:|---|---|---:|
| public-transport-83946471535236.jsonl | 55 | 2026-11-16T00:00:36.471535236Z | 2026-11-16T00:00:36.867934766Z | 1/0 |
| public-transport-91174136453043.jsonl | 66 | 2026-11-16T02:01:04.136453043Z | 2026-11-16T16:01:54.096764050Z | 5/5 |
| public-transport-141674854658832.jsonl | 78 | 2026-11-16T16:02:44.854658832Z | 2026-11-16T16:45:21.532326185Z | 1/1 |

*The filename contains a monotonic-ns value. UTC conversion assumes the known naming convention and current boot epoch; it is approximate. No event row contains a UTC/monotonic timestamp. Reported PIDs are log identities, not proven host PIDs.

The latest bridge (reportedPID78, instancec1c712b3e3b04c6f8d56e3c7940af160) records TLS1.3 connection, then one peer_closed disconnect with byte counters128597/151295, and no subsequent connection record. Its final source mtime is2026-11-16T16:45:21.532326185Z, within the requested16:44–16:47 window. This is a last-write correlation; it is not an intrinsic event timestamp. The earlierPID66 instance has five connect/disconnect pairs, all reasonpeer_closed. The initialPID55 file has startup/connection only. Overall there are seven TLS connections and six peer_closed disconnections.

There are no exception-class/error-type fields or timeout error records in these three logs. They do not identify the closing side or TLS control/session-ticket state. Thus the records are consistent with loss of the live relay before the receiver timeout, but cannot independently attribute it to the separately reproduced TLS1.3 blocking-read timeout. Existing rows also cannot assign individualPID66 connection closes to exact UTC times or demonstrate an automatic reconnect loop. The approximate third-instance creation16:02:44.854658832Z is compatible with root's reported16-hour upgrade; the logs do not label that operation.

Independently checked Research backend is stopped/PID0 (finished16:47:00.653939677Z), its scope is not-found/inactive, private engine has zero running containers, parent quota remains200000/100000, and aggregate infrastructure usage was0.000438cores over a one-second metadata sample. No restart, signal or runtime mutation was performed. Preserve all copies and failed-attempt evidence; no new attempt was started.
