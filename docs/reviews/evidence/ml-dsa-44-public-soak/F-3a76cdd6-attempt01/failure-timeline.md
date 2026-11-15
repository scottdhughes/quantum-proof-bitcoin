# Sealed soak 01: final-payment timing analysis

This is derived read-only analysis of the sealed F public event log and source. The run remains **FAIL**. No partial elapsed time is credited to another soak. All original events, reports and runtime state are preserved.

The original hash chain verifies: 48577 events, final hash `c66e889ffd84e1a49fa110470b5e9223f432bd4def4ebb2beed6da105d712093`. There are 1260 recorded normal slots (1255 successful and 5 fault-attributed misses), seven completed fault phases, and successful cleanup. There is no completed public-clock boundary.

| Final operation | Dispatch UTC | Response UTC | Duration |
| --- | --- | --- | ---: |
| research receive | 2026-11-15T22:13:20.789045+00:00 | 2026-11-15T22:13:23.004014+00:00 | 2.214962 s |
| mac send | 2026-11-15T22:13:23.004320+00:00 | 2026-11-15T22:13:25.188141+00:00 | 2.183823 s |
| research transaction | 2026-11-15T22:14:17.019239+00:00 | 2026-11-15T22:14:18.730128+00:00 | 1.710880 s |
| research transaction | 2026-11-15T22:14:18.835577+00:00 | 2026-11-15T22:14:20.457543+00:00 | 1.621949 s |
| Mac mine (unanswered) | 2026-11-15T22:14:20.458111+00:00 | failure 2026-11-15T22:14:20.798198+00:00 | 0.340082 s waiting |

There were 32 transaction probes: 31 negative, then one positive. Receive took 2.214962 s and send took 2.183823 s. The final true reply arrived 55.269264 s after send returned. The mine dispatch had at most 0.331092 s left under the sixty-second budget; payment began before the first receive-dispatch event. The actual mine-to-failure wait was 0.340082 s.

## Proven observations and source behavior

- The sealed F report is FAIL with successful owned cleanup; the complete original event chain verifies. There is no public_clock_completed event.
- Final target transaction was broadcast by Mac, then 31 negative membership replies were followed by one positive Research reply. The subsequent mine request did not return before the shared sixty-second payment deadline.
- Penultimate negative membership response includes pending_sats=100000 and one additional owned UTXO in its later full status. That shows an owned pending coin before the final positive membership acknowledgment; compact status omits its txid.
- PublicController.action(transaction) issues a transaction request and then a separate full status request. Each successful runtime response carries the full public manifest, and each controller request merges/validates/deep-copies it and fsyncs the retained journal, even when unchanged.
- Full status scans all owned scripts with scantxoutset, then performs one gettxout per candidate and renders all addresses. Research had 1266 addresses and 1136 UTXOs before the final incoming payment. The agent compacts status only after this work.
- Measured transaction RPC latency grows over the run: Research median 0.2513 seconds in hour one to 1.6059 seconds in the last observed hour; Mac 0.2192 to 1.0591 seconds.
- Native inventory scheduling queues transactions, then uses exponential inter-announcement intervals (inbound mean five seconds, outbound mean two seconds). The scheduler contains no policy delay cap below sixty seconds. PublicNode adds no NoBan whitelist option.
- The selected runtime/node source paths are byte-identical between qualified D and F; the inspected ten paths are byte-identical between F and documentation commit62fed742.

## Hypotheses and evidence limits

- A long native randomized inventory interval is consistent with the long Mac-to-Research wait, but event logs do not timestamp INV/GETDATA/TX or expose scheduler draws. It is not established as the unique cause.
- A public TLS transport stall or receiver scheduling delay cannot be distinguished from inventory delay with the available coordinator receipts. Peer count one and bridge liveness do not prove continuous packet progress.
- Manifest serialization/retention and full UTXO observation are proven growing work and plausible contributors to measured latency, but no substep profiles allocate their individual costs.
- The penultimate pending coin is strongly correlated with the target payment but is not direct txid-specific receipt evidence because compact status omits individual UTXO ids.
- The timed-out mine call is ambiguous; this log does not prove whether it mined a block. It must not be retried or credited.

## Next engineering checks

- Preserve the sixty-second settlement gate, all seven fault requirements and the failed original run. Do not accumulate its partial elapsed time into a replacement soak.
- Add a read-only transaction-observation path whose response does not reconstruct full wallet balances/UTXOs or serialize/retain an unchanged manifest. Keep authoritative floor/journal durability on mutation and recovery paths.
- Exercise a disposable public fixture with at least the observed 1266 addresses and 1136 UTXOs, measuring observation, send and confirmation costs separately before a replacement preflight.
- Add public-safe per-stage native relay timestamps or an equivalent diagnostic before attributing the long tail. Any relay-policy change requires its own scoped review/tests and fresh exact-source qualification.

## Source references in frozen F

- `contrib/ml-dsa-qualification/run_public_soak.py:996-1022`: shared settlement deadline and mining after actual recipient-membership acknowledgment.
- `contrib/ml-dsa-console/public_controller.py:365-382,406-421,650-655,729-735`: manifest retention and appended full status.
- `contrib/ml-dsa-console/runtime.py:505-510`: inherited full-manifest response envelope.
- `contrib/ml-dsa-console/public_runtime.py:131-177,295-312`: full balance/UTXO/address construction and membership query.
- `contrib/ml-dsa-signer/node_wallet.py:76-94,394-406`: manifest validation and full-script UTXO scan.
- `contrib/ml-dsa-qualification/public_soak_agent.py:228-238`: compaction occurs after full status.
- `src/net_processing.cpp:161-167,1145-1154,2129-2140,5708-5717`: native relay queue and exponential scheduling.
- `src/random.h:355-369` and `src/random.cpp:704-716`: exponential sampler contract and implementation.

JSON receipt: `soak01-failure-timeline.json`, SHA256 `2d5b07af354902c5078d400e3fb3fccf0f15c3d318ce042cc5078b8ce4243318`. No wallet/private records, credentials, node processes or Research runtime were accessed. No source files were changed.
