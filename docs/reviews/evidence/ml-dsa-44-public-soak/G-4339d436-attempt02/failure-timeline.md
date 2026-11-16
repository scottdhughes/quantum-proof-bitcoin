# G SOAK02 failure timeline

Public evidence result: **FAIL**, at **2026-11-16T16:46:56.470020+00:00**. The failure was `Receiver did not observe actual transaction relay before mining`. The event clock ran 60360.005481 monotonic seconds before failure (about 16 h 46 min); it has no completion boundary and earns no 24-hour qualification credit.

The complete chain and inventory were reverified: **59,862 events**, **1,005 normal outcomes** (1,002 successful, 3 missed), **1,010 confirmed payments**, and **6 completed fault phases**, all PASS. All 28,862 dispatches have matching completed actions. The frozen monitor re-audit reached `monitor_complete`, returned the expected exit 1 for FAIL, and emitted no validation error. There were no pending-action alerts.

## Final payment and deadline

The preceding payment, Mac → Research, was confirmed at 2026-11-16T16:45:02.475097+00:00 ([58883](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58884)), settling in 6.006037 s. Slot 1004 then completed. The next payment was **Research → Mac**, with txid `2a58e6c4ddb43f9d51c1ec37b7fc800f15f522b14855c8f41604c94e29f52448`. Slot 1005 never received a normal outcome.

| Step | Dispatch → completion UTC | Duration | Evidence |
|---|---|---:|---|
| mac `sample` | 2026-11-16T16:45:16.528669+00:00 → 2026-11-16T16:45:16.592997+00:00 | 0.064310 s | [58886](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58887) |
| research `sample` | 2026-11-16T16:45:16.593162+00:00 → 2026-11-16T16:45:16.918215+00:00 | 0.325061 s | [58888](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58889) |
| mac `sample` | 2026-11-16T16:45:47.022146+00:00 → 2026-11-16T16:45:47.086512+00:00 | 0.064363 s | [58890](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58891) |
| research `sample` | 2026-11-16T16:45:47.086678+00:00 → 2026-11-16T16:45:47.406986+00:00 | 0.320317 s | [58892](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58893) |
| mac `receive` | 2026-11-16T16:45:56.468058+00:00 → 2026-11-16T16:45:57.574435+00:00 | 1.106361 s | [58894](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58895) |
| research `send` | 2026-11-16T16:45:57.574642+00:00 → 2026-11-16T16:45:59.906897+00:00 | 2.332248 s | [58896](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58897) |
| Mac first transaction poll | 2026-11-16T16:45:59.907240+00:00 → 2026-11-16T16:45:59.922323+00:00 | 0.015087 s | [58898](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:58899) |
| Mac last transaction poll | 2026-11-16T16:46:56.360154+00:00 → 2026-11-16T16:46:56.366212+00:00 | 0.006045 s | [59858](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:59859) |
| Terminal receiver-relay failure | 2026-11-16T16:46:56.470020+00:00 | — | [59859](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl:59860) |

The Research send returned `broadcast=true` in **2.332248 s**. The frozen driver gives the entire receive/send/relay/mine/agreement/confirmation sequence one shared **60 s** deadline. Exact payment-start and deadline instants are not logged. The first receive dispatch plus 60 s is 2026-11-16T16:46:56.468058+00:00; observed receive-dispatch → failure was **60.001636625 s**. This approximation must not be promoted to an exact logged deadline.

There were **481 completed receiver polls**, all for the expected txid, all `in_mempool=false`, `confirmed=false`, `confirmations=0`, `block_hash=null`. Their combined dispatch-to-completion time was **6.778447467 s**. The 480 intervening gaps totalled **49.680227991 s**; each was approximately the driver’s 0.1 s sleep plus local overhead. The final completion was 0.103812292 s before failure. No `mine` dispatch followed the final send.

## Peer, resource, and image observations

- **mac:** preceding full status 58876 at 2026-11-16T16:45:01.746003+00:00 reported 1 peer; final full status 58894 at 2026-11-16T16:45:57.574435+00:00 reported **0 peers**. Both final nodes remained ready at height 1215 with the same tip and UTXO hash. Latest resource sample 58890 at 2026-11-16T16:45:47.086512+00:00 reported RSS 87,928,832 bytes, peak RSS 91,078,656 bytes, and mempool size 0.
- **research:** preceding full status 58878 at 2026-11-16T16:45:02.400622+00:00 reported 1 peer; final full status 58896 at 2026-11-16T16:45:59.906897+00:00 reported **0 peers**. Both final nodes remained ready at height 1215 with the same tip and UTXO hash. Latest resource sample 58892 at 2026-11-16T16:45:47.406986+00:00 reported RSS 88,006,656 bytes, peak RSS 90,624,000 bytes, and mempool size 0.

The last Research sample also reported `bridge_alive=true` and whole-host CPU 0.0%. These samples preceded the failed send; the payment loop recorded no new full-status, peer, bridge, or resource sample during its deadline. The two final zero-peer statuses are the only post-upgrade full-status observations with zero peers. They bracket an observed connectivity/state failure but do not explain its cause.

The upgrade phase completed PASS at 2026-11-16T16:02:58.300216+00:00, 2638.154072 s before the terminal failure. Both hosts had reported version-b images/source `4339d436cdcfce9724476b9786994d347f1a4b06`; both upgrade receipts retained their original volume identity. Rollback had not completed.

| Host | Upgrade completion | Image after upgrade |
|---|---|---|
| mac | 2026-11-16T16:01:47.522091+00:00 | `sha256:3c042b6e21c94368ecf58ab2cb793bf5f40a546736e77d82e42d7d6e4197d02e` |
| research | 2026-11-16T16:02:42.116225+00:00 | `sha256:89e3d98fa388a8fa4841174dc490feab836036f9352f8065b7a461b8d05f9eb8` |

## Earlier mempool positives

- mac last returned `in_mempool=true` at **2026-11-16T16:44:01.340926+00:00**, event 58832, for `0d6146a3b69b0f4dfa6618a42ce7cb5a5eeccbd6797f623922908023caa67464`. Across the attempt it returned 506 positive per-transaction responses.
- research last returned `in_mempool=true` at **2026-11-16T16:45:01.044330+00:00**, event 58872, for `8b3333ccf77ec11bba04f9d99b9947cf9df20af4ec38d3cecfd5b2b13a0dfe50`. Across the attempt it returned 504 positive per-transaction responses.

Mac’s positive at 16:44:01 was in the same Research → Mac direction as the failure. Research’s positive at 16:45:01 belonged to the immediately preceding successful payment. There is **no positive observation for the failed txid**. Every periodic `sample.mempool_size` observation was zero; those coarser observations do not exclude between-sample mempool membership and must not erase the explicit positive transaction responses.

## First-hour versus final-hour observer latency

Latency is coordinator monotonic dispatch → action completion, including host/control transport, parsing, and logging overhead; it is not isolated native CPU time. Quantiles use nearest rank. The final observed hour is failure-minus-3600 s through failure and includes the upgrade phase. All-query rows include confirmation lookups.

| Window / host | Queries | Median | p95 | p99 | Maximum |
|---|---:|---:|---:|---:|---:|
| first_clock_hour / mac | 1064 | 16.065 ms | 40.857 ms | 44.984 ms | 63.986 ms |
| first_clock_hour / research | 877 | 72.002 ms | 138.241 ms | 161.189 ms | 526.532 ms |
| last_observed_hour / mac | 1141 | 14.526 ms | 271.106 ms | 308.467 ms | 2495.631 ms |
| last_observed_hour / research | 544 | 60.640 ms | 421.370 ms | 434.124 ms | 485.815 ms |
| Final failed Mac relay loop | 481 | 14.653 ms | 15.647 ms | 16.115 ms | 19.297 ms |

The bounded observer change worked in the specific cost sense tested here: wallet address counts grew from 3 to 1,012, while the failed loop returned the same five-field, **148-byte** result 481 times, each below 20 ms. First/final-hour medians stayed in the same range. Higher final-hour tail latency remains visible and the final-hour window is confounded by upgrade/transport effects. These observations do not certify lookup semantics, prove an asymptotic complexity bound, or rule out a false-negative native/observer defect. They do show that this failure was not a history-sized status response consuming the shared deadline.

## Causal limits and verification receipts

The evidence establishes a pre-mining receiver-membership deadline failure after successful broadcast acknowledgement at the sender API. It does not establish why peers became zero, whether bytes crossed the transport, whether a native scheduler reconnected, or whether an observer/native-state defect returned a false negative. `broadcast=true` alone does not prove receiver receipt. No attribution to randomness is supported. This G failure must remain separate from the earlier F mine-response deadline: G dispatched no mine for its final transaction.

Cleanup is **reported successful**: both owned-host stop proofs say STOPPED, both agents exited 0 with zero stderr, state directories were preserved, and route configuration was retained after backend/bridge stop. No runtime or Docker action was performed for this analysis.

| Public input | SHA256 |
|---|---|
| [events.jsonl](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/events.jsonl) | `ffaf5ea2f33f9c3f774c1c88740da262f0577c4334b4a90e9072958d10d07ed6` |
| [report.json](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/report.json) | `d6e5e77793f5fdadd709c29d38182dd8c02c0e69f314b525978bc9e04f150416` |
| [declaration.json](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/declaration.json) | `282a3e423804e591cf123d4047279bd0e0c5117c837d97746cd2fa3352bea680` |
| [evidence-sha256.json](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak-20261115-02-output/evidence-sha256.json) | `2a55fe8d51dfa4470df76e7fdd065fea7fd63cd2c63db66643ec3c9edc2da46d` |

Chain terminal hash: `7bec39aeac9065dfe9fae515a4d79291d518a62fd87f090690aa32a1b0ccc9bf`. Frozen monitor helper: `845941335a52365d99aacf28aab0147435f3376b2da239ad9f1412a236abe1d2`. Source clone was clean at `4339d436cdcfce9724476b9786994d347f1a4b06`, tree `b9923bede37da41119ac69a39d57f16a8a89b3eb`; its driver hash matched declaration and report. The [machine-readable timeline](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/research/g-soak02-failure-timeline.json) contains all 481 final polls, action pairs, safe status/resource summaries, quantile definitions, input hashes, and the independent chain/count assertions.

Source contracts: [payment()](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/candidate-g/source-clean-4339d436/contrib/ml-dsa-qualification/run_public_soak.py:996), [action dispatch/recording](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/candidate-g/source-clean-4339d436/contrib/ml-dsa-qualification/run_public_soak.py:912), [workload scheduling](/Users/scott/quantum-proof-bitcoin-evidence/20261114-runpod-public-soak/candidate-g/source-clean-4339d436/contrib/ml-dsa-qualification/run_public_soak.py:1160). Analysis read only the public events/report/declaration/inventory, the frozen monitoring helper/driver, and Git source identity. No wallet, key, backup, or private file was opened.
