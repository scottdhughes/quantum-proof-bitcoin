# Local console validation — 2026-11-09

This records the first console checkpoint. The later
[durable runtime validation](DURABLE_RUNTIME_VALIDATION.md) supersedes its
ephemeral-runtime limitation and records actual Docker restart/recreation.

The local console is implemented and tested against the real two-node ML-DSA
fixture. At this checkpoint console changes were uncommitted in the isolated
`mldsa-local-console/quantum-proof-bitcoin` worktree, based on
`9f4b20a938e67ef985df0780fb41b6035abef15e`. The native integration source remains
clean at that exact revision. This is experimental, valueless regtest evidence.

## Result

- **73 tests passed** across the console runtime, controller, HTTP boundary,
  and existing protocol test modules.
- All seven new Python files passed the repository's selected 38 Ruff rules,
  using cached Ruff 0.17.1. Python compilation, JavaScript syntax, shell syntax,
  and `git diff --check` passed.
- The final real HTTP flow passed all **19 actions**, including its last stop.
  There were zero `pqbtcd` or `pilot-signer` processes left in the container
  immediately after that stop.
- Browser controls were exercised for start, receive/copy, test funding, send,
  mining, backup, recovery confirmation, lock/unlock, and stop. Desktop
  1440×1100 and mobile 320×900 layouts were visually inspected. The final page
  load had zero browser console errors.

## Real recovery/spend evidence

The flow funded 2,000,000 sats, made a backup, issued another address, spent,
mined, stopped/restarted, restored the earlier backup, issued another address,
spent again, and mined. It also checked locked signing, invalid destination,
and insufficient funds rejection.

The restored address index was **2**, greater than the post-backup issued
index **1**. Both actual spends returned transaction IDs:

```text
before restore: 9c00c34d4562bcaa8622ecb9bcc0743551088707f87faf6e1b205f7fab6bf13b
after restore:  590b6d48668f3a478f8a8e10a0dcdcf9a5df20e4ce2edce2cce468583ac956bd
```

After both 1,000-sat fees, the wallet held **1,998,000 confirmed spendable sats**.
Both nodes were at block **104**, with **107 UTXOs**, and agreed on:

```text
tip:  6933c1c113c13e46bbbf918391f4184008d8bba1da577c70cd8e8a1736fa9efd
UTXO: f56a574046fd88f48b229f42bbb9d82eed40975f000a373db8f252d5af970f21
```

Public evidence is saved outside the repository:

- `/Users/scott/quantum-proof-bitcoin-evidence/20261109-console-qualified-flow.json`
- `/Users/scott/quantum-proof-bitcoin-evidence/20261109-console-ready-desktop.png`
- `/Users/scott/quantum-proof-bitcoin-evidence/20261109-console-ready-mobile.png`
- `/Users/scott/quantum-proof-bitcoin-evidence/20261109-console-code-sha256.json`

The screenshots show the default demonstration wallet, which was separately
tested and reopened for use. The qualified-flow JSON records its own fresh
disposable wallet and includes successful teardown.

## Verification commands

```sh
python3 -m unittest ci.test.test_ml_dsa_console_runtime \
  ci.test.test_ml_dsa_console_controller ci.test.test_ml_dsa_console_http \
  ci.test.test_ml_dsa_protocol_v1
node --check contrib/ml-dsa-console/web/app.js
sh -n contrib/ml-dsa-console/launch.command
git diff --check
./contrib/ml-dsa-console/launch.command --no-browser \
  --state-dir /Users/scott/quantum-proof-bitcoin-evidence/20261109-console-qualified
python3 contrib/ml-dsa-console/test_end_to_end.py \
  --output /Users/scott/quantum-proof-bitcoin-evidence/20261109-console-qualified-flow.json
```

Ruff used the exact selected rule list extracted from `lint_py_lint()` in
`test/lint/test_runner/src/main.rs`, applied only to the seven new Python files.
No native prototype binary ran on macOS. The controller required the prepared
offline Linux container's isolation settings, exact source head, and all three
previously qualified native binary hashes before starting native processes.

Review found and corrected a browser lock/readiness trap, stale JSON-line
responses after a timeout, partial-startup cleanup, foreign-port ownership,
abnormal node shutdown reporting, and replay of expired HTTP request IDs.
These checks are engineering review, not independent human cryptographic review.

## Remaining limits

The default console has been left running at `http://127.0.0.1:8844`, using
`~/quantum-proof-bitcoin-evidence/local-console`. See the console README for
the launcher and full walkthrough. Stop the network with its button or stop
the console with Ctrl+C in its terminal.

The launcher requires the prepared container and its tmpfs native build. It
does not provision a replacement runtime after container loss. Host backup
bundles persist, but recovery still needs the exact native runtime. Preserve
the whole host state directory to retain later address floors. The test phrase
is public, so these backups are only for disposable fixtures.

Production platform qualification, human cryptographic review, and public soak
remain outstanding. No commit, push, merge, publication, or reviewer contact
was performed. The next practical step is to use the local console, then make
native runtime provisioning durable before broader testing.
