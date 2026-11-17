# Native 1,450-entry recovery capacity diagnostic

The isolated diagnostic passed with **1,450 retained public keys**, 725 on each
address branch. It quarantined the selected current wallet record, retained the
independent public floor journal, recovered the earlier normal backup, issued
receive index 725, and confirmed a new self-payment. Both final address floors
were 726. The owned backend stopped with PID 0 and its container and volume were
retained.

The host controller was frozen source L
`7223772e76d2d0a0bb7fd1d35e0e16fba61918fd`, tree
`33b36275b1da7f7fbc27fae00d519206b0f7c16f`. Native execution used qualified H
`52f26f31e2d8fcf52459f9cb2e9159564395f74a`, tree
`d2e07ad8db149f6d3eac1cb15379d97e1484e2e6`, Linux ARM GCC image
`sha256:87075e6b6c13a805afaa8dcdc72b8e9cb35c78389ed6283949f1cf079b626153`.
This pairing exercises recovery on the planned rollback image. It is not a new
qualification of every L native binary. The helper pinned six host-control
hashes before running; the selected H descriptor independently binds the same
public-controller and public-runtime hashes. Other source files and original
native build/qualification reports are external to this selected packet.

The observed recovery frame was **1,956,099 bytes**:
`2 + 43 + 4 + 1450 × 1349`. The complete instrumented `_start_signer` call took
**0.599333125 seconds**; its checkpoint wait took **0.468505417 seconds**. The
existing operator-input deadline remained five seconds and the checkpoint
deadline remained 45 seconds. **Input transfer time was not measured directly.**
The checkpoint timing and the complete function timing are separate observations;
neither is relabeled as a direct input timing.

The fixture created one public entry through the normal receive API. It then
fsynced 1,449 independent address intents and made 1,449 sequential authenticated
native reservation requests inside one bounded container invocation. It retained
the combined public manifest once, then used the normal lock, quarantine,
old-backup recovery, receive, fund, send, mine, and transaction-proof controls.
The batch reservation/retention phase took 406.908222708 seconds. This compressed
preparation checks the selected recovery capacity; it does not reproduce 1,449
ordinary HTTP receive flows or a complete day of transaction traffic. The batch
never retries an ambiguous native reservation. Public manifest payloads, wallet
records, generated passwords, host state, logs and RPC cookies are not included.

Run the portable offline packet checks using Python's standard library:

```sh
python3 -I -B /path/to/bulk-recovery-20261117-01/verify.py
python3 -I -B /path/to/bulk-recovery-20261117-01/negative-controls.py
```

The raw report, all 23 safe events, original helper, original nine-test fixture,
and H descriptor are unchanged local custody members. `SOURCE.json` records
their provenance; `SHA256SUMS` covers every local member except itself. The
offline verifier checks byte custody, separate host/native identities, exact
event/action order, 1,450 entries and branch floors, frame size, timing-field
joins, old-record quarantine, a new confirmed spend, and stopped/retained cleanup.
Historical helper and test code are parsed only; they are never imported or run
by either packet-check command. The original nine mocked tests and pinned Ruff
were run by the root before native execution; those command outputs are external
to this selected packet, and these offline checks do not claim to rerun them.

No Docker Desktop restart or operating-system reboot was performed here. This
diagnostic contributes **zero public-soak time**, establishes no public relay
failure cause, and claims no human review or production admission. Experimental
valueless TEST use only; the production release hold remains unchanged.
