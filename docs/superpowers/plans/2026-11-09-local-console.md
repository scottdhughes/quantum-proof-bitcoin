# Local ML-DSA console implementation

The user authorized building status, receive, send and recovery controls and
testing the whole flow. Use the existing CONTRACT-1 implementation and native
binaries at `9f4b20a938e67ef985df0780fb41b6035abef15e`; no new signature or
consensus design. Work in this isolated managed worktree, preserving main.

## Product and architecture

A one-command Python launcher serves a browser console on 127.0.0.1. A host
controller orchestrates the prepared offline Docker runtime. One serial Python
worker as UID1001 owns two real node children and public wallet operations;
the existing native signer runs separately as UID1000, with its operator
password/checkpoint descriptors. No native prototype executes on the host.
The only password is the clearly public disposable-fixture phrase. No real
wallet/password import, production activation or public listeners.

Commands: start, stop, status, receive, fund (test coins), send, mine, backup,
recover, lock and unlock. Send takes integer satoshis, selects mature confirmed
unspent owned inputs, signs using NodeWallet.sign, and broadcasts normally.
Mining is explicit. The UI displays pending and confirmed balances distinctly.

Backups combine quiesced167-byte encrypted record, validated public manifest,
public counter checkpoint, spec/network/source identity and raw public blocks.
Use atomic0600 host bundles, bounded reads and SHA256 identity checks. Recovery
uses a new signer directory, imports public metadata before status, applies
maximum retained floors for the same wallet and scans the real chain. Stop and
restart preserve node/public state while the container lives. Container/tmpfs
loss is reported explicitly; no claim that a wallet-only backup recreates coins.
Do not overwrite old state or delete uncertain temporary files automatically.

## Files and ownership

- Runtime worker: `contrib/ml-dsa-console/runtime.py`, runtime unit tests.
- Host controller: `contrib/ml-dsa-console/controller.py`, controller unit tests.
- UI: `contrib/ml-dsa-console/web/{index.html,app.js,style.css}`.
- Root: `contrib/ml-dsa-console/app.py`, HTTP tests, end-to-end driver and docs.

## Interfaces

Runtime CLI: `python3 runtime.py --source PATH --build PATH --state PATH
--socket PATH --signer-uid 1000`. New/existing state is UID1001-owned0700.
Read one JSON object per stdin line: `{action,params}`; emit exactly one JSON
response `{ok:true,result:VALUE,manifest:PUBLIC_OR_NULL}` or
`{ok:false,error:MESSAGE}`. Keep logs on stderr/files, never stdout. Actions:
`start`, `stop`, `status`, `receive`, `fund`, `send`, `mine`, `manifest`,
`import_manifest`, `export_chain`, `import_chain`, `lock`. Stop closes/reaps
node children; EOF also cleans up. Status without signer reports chain state.
Receive/sign/fund require the actual active deployment and existing APIs.
`import_manifest` takes `params.manifest` before any wallet status on fresh store.
`fund` takes amount_sats(default2000000), optionally address; `send` takes
address,amount_sats,fee_sats(default1000). Mine takes blocks(default1,max101).
`export_chain` returns `{genesis,tip,blocks:[RAW_HEX...]}`, bounded5000blocks/32MiB;
`import_chain` validates identity/prefix and replays missing blocks on both nodes.

Controller class `Controller(container,source,build,state_dir,code_dir)` has
`status()` and `action(name,params={})`. A successful action returns
`{status:STATUS,result:VALUE}`. Methods raise ConsoleError on failure.
Controller serializes all actions, validates prepared container restrictions,
stages runtime.py outside the clean native source checkout, supervises actual
guest processes, snapshots public metadata and owns encrypted backup I/O.
`close()` stops processes. It preserves public session metadata for relaunch.

STATUS: `{phase,ready,nodes,wallet,backups,activity}`. phase is stopped/running/error.
Each node: `{name,height,peers,tip}`. Wallet: `{wallet_id,locked,balance_sats,
spendable_sats,utxos,next_receive,next_change,addresses}`. Each address has
address,index,branch. Backups: `{id,created_at,height,wallet_id}`. Activity:
`{time,kind,message,txid?}`. No seeds/passwords/private keys in responses.

Browser API: GET `/api/status` -> `{ok:true,data:STATUS}`. POST `/api/action`
with `{action,params,request_id}` -> `{ok:true,data:{status,result}}`.
Errors: `{ok:false,error:MESSAGE}` with4xx/5xx. Serve same-origin local static
assets only, no dependencies/CDNs; bind127.0.0.1 and require exact Host/Origin,
JSON bounded body and per-launch CSRF header on mutations. No arbitrary paths,
commands, RPC methods or passwords in API. Prevent overlapping/duplicate sends.

## Visual direction

Cool paper #f3f6fa, ink #182c43, slate #526981, blue #245dc7, pale blue #e6eefb,
green #226b55 for verified running state. Avenir Next/Trebuchet body, Optima
headings, readable system fallback. Left wallet overview and receive/send
workspace; right node status and activity; backup/recovery drawer. Mobile stacks
in task order. Sentence-case labels, keyboard focus, clear busy/error states,
explicit 'test coins' units; no network jargon in ordinary send/receive flows.

## Test sequence

1. Baseline public-wallet tests in contained Linux.
2. RED/GREEN runtime tests for exact amounts, input selection, mempool-spent
   exclusion, balance, invalid addresses, change, actual broadcast and restore
   ordering; controller tests for backup integrity and process/state failures.
3. HTTP tests for routing, origin/token/body/input validation and duplicate IDs.
4. Use the real console to start two nodes, receive/fund/mine/send/mine, snapshot,
   issue another address, stop/restart, restore older ciphertext with retained
   floors, and send again. Compare actual node tips/UTXOs and mutation rejection.
5. Browser exercise of all controls and responsive layout; independent code
   review, fix required findings, narrow tests/lint and evidence report.

No commits/push/merge. Keep original native source/binary identity distinct from
new operator files. Preserve test failures and synthetic state. Leave a usable
local console running if the full flow passes, with documented stop command.
