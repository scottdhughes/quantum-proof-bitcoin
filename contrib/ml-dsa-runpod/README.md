# Runpod public TEST runtime

This launcher runs a valueless public TEST node and wallet on a CPU-only Runpod
pod, paired with the Mac's independently qualified Docker node. Research is not
used. It reuses the existing sealed wallet formats, UID1000 signer, UID1001 node,
public address-floor journal, and the original public-soak payment/timing rules.

Validation status, 2026-11-14: Runpod native startup is blocked. Both qualified
A3 and C daemons received SIGKILL before diagnostic cleanup, without a recorded
cgroup OOM event. The sender and cause are unconfirmed. Installation, real NFS
UID isolation, and private evidence export passed, but no Runpod wallet,
transaction, provider-restart qualification, public preflight, or elapsed soak
completed. These results do not qualify Runpod as a functioning platform yet.

Runpod's outer provider container is the isolation boundary. There is no nested
Docker daemon. Native application-session crashes, native payload upgrades, Mac
Docker image replacements, and actual provider-container restarts are recorded
as distinct events. A native A3↔C transition does not replace the outer image.

## Before deployment

Prepare native x86_64 payloads from the exact A3 and C source revisions. Each
`versions/<a3|c>/` directory contains `descriptor.json` (schema
`PQBTC-RUNPOD-PAYLOAD-1`), the original `manifest.json`, original build descriptor,
the matching full nine-gate native qualification PASS receipt, and `seed/`.
The payload's node/signer/profile/contract hashes must match that receipt.
The new launcher is separately frozen to a committed source HEAD/tree and the
eight control-file hashes listed in `run_public_soak.py`.

The provider adapter supplies a fresh owned CPU-only pod and persistent storage.
Runpod allocation must expose cgroup v1 or v2 CPU, memory, and PID counters.
The launcher maps `/proc/self/cgroup` through `/proc/self/mountinfo` to select
the current process's controller directories, rather than an assumed host root.
Receipts explicitly record the cgroup version and selected paths. CPU quota
and/or the effective cpuset must provide the declared hard CPU bound; memory
must have a finite hard limit. `memory_bytes` is the exact observed byte count
(for example 8,000,000,000 bytes is distinct from 8 GiB).
The declaration binds the actual CPU/memory hard allocation;
PID count and node RSS monitoring are observations, not a claim of the old Docker
`--pids-limit` or read-only-root configuration. Child capabilities/UIDs and owned
process-session cleanup are checked by `native_backend.py`.

Persistent storage must enforce real per-user permissions. The installer first
creates a disposable file as UID1000, verifies owner-only mode, and proves that
UID1001 cannot open it for reading or appending. Synthetic permission listings
alone do not qualify a mount. A rejected storage tier must not be used for live
wallet state, and selecting `HIGH_PERFORMANCE` does not itself establish that
this test passes.
On root-squashed NFS, each role creates its own private directory exclusively;
the fresh initialization parent is sticky only during creation and returns to
0755 before any application starts. The installer also proves that neither
application UID can read or modify the root-owned control journal. Export runs
under the native global lock with all application sessions stopped, reading
each private branch as its owner and restoring root between branches. It
preserves the original ownership/modes and excludes task authentication cookies.

The running node hash comes from its actual `/proc/<pid>/exe`. The hardened
signer deliberately denies post-exec executable inspection, including to the
container's root without ptrace privileges. Its separate receipt binds a
root-verified immutable ELF file descriptor and SHA-256 before execution to the
live owned child through its pidfd, UID, start tick and session. The launcher
does not claim a post-exec signer-image observation, add ptrace capabilities, or
enable dumpability.

Use sibling fresh controller/data directories below the canonical provider
mount, for example `/var/lib/pqbtc/attempt-preflight/control` and
`/var/lib/pqbtc/attempt-preflight/data`. The attempt parent must be root-owned
and executable by both unprivileged users (0755 or 0711); the controller leaf is
0700. Never reuse either directory for the final soak. The existing local
offline wallet and port 8844 are outside this launcher's ownership.
Public configurations require `/opt/pqbtc-runtime` and
`/opt/pqbtc-runpod/versions`; these paths and the `/var/lib/pqbtc` state mount
match the independently locked exporter. Custom backend constructor paths are
reserved for local container rehearsals.

## Configuration and run

The private configuration has schema `PQBTC-RUNPOD-PUBLIC-SOAK-CONFIG-1` and keys
`hosts`, `public_endpoint`, `cleanup_public_route`, and `provider_restart`.
Both hosts use the original public-soak host fields, plus:

- `backend`: `docker` for the local bootstrap, `native` for the SSH follower.
- `control_identity`: committed launcher `source_head`, `source_tree`, and a
  `sha256` map with exactly the eight reviewed control-file names.
- Native `versions.a`/`.b` additionally name local `payload` descriptor files;
  the existing `descriptor` and `native_receipt` fields remain their qualified
  **build provenance**, not the outer provider image.
- The native host's `native` object binds `pod_id`, `namespace` (`pqbtc-runpod-*`),
  `data_root`, `versions_root`, `runtime_root`, actual `cpu_cores`, actual
  `memory_bytes`, and the provider-attested `outer_image`.
- `provider_restart` pins a local Python lifecycle helper as
  `{ "argv": ["/absolute/python3", "/absolute/helper.py", "..."],
  "script_sha256": "..." }`. No operator password is passed to it. It must
  actually restart the owned pod, verify the new generation and persistent
  mount, refresh SSH trust using the authenticated provider's public host key,
  and reinstall/verify the frozen capsule if the provider wiped its rootfs.

SSH is noninteractive, with strict host-key checking, forwarding disabled, and
the provider-attested per-generation public known-hosts file. Explicit private
key/config paths, forwarding, proxies, and remote-command hooks are refused.
The native transport also retains `pod_id`, `generation`, `known_hosts_sha256`,
and `hostkey_source` from the provider adapter. Since sshd may omit
`RUNPOD_POD_ID`, the installer writes a root-owned, read-only public binding at
`/opt/pqbtc-runpod/provider-binding.json`, checked against that transport on
startup and after restart. Receipts call this an API-attested SSH binding and
separately report whether the environment supplied the pod ID. Provider reads
before and after installation must identify the same runtime generation.

```sh
python3 contrib/ml-dsa-runpod/run_public_soak.py \
  --config /absolute/preflight-config.json \
  --output-dir /absolute/new-preflight-evidence --mode preflight
```

Run the same command with a **new configuration, namespaces, and evidence
directory**, using `--mode soak`, after preflight passes. Preflight requires 900
actual seconds; soak requires 86,400 actual seconds on both UTC and monotonic
clocks. Each setup additionally verifies a real provider restart before its
elapsed clock begins: volume UUID, wallet identity, floors, tip and full UTXO
state survive, followed by a new confirmed spend.

The unchanged workload schedules a payment each minute (1,440 slots; at least
1,410 successful), observes receiver mempool relay before mining, and confirms
the specific transaction on both nodes. Seven declared fault phases cover a
native application crash, partition/rejoin, hostile public input, old-backup
recovery with both selected records missing, reindexing, upgrade and rollback.
Each recovery includes a fresh confirmed spend within five minutes. Soak cannot
resume or accumulate elapsed time from an interrupted attempt.

## Shutdown and evidence

The stdio agent independently stops its owned application sessions at its UTC
or monotonic deadline and on EOF. The Mac retains an independently scheduled,
exact-pod provider shutdown controller: stopping application processes does not
stop Runpod billing. Evidence export precedes ordinary pod/storage deletion;
emergency budget shutdown retains bounded control receipts.

The launcher does not rent resources, inspect account balances, or handle
provider API credentials. Only the separately reviewed provider adapter does
provider lifecycle operations. The user-approved total spending envelope is
enforced there. No public RPC, wallet console, signer IPC, or operator material
is exposed. All coins are disposable TEST coins; no production admission is
implied by a passing finite run.

Replacement plans can select `--volume-type HIGH_PERFORMANCE`, but must carry
`--prior-exposure-usd` and the original `--hard-deadline-epoch`. This keeps one
total spending envelope and one absolute deadline across attempts. Export and
close the previous owned resources before creating replacement compute.
