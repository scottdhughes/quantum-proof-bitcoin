# Two-host public test soak

This run uses two existing owned hosts: the local Mac is the bootstrap with
public ingress, and Research is the SSH follower with an outbound TLS bridge.
Transport and network role are independent; the opposite layout is also
supported when its bootstrap owns a usable public ingress. The runner rents no
infrastructure. Only the dedicated
valueless TEST network is supported. Keep the existing offline wallet separate.

Prepare both qualified source versions on each host, publish only the bootstrap
node's loopback P2P port through the declared public TLS ingress, and resolve its
numeric **global** ingress IP independently. RPC, console, and signer IPC stay
local. Private Tailnet connectivity can carry control traffic; it does not count
as the public peer route. The runner completes anonymous certificate-checked TLS
and native TEST version/verack handshakes over the numeric public route before
starting its clock, every ten minutes, and at the end.

Each host needs two source-runtime descriptors and matching native-qualification
PASS reports. Copy the SSH host's public descriptors/reports to the coordinator
for validation. Each receipt must match its image, compiler, native architecture,
source HEAD/tree, node/signer binary hashes, all required native checks, and
completed qualification cleanup. Versions A and B must have distinct source
HEADs, source trees, image IDs, and node binary hashes. An empty source commit or
recreating the same image is insufficient.

Before starting either agent, a read-only, isolated standard-library helper
checks each host checkout's clean HEAD/tree and hashes the agent, controller, and
transport files without importing them. They must match one of the qualified
source images. The helper reads the actual Docker architecture and daemon ID;
emulation and two controls targeting the same daemon are refused. These facts
are bound in the declaration. Live agent identity checks also join source-built
images and binaries to their receipts after both transitions. The runner records
its own clean committed checkout independently.

Save a private configuration outside the checkout with mode 0600. All paths
below are placeholders. The public IP placeholder deliberately fails validation
until replaced with the address of the owned ingress. No real host route or
operator material belongs in a committed configuration.

```json
{
  "schema": "PQBTC-MLDSA44-PUBLIC-SOAK-CONFIG-1",
  "hosts": [
    {
      "name": "local",
      "role": "bootstrap",
      "transport": {"kind": "local"},
      "repo": "/absolute/path/to/clean/agent-checkout",
      "state_dir": "/absolute/path/to/new/local-soak-attempt-state",
      "container": "pqbtc-mldsa-public-soak-attempt-001",
      "p2p_port": 23833,
      "sudo_docker": false,
      "versions": {
        "a": {"descriptor": "/local/receipts/local-a-descriptor.json", "native_receipt": "/local/receipts/local-a-native/report.json", "remote_descriptor": "/local/receipts/local-a-descriptor.json"},
        "b": {"descriptor": "/local/receipts/local-b-descriptor.json", "native_receipt": "/local/receipts/local-b-native/report.json", "remote_descriptor": "/local/receipts/local-b-descriptor.json"}
      }
    },
    {
      "name": "research",
      "role": "follower",
      "transport": {"kind": "ssh", "argv": ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "agent@existing-owned-host.example"]},
      "repo": "/absolute/path/to/clean/agent-checkout",
      "state_dir": "/absolute/path/to/new/research-soak-attempt-state",
      "container": "pqbtc-mldsa-public-soak-attempt-001",
      "p2p_port": 23833,
      "sudo_docker": true,
      "versions": {
        "a": {"descriptor": "/local/receipts/research-a-descriptor.json", "native_receipt": "/local/receipts/research-a-native/report.json", "remote_descriptor": "/remote/receipts/a-descriptor.json"},
        "b": {"descriptor": "/local/receipts/research-b-descriptor.json", "native_receipt": "/local/receipts/research-b-native/report.json", "remote_descriptor": "/remote/receipts/b-descriptor.json"}
      }
    }
  ],
  "public_endpoint": {"hostname": "your-owned-public-ingress.example", "port": 443, "public_ips": ["REPLACE_WITH_NUMERIC_PUBLIC_INGRESS_IP"]},
  "cleanup_public_route": true
}
```

`remote_descriptor` is the path read by that host's agent at startup. The full
qualified candidate descriptor is sent over stdin during upgrade/rollback.
SSH command arguments are quoted as data; no shell interpolation of paths is
needed. Existing noninteractive SSH and Docker access must already work.

Use new dedicated state/container **and volume** names and a new output directory
for every attempt. Both hosts must have absent container and named-volume
namespaces, and neither state directory may already exist, even empty. The
runner checks both hosts before starting either agent. It then atomically
creates each private state directory and its `.public-soak-attempt.json` claim,
rechecking Docker absence at claim time. A collision or failed second claim
starts no agents; any already-created empty attempt directory remains preserved
as a failed attempt and is not reused. The declaration binds the initial absence
proofs and attempt tokens. An older matching public-project deployment is never
claimed merely because its name, image, profile, and port match.

The runner refuses preexisting wallet custody. It generates disposable
test-wallet operator values in memory, transmits them through agent stdin, and
never saves those values. It makes old encrypted backups before subsequent
receive/send issuance. Losing the coordinator cannot be treated as a resumable
passing attempt; the agent's EOF/deadline paths stop its owned services.

First run the complete accelerated public preflight:

```sh
python3 contrib/ml-dsa-qualification/run_public_soak.py \
  --config /absolute/path/to/preflight-config.json \
  --mode preflight --output-dir /absolute/path/to/new-preflight-evidence
```

Preflight lasts 900 actual seconds, uses five-second payment slots, and compresses
the fault schedule. Its only successful label is `PREFLIGHT_PASS`. Reprovision
fresh disposable state and the task's public route for the separate soak:

```sh
python3 contrib/ml-dsa-qualification/run_public_soak.py \
  --config /absolute/path/to/soak-config.json \
  --mode soak --output-dir /absolute/path/to/new-soak-evidence
```

There is no short-duration override. The actual soak needs at least 86,400
monotonic seconds **and** 86,400 UTC seconds after its immutable declaration.
The workload duration starts after the public start event has been fsynced, so
append/fsync latency cannot shorten the independent event-clock span. The
hash-chained log records public start/end boundaries; a claimed elapsed summary
cannot substitute for that span.

The workload alternates one 100,000-satoshi payment each minute with a
5,000-satoshi fee. Before mining, the receiver must report that specific
transaction in its mempool, proving transaction relay separately from block
relay. Both nodes must then confirm it in the mined block and agree on tip,
height, full UTXO hash, and output count within the same 60-second budget.
At least 1,410 of 1,440 normal slots must succeed. At most 30 may be missed, and
only within the actual execution windows of declared fault phases. No unexplained
workload or monitoring gap is accepted. Actual invalid-signature and wrong-network
HELLO controls run every ten minutes.

| Actual elapsed time | Fault phase |
| --- | --- |
| 2 hours | Crash/restart the follower's owned container, unlock, re-peer |
| 4 hours | Disable both peer networks, mine competing branches, hold 60 seconds, rejoin to the longer branch |
| 6 hours | Complete a public handshake, send only an oversized P2P header, observe disconnect, clear owned bans, re-peer |
| 8 hours | Quarantine the bootstrap's current encrypted record, restore its old backup using retained independent public floors |
| 12 hours | Follower reindex-chainstate and full state agreement |
| 16 hours | Sequential compatible upgrade of both hosts to qualified B |
| 18 hours | Sequential binary rollback of both hosts to qualified A on the same persistent volumes |

Each phase needs a new relayed and confirmed cross-host payment inside the same
five-minute recovery bound before its phase result can pass. These additional
proof payments are separate from the normal minute-slot ledger. Wallet identity
and address floors must never go backward, and issued paths/addresses cannot
repeat. The original volume ID is read from the owned public runtime journal
after the agent has ensured the live marker, then bound in the declaration;
every upgrade and rollback must retain that original ID. After the
elapsed run the follower also restores an old backup with its current record
missing, then completes another cross-host confirmed spend.

Samples enforce node peak RSS at most 1 GiB, 32 MB maxmempool and bounded actual
usage, a live bridge on the follower, and Research whole-host CPU below 90% on
the SSH host regardless of its network role. In this layout the bridge listens
on Research's contained `127.0.0.1:23834` and connects through numeric public TLS
to the Mac bootstrap's Funnel, which forwards only to `127.0.0.1:23833`. An unexpected
monitoring gap beyond 90 seconds or clock discontinuity is terminal.

Agents have independent UTC/monotonic shutdown deadlines. EOF closes owned
nodes/bridges. An independent host helper requires this attempt's private claim
and retained `public-runtime.json`, then joins its volume UUID to the actual
named-volume mount and read-only public `identity.json` marker. It also checks
the exact container name, source/profile/manifest labels, qualified image, and
loopback P2P binding before stopping its immutable Docker ID and rechecking it.
An absent/mismatched claim, missing runtime journal with an existing container,
or wrong volume marker prevents any stop. This runs after clean
EOF to stop the idle supervisor too. If an agent stalls, the helper runs before
and after forced agent termination. If the initial stop cannot be proved, the
still-live agent/watchdog is preserved and cleanup is FAIL.

The initial Funnel configuration must actually forward the declared TLS port to
`127.0.0.1:<p2p_port>` with the declared TLS hostname and enabled public access.
The runner binds this handler in the declaration and checks it again during
probes and before cleanup. It uses the documented
[Tailscale ServeConfig fields](https://github.com/tailscale/tailscale/blob/main/ipn/serve.go).
With `cleanup_public_route: true`, only the still-matching task port is disabled;
a changed or shared handler is preserved and cleanup fails. Other handlers are
checked unchanged. No `funnel reset` is used. With `false`, stopped backend/bridge
cleanup is recorded and the owner separately disables the retained route.

Inspect `declaration.json`, `events.jsonl`, `report.json`, and
`evidence-sha256.json`. Failures remain FAIL and trigger owned cleanup; their
elapsed time cannot be added to another attempt. Unit tests, offline runs,
preflight, and platform qualification never become a public 24-hour soak PASS.
Successful soak evidence does not remove production RELEASE_HOLD.
