# Native ML-DSA qualification and public test soak

Owner request: finish native qualification, run a public soak with test coins,
fix failures, and test the assembled system. On 2026-11-10 the owner selected
Research plus this Mac, no new paid hosting, and 24 hours of actual elapsed soak.
This design implements the existing completion roadmap and owner continuation.
It does not activate a real-value network or manufacture human review.

## Scope and invariant

Keep default main/test/testnet4/signet/regtest behavior and the existing
`-regtest -mldsa44demo` fixture intact. Add explicit command-line-only
`-chain=test -mldsa44test`, requiring the experimental build, with its own
`mldsa44-test-v1` data directory. It uses the already-frozen CONTRACT-1 TEST
binding from GENESIS-v1: magic a7e29cf7, genesis
2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979,
HRP tq and ports 23833/23832. It has no inherited Bitcoin discovery seeds,
assumeutxo snapshots or assumevalid signature bypass. Existing contract, wallet,
IPC and regtest-manifest bytes stay sealed. No new PQSIG ALG_ID is allocated.

H=1 uses the exact genesis as H-1 and a genuinely empty pre-H UTXO inventory.
Every spendable output from H1 onward, including coinbase payouts, must be native
v2/32. Only zero-valued canonical OP_RETURN with one push of at most 80 bytes is
also allowed. Every non-coinbase prevout must be native v2/32 and scriptSig empty.
This excludes classical, rc2, nested and unknown-witness fallback on this profile.
Check outputs and inputs in mempool and ConnectBlock, including reindex paths.
The unspendable frozen genesis transaction is the sole inherited special case.

Bootstrap H1 to a fixed unowned v2/32 activation program, then permit wallet
issuance and mine directly to signer-derived tq addresses, respecting maturity.
Do not enable wallet issuance before H1 or use OP_TRUE funding in public mode.

## Verification accounting and qualification

Builder decision: one native ML-DSA input costs 625 signature-operation units
when SCRIPT_VERIFY_MLDSA44 is enabled. The inherited 80,000 block and 16,000
standard-transaction ceilings give 128 checks/block and 25/standard transaction.
These are conservative experimental limits to validate by actual measurements,
not an extrapolation from the isolated 16,000,000-WU resource model. The inherited
4,000,000-WU block ceiling remains. Signer limits of 100 inputs/100 outputs remain
local service limits, not a new consensus cap.

Use the existing cost function consistently in mempool entries, mining and
ConnectBlock. In particular, add the active ML-DSA flag before mempool cost
calculation. Do not merely add a standalone counter to tests. Standardness must
explicitly permit native v2/32 on this profile while retaining other policy
checks; do not use accept-nonstandard as a substitute. Reference public nodes use
32 MB maxmempool; pressure tests verify admission/eviction and actual accounting.

Acceptance requires exact-limit and one-over through testmempoolaccept,
broadcast/miner templates and submitblock, normal and malformed witnesses,
classical/rc2/output rejection, absence/startup/reindex/assumevalid controls,
full-weight blocks, reorg, crash/restart and full UTXO agreement. Measure release
node CPU/wall/RSS on Linux x86_64 GCC/Clang and the shipped Linux arm64 Docker
build. Declare emulation explicitly; it is not native hardware evidence.
For normal builds, 30 observed 128-check full-block validations must have p95
wall time <=2 seconds and node peak RSS <=1 GiB in the declared configuration.
Record raw timings and hardware; sanitizer runs are correctness evidence and
do not supply release timing. Fix or revise an unqualified experimental budget
before public activation, with a new profile version if sealed bytes change.

Run the actual existing spend/restore adversarial mode from current source,
without historical image IDs. Add native entropy/fault/key-lifecycle controls
and optimized builds. Preserve disclosures about uninstrumented OpenSSL and
limits of leakage, erasure and fault evidence. A fixture-only raw signer may
generate large adversarial blocks in an isolated qualification namespace; it
must not bypass limits in the shipped signer or share keys with public wallets.

## Wallet, app and operator behavior

Plumb explicit `test` versus `regtest` through native signer/client, public
manifest validation, HD/address derivation, witness attachment and node context.
Default APIs retain regtest behavior. Public clients validate the dedicated RPC
context, exact TEST binding, contract and public-profile hashes; they never infer
an active network from address syntax. MAIN remains unsupported by these tools.

Keep the current offline runtime checks intact. A separate public runtime exposes
only P2P; RPC, signer AF_UNIX and browser console stay local. Public setup and
unlock/recovery use an operator-selected secret through the existing native FD
channel. Secrets never enter argv, environment, URLs, logs, public metadata or
signer IPC. The public fixture phrase remains confined to explicit demo mode.
Backup must not retain a secret just to restart an unlocked signer; a locked
state and re-prompt is an acceptable documented transition.

Public wallet backups contain encrypted root and public address high-water data,
bound to network/contract/profile and format compatibility. They do not require
copying the whole blockchain; recover validated history from peers. Wrong
password, tampering, wrong network, missing/corrupt current record and old-backup
restore must fail or recover explicitly without lowering address floors.

Provide an explicit compatible-image upgrade and binary rollback operation.
Keep one active signer/volume, retain the prior image/descriptor and backup,
validate network/profile/contract/format and wallet identity before custody,
and never roll wallet data back to an older volume snapshot. Test two genuinely
distinct, qualified compatible source versions before declaring upgrade/rollback
complete; rebuilding the same version is only recreation evidence.

## Public exposure and resources

Research and this Mac are the two independent machines. Use normal existing
authentication without inspecting credentials, SSH keys or .env files. Preserve
the original pqbtc-mldsa-local container/volume/state and port 8844. Use fresh
task namespaces and evidence outside the repository. Do not rent new machines,
stop unrelated Research services or silently change their CPU allocation.
Heavy builds/qualification may use at most four of Research's 16 cores with
task memory/PID limits, and must keep sampled whole-host CPU below 90%; public
nodes use a smaller cap. An independent task shutdown path stops owned producers
and public listeners on terminal failure or the declared end.

Prove an unauthenticated public P2P route before starting the soak clock. A
private Tailscale connection is control-plane connectivity, not public soak.
Prefer direct public TCP. If NAT requires an already-owned free public TLS
ingress, declare and test the transport adapter, TLS/public endpoint and exact
native P2P handshake; no private-tailnet credentials may be needed by peers.
No RPC, operator channel or console is exposed. If external ingress needs an
unavailable owner setting, finish preflight and surface that concrete action;
do not relabel a private test as public or provision paid hosting.

## Predeclared 24-hour acceptance run

The immutable run declaration records exact source/tree/binaries/dependencies,
profile and corpus hashes, host identities, public transport and ports, wallet
public identities, workload schedule, start/end monotonic and UTC clocks, CPU
caps and failure criteria before public start. Only actual elapsed time counts.

Baseline: one cross-host payment per minute, alternating direction, 100,000 test
sats with an explicit 5,000-sat fee; relay, mine and require confirmed tip/full
UTXO agreement. Record per-operation results and latency, resource and peer
samples. Every ten minutes run bounded invalid-signature/wrong-network controls
against owned endpoints. Public P2P invalid-message controls use an isolated
declared phase with expected disconnect/ban behavior and explicit recovery.

Declared disruption phases: controlled node crash/restart at hour 2; a 60-second
partition and competing-chain/rejoin at hour 4; old-backup recovery with a missing
current record at hour 8; chainstate reindex at hour 12; compatible upgrade at
hour 16 and binary rollback at hour 18. Each phase must preserve wallet identity
and address floors, settle new spends afterward, and restore full peer agreement
within five minutes. Declare both version digests before start. Normal slots
allow at most 30 missed slots reserved for these declared phases; require at
least 1,410 successful normal payment slots and p95 normal settlement <=60s.

Abort on an invalid accepted signature/block, protected-output fallback,
unrecovered divergence, address reuse/lowered floor, secret disclosure,
unexplained producer gap, exceeded resource boundary or incompatible upgrade.
Save failure evidence, stop only owned workload/listeners, fix and rerun affected
preflight. A failed attempt does not contribute elapsed time to a passing new
24-hour attempt. At success, save final agreement and another recovered spend,
stop test-only public exposure/producers, preserve encrypted state and evidence,
and publish the accurately scoped experimental result. Production RELEASE_HOLD
and human-review-not-performed records remain unchanged.
