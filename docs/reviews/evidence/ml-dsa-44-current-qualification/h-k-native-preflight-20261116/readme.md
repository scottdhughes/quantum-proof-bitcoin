# H/K native, private HTTP and completed K preflight evidence

This selected packet records three qualified Linux profiles for H and four
for K. Every profile reports nine native gates and the 17-event private HTTP
flow. H ARM Clang was not qualified and is not claimed. Profile directories
and exact source/image identities are indexed in [source.json](source.json).

The separate [completed preflight](public-preflight01/report.json) is
PREFLIGHT_PASS: 2,305 hash-linked events, seven completed faults, 22 unique
confirmed payments, 12 successful normal slots, three fault-window misses,
final selected-record recovery and confirmed spend, and owned cleanup.
Its actual event clocks exceed 900 seconds. This is zero 24-hour soak credit.
The final public preflight retained the independent journal; the stronger
both-records-missing private recovery case is separately recorded in each
17-event private HTTP report. Public protocol keys, transaction identifiers,
and compact disposable test-wallet counters are intentionally preserved in
the unmodified public event chain; no private keys/operator input are present.

The 15 selected H/K functional files are byte-identical; tracked differences
are under docs/. The qualified image/node identities differ. The recorded
upgrade/rollback is a mechanical binary transition, with no claimed new
consensus format or behavioral upgrade. These are valueless prototype TEST
results. Production admission, independent human cryptographic review, whole
application constant-time behavior, and a successful 24-hour public soak are
not claimed. Ongoing soak output is deliberately absent.

Run from any directory using Python3 standard library only:

    python3 -I -B /path/to/packet/verify.py

Run the seven isolated negative controls with:

    python3 -I -B /path/to/packet/negative-controls.py

The negative controls mutate disposable copies only. Short-clock, wrong-source
missing-phase, stale-manifest-digest and event-declared-duration mutants
rebuild copied checksums to
exercise semantic gates;
none alter the original records. An external public-marker directory-symlink
fixture is rejected, and disposable copies preserve symlinks instead of
following their external contents.

The verifier checks exact selected-file membership, checksums, source/image/
compiler/native-architecture identities, native resource/consensus DATA,
private HTTP events, original included inventory members and complete
preflight hash chain/timing/fault/recovery/cleanup bindings. It does not run
native programs or reproduce their execution. See [sha256sums](sha256sums).

Original native inventories are preserved byte-for-byte but also name omitted
logs, corpus/frame data and key-lifecycle archives. Those omitted payloads
are external historical custody references, not closed local dependencies.
Only the four selected native inventory payloads/profile are rehashed here.
Four x86 profiles also retain their native-original descriptor auxiliary.
Those exact bytes match the native inventory, while each outer descriptor's
exact bytes match the declared exported runtime identity. Complete parsed
descriptor objects are equal; their original byte serializations differ.
Neither original serialization is normalized or replaced.
Report paths and reviewer context may contain original machine paths or CI
artifact references; these are historical provenance, never instructions to
fetch private/omitted content. Raw reports retain historical cleanup and CI
snapshot statuses unchanged. Later context does not rewrite those records.

Only selected public JSON, deterministic lossless preflight event gzip and
derived metadata/verifier are included. No image/ZIP/tar/binary, private
wallet/state/backup/cookie/environment/operator material, deployment config,
or live/growing soak output is copied. This staging packet is prepared for
review; publication is a later root-owned action after the soak terminates.
