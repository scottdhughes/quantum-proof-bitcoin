# Native platform qualification

Run from a clean committed checkout with a working Docker CLI. The host runs
Python orchestration; the node, signer, compiler, and fixture code run only in a
fresh offline Linux container. The existing local wallet is not targeted.

For an x86_64 Linux Docker host:

```sh
python3 contrib/ml-dsa-qualification/run_native_qualification.py \
  --compiler gcc --expect-head "$(git rev-parse HEAD)" \
  --expect-architecture x86_64 --output-dir /tmp/pqbtc-native-gcc-evidence
```

Use `--compiler clang` for the other compiler. On an Apple Silicon Mac with a
native Linux Docker VM use `--expect-architecture aarch64`. A translated image
does not pass the native architecture gate. A prior source-build descriptor can
be reused with `--descriptor /absolute/path/runtime-descriptor.json`; its image,
source HEAD/tree, compiler, binary hashes, and pinned dependency installation
must match. The evidence directory and `pqbtc-native-*` container name must be
new. `--no-cache` requests a fresh source image build.

The assembled-system GCC/Clang CI jobs reuse the image already tested through
the app, so the stronger stage does not require another full node build.

The runner records:

- Normal and ASan/UBSan contract/backend and wallet/IPC signer checks, including
  explicit TEST binding. Sanitizer positive controls and the private-symbol
  audit remain required.
- Native entropy/fault, protected allocation, erasure, export, and alias controls
  from the key-lifecycle harness, with its complete transcript and disassembly.
- The node's activation, public-profile, and shared verification-cost unit
  suites, followed by actual two-node spends, adverse controls, encrypted old
  record restore, reindex, restart, and full UTXO comparison. This spend/restore
  fixture uses the existing offline regtest profile; it is not a public soak.
- Actual TEST-profile 25/26-input mempool and 128/129-verification template/block
  boundaries, malformed rejection, and 32 MB mempool pressure/eviction.
- Actual public-profile classical/output-shape and wrong-network signature
  rejections, native/canonical positive controls, and both reindex paths. Full
  reindex must log rejection of the exact stored forbidden block hash, while
  retaining the valid tip and complete UTXO fingerprint. Node logs are retained.
- Thirty distinct 4,000,000-WU blocks with 128 ML-DSA verifications and dense
  output metadata. The declared release thresholds are p95 submitblock wall time
  at most 2 seconds and node peak RSS at most 1 GiB. Raw CPU, wall, memory, and
  configuration observations are retained. Fixture construction is excluded
  from the timing interval.

The container has four CPU cores, 4 GiB memory, 512 PIDs, and a 3 GiB temporary
filesystem. Its root is read-only, all capabilities are dropped, and it has no
network or host mounts. Public fixture diagnostics are collected before owned
container cleanup. Cleanup failure makes the final receipt FAIL. No skipped,
instrumented, short, or pressure-free resource run becomes a release PASS.

The pinned static OpenSSL library is reused and is not sanitizer-instrumented
by this run. Whole-node sanitizer builds are also outside this runner's stated
instrumentation scope. These exclusions are recorded in the result. Successful
platform qualification does not remove production RELEASE_HOLD, claim a human
cryptographic review, or count any time toward the separate public 24-hour soak.
