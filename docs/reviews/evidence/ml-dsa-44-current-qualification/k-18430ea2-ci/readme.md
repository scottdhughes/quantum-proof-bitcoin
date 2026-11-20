# K exact-source CI evidence

Packaged 2026-11-16 UTC from the sealed CI report for K
`18430ea2cfcac66cca0e8612605db47a5c0e935b`, tree
`d397b324f83b82017722073c3c53688e0765fb30`.

The [unchanged report](report.json) records **13 successful workflow runs and 51
successful latest logical jobs**: **22** in the Promotion Matrix and **29** across
12 other runs. Both actual macOS ARM64 capacity retries passed. The original
anonymous advisory API quota failure, its one successful authorized retry, the
two original zero-runner capacity cancellations, both rejected API calls, and
exactly one executed capacity retry per Mac dimension remain explicit in the
report. GitHub carries earlier successful logical results forward; those records
are not additional test executions.

The report also binds the manual GCC/Clang Linux x86-64 native qualification,
private two-container app flows, selected public resource/consensus reports, and
verified GCC export/archive identity. These distinct receipts remain scoped to
K. CI provides **zero public-soak elapsed credit**, no completed 24-hour soak,
no independent human cryptographic review, and no production admission.

This packet has exactly five local files: report.json, source.json, readme.md,
sha256sums, and .gitattributes. The [provenance record](source.json) distinguishes
these local members from **external history/custody references**. The 51 files in
the original external CI custody seal are not claimed as local members of this
compact packet. Referenced auxiliary payload files, archives, wallets, keys, credentials,
and runtime state directories are outside this packet. The raw report itself embeds
selected history details and external hashes.

The report preserves exactly **223,222 bytes**, SHA256
`08bfcb22321ce0fc9a3b93cde46a1b2ffea9837e8523065b4ffe40468b3dedb6`.
The scoped .gitattributes rule preserves these bytes under Git newline conversion.
No fresh GitHub polling, dispatch, rerun, source/runtime change, or publication
was performed for this packaging step.

Official references: [K source](https://github.com/scottdhughes/quantum-proof-bitcoin/commit/18430ea2cfcac66cca0e8612605db47a5c0e935b),
[Promotion Matrix](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43931134510),
[manual assembled/export](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43931134439),
and [advisory run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43929408313).

## Portable offline verification

From this directory, `shasum -a 256 -c sha256sums` verifies all four sealed members;
GNU `sha256sum -c sha256sums` is equivalent. The checksum file is the external seal
root and does not hash itself. The following standard-library Python check also
binds the bounded logical inventory and the two actual Mac executions. Isolated
mode ignores Python environment settings such as PYTHONOPTIMIZE. An explicit
optimized interpreter is refused by a non-assert guard before any checks:

```sh
python3 -I -B - <<'PY'
if not __debug__:
    raise SystemExit('Optimized Python refused')

import hashlib
import json
from pathlib import Path

root = Path.cwd()
expected = {"head": "18430ea2cfcac66cca0e8612605db47a5c0e935b", "tree": "d397b324f83b82017722073c3c53688e0765fb30"}
lines = (root / "sha256sums").read_text().splitlines()
assert len(lines) == 4
names = set()
for line in lines:
    checksum, name = line.split("  ", 1)
    assert name in {".gitattributes", "readme.md", "report.json", "source.json"} and name not in names
    names.add(name)
    path = root / name
    assert path.is_file() and not path.is_symlink()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == checksum
assert {p.name for p in root.iterdir()} == names | {"sha256sums"}
raw = (root / "report.json").read_bytes()
assert len(raw) == 223222 and hashlib.sha256(raw).hexdigest() == "08bfcb22321ce0fc9a3b93cde46a1b2ffea9837e8523065b4ffe40468b3dedb6"
r = json.loads(raw)
assert r["source"] == expected and r["result"] == "PASS"
runs = r["runs"]
jobs = [job for run in runs for job in run["jobs"]]
assert len(runs) == r["run_count"] == 13
assert len(jobs) == r["latest_logical_job_count"] == 51
assert len({job["id"] for job in jobs}) == 51
assert all(run["headSha"] == expected["head"] and run["status"] == "completed" and run["conclusion"] == "success" for run in runs)
assert all(job["run_id"] == run["databaseId"] and job["status"] == "completed" and job["conclusion"] == "success" for run in runs for job in run["jobs"])
m = next(run for run in runs if run["databaseId"] == 43931134510)
assert m["attempt"] == 3 and len(m["jobs"]) == r["matrix_latest_logical_jobs"] == 22
assert r["non_matrix_runs"] == 12 and r["non_matrix_latest_logical_jobs"] == 29
h = r["availability_retry_history"]
assert h["advisory"]["executed_retry_count"] == 1
assert h["matrix"]["executed_retry_counts"] == {"fuzz": 1, "GUI": 1}
fuzz = next(j for j in h["matrix"]["second_attempt"]["jobs"] if j["id"] == 133573080807)
gui = next(j for j in h["matrix"]["latest_attempt"]["jobs"] if j["id"] == 133585508256)
assert all(j["conclusion"] == "success" and j["runner_id"] > 0 for j in (fuzz, gui))
assert r["manual_assembled_and_export"]["manual_assembled_result"] == "PASS"
assert r["public_soak_elapsed_seconds_credited_from_CI"] == 0
print("VERIFIED_K_CI: 13 runs / 51 latest logical jobs / matrix 22; no public-soak credit")
PY
```
