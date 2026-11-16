# Historical G CI evidence

Packaged 2026-11-16 UTC. This is an unchanged copy of the historical GitHub CI
snapshot observed at **2026-11-15 23:56:40 UTC**, for source G
`4339d436cdcfce9724476b9786994d347f1a4b06`, tree `b9923bede37da41119ac69a39d57f16a8a89b3eb`.
It records **14 completed-success workflow runs and 52 successful jobs**, all on
**attempt 1**. The 22-job Promotion Matrix and both GCC/Clang assembled matrices
(two jobs in each run) are included. Event categories are nine pull-request runs,
three push runs, and two manual workflow dispatches.

This CI result belongs only to G. It supplies **no H/I qualification credit**, no
public-soak PASS, and no production admission. G's separate 24-hour public attempt
failed; the [failed-attempt packet](../../ml-dsa-44-public-soak/G-4339d436-attempt02/SOURCE.json)
retains its own terminal result and zero elapsed credit. The separate
[G native/preflight packet](../G-4339d436/SOURCE.json) preserves its distinct native
and 900-second preflight evidence. CI jobs do not replace those source/binary/run
boundaries.

`report.json` preserves the exact original **131,564 bytes**, copied from
`github/candidate-G-4339d436-all-CI.json` in the task's external evidence root.
Its SHA256 is `4095a3892babb34113263743175b54eb2e95d9abbeb5cac031961d9732feda9f`. A recursive private-field, credential-pattern,
and signed-URL scan found no matching private fields/material or signed URLs.
No fresh CI polling, dispatch, rerun, build, or native execution was performed
for this packaging step. The scoped `.gitattributes` rule preserves exact bytes
under Git newline-conversion settings.

## Portable verification

From this directory:

```sh
shasum -a 256 -c SHA256SUMS
```

GNU `sha256sum -c SHA256SUMS` is equivalent. The following standard-library Python
check independently binds the report, counts, attempts, and recorded job matrices:

```python
import hashlib
import json
from pathlib import Path

raw = Path("report.json").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "4095a3892babb34113263743175b54eb2e95d9abbeb5cac031961d9732feda9f"
r = json.loads(raw)
assert r["source"] == {"head": "4339d436cdcfce9724476b9786994d347f1a4b06", "tree": "b9923bede37da41119ac69a39d57f16a8a89b3eb"}
runs = r["runs"]
jobs = [job for run in runs for job in run["jobs"]]
assert r["result"] == "PASS" and len(runs) == r["run_count"] == 14
assert len(jobs) == r["materialized_job_count"] == r["success_job_count"] == 52
assert len({job["id"] for job in jobs}) == 52
assert all(run["head_sha"] == r["source"]["head"] and run["run_attempt"] == 1
           and run["status"] == "completed" and run["conclusion"] == "success"
           for run in runs)
assert all(job["run_id"] == run["id"] and job["status"] == "completed"
           and job["conclusion"] == "success" for run in runs for job in run["jobs"])
assert [len(run["jobs"]) for run in runs if run["name"] == "Promotion Matrix"] == [22]
assert [len(run["jobs"]) for run in runs
        if run["name"] == "ML-DSA-44 clean-checkout assembled system"] == [2, 2]
print("VERIFIED_HISTORICAL_G_CI: 14 runs / 52 jobs / attempt 1; no H/I credit")
```
