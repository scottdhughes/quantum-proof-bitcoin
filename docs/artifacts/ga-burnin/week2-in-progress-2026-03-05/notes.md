# week2-in-progress-2026-03-05

- Snapshot at (UTC): 2026-03-05T20:46:33Z
- Candidate commit: 8bd1e97bda89192cc3a6ddbf4e0e53051b5ef86f
- Candidate short SHA: 8bd1e97bda
- Status: in progress for the 2026-03-09 GA decision checkpoint.

## Evidence source

This directory intentionally reuses the fresh March 5, 2026 evidence bundle captured into:
- `docs/artifacts/ga-burnin/week1-backfill-2026-03-05`
- `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05`
- `/Users/scott/quantum-proof-bitcoin/build/soak-artifacts/pq-mempool-20260305T204116Z`

## Why still incomplete

- The dated Week 2 GA checkpoint is `2026-03-09`, which is still in the future.
- The current local candidate is a dirty working tree, not a merge commit with current gatekeeper evidence.
- The layer-2 WOTS mutation at offset `3272` remains an open GA-blocking `priority:P1` finding tracked in GitHub issue `#48`.

## Historical exclusion

The soak batch at `/Users/scott/quantum-proof-bitcoin/build/soak-artifacts/pq-mempool-20260228T184455Z` is excluded from GA evidence because it failed during HTTP server startup and RPC binding, not during PQ relay or mempool execution.
