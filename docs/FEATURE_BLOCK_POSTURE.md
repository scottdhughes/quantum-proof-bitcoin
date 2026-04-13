# Feature Block Posture

## Status

- Suite: `test/functional/feature_block.py`
- Policy class: `pq_backlog`
- Scope of current owned tranche: PQ-specific harness adaptation plus the
  invalid multi-block branch contract required to keep the full suite green on
  PQBTC

## Current Owned Contract

The current owned `feature_block.py` tranche is still deliberately bounded, but
it is now broader than the original same-work fork-choice carveout.

It freezes six things:

1. The script-size boundary setup is adapted to PQBTC's larger
   `MAX_SCRIPT_ELEMENT_SIZE` by constructing exact push-only scripts at
   `MAX_SCRIPT_SIZE` and `MAX_SCRIPT_SIZE + 1`.
2. Block-spend signing in this functional suite uses the PQ legacy-signature
   helpers rather than inherited classical ECDSA helpers.
3. Same-work side branches are treated as header-only announcements that do not
   move the active tip by themselves. When a later test needs to evaluate that
   side branch further, the suite explicitly force-sends the required ancestor
   chain instead of relying on inherited header-fetch timing.
4. Invalid multi-block branches hanging off those side branches are asserted as
   explicit invalid-branch outcomes with the active tip preserved, instead of
   depending on inherited disconnect-only behavior. That includes:
   - the double-spend longer fork
   - the bad-coinbase longer forks
   - the forked reorged-out spend branch
   - the forked immature-coinbase branch
5. Oversized edge cases that now fail at the transport layer under PQBTC are
   treated as disconnect/oversize cases in this suite, not parser-level
   validation cases. That currently includes the `b24` and `b64a` paths.
6. The transaction-resurrection section is grounded on the actual mempool
   baseline: the suite now asserts that `tx78` and `tx79` are absent before the
   reorg and reappear afterward, without assuming the global mempool is empty.

## Explicit Non-Goals For This Tranche

This tranche still does not:

- promote `feature_block.py` into `pq_required`
- claim a general PQ migration decision for every chainstate-facing behavior in
  the suite
- redesign consensus, policy, or mempool semantics outside the specific
  functional-harness contracts listed above

Those remain later CI/backlog decisions, not a reason to widen this tranche
into a broader chainstate rewrite.
