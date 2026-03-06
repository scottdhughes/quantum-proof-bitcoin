# Issue #48 Waiver vs Mitigation Memo (2026-03-06)

## Scope

This memo covers the March 7 to March 9, 2026 release decision for GitHub issue `#48` (`GA Blocker: offset 3272 layer-2 WOTS mutation still verifies`).
The question is narrow: can the current finding be waived for `v1.0.0`, or does it require mitigation before any GA promotion?

## Decision Update (2026-03-06)

1. The waiver path is no longer the active release posture.
2. `v1.0.0` on the original `ALG_ID=0x00` profile is held.
3. The active mitigation path is `v1.0.0-rc2` with the exact public-root profile under `ALG_ID=0x01`.
4. issue `#48` stays open until fresh rc2 evidence shows the former offset-`3272` mutation no longer verifies across the required gate set.

## Current Evidence

1. `python3 contrib/pqsig-ref/repro_offset_3272.py` still reproduces `mutated_verify=True` for the layer-2 WOTS byte at offset `3272`.
2. The C++ verifier consumes that byte through `wotsc::CommitLayerSignature(...)` and `hypertree::ComputeLayerRoot(...)`; the byte is not ignored.
3. A targeted C++ sweep over the auth, WOTS, and count boundary windows currently reports:
   - auth accepted offsets: none
   - WOTS accepted offsets: `3272`
   - count accepted offsets: none
4. The verifier still accepts on the one-byte predicate `final_digest[0] == pk_root[0]`.
5. There is no current evidence of node disagreement. The risk is accepted-set widening at the consensus layer, not a demonstrated chain split.

## Option A: Waive for GA

### Requirements

1. Bound the accepted-set behavior well enough to explain why the surviving mutation cannot become a practical unauthorized-spend vector.
2. Record an explicit accepted-set rationale signed off by release authority.
3. Keep issue `#48` visible as a documented exception in the GA package.
4. Hold block-weight changes and further verify-path edits outside a fresh adjudication cycle.

### Assessment

- The new targeted sweep narrows the immediately demonstrated symptom, but it does not validate the underlying acceptance rule.
- A GA waiver would require an argument that a one-byte terminal predicate is still a defensible authorization condition after a security-relevant WOTS byte survives mutation.
- That argument does not currently exist in this repo.
- On current evidence, a waiver is not technically defensible for GA promotion.

### Bottom Line

- A waiver is only plausible as a time-boxed RC continuation posture.
- A waiver is not sufficient for March 9 GA.

## Option B: Mitigate Before GA

### Requirements

1. Change the acceptance rule in `src/crypto/pqsig/pqsig.cpp` and any corresponding signer-side construction that depends on it.
2. Regenerate or refresh vectors and any deterministic artifacts affected by the new rule.
3. Rerun the full evidence bundle:
   - deterministic artifacts
   - bench envelope
   - PQ unit suites
   - seeded fuzz smoke
   - functional PQ suite
   - soak campaign
   - Gatekeeper on the merge commit
4. Refresh the CFC verdict and burn-in log on the mitigated candidate.

### Assessment

- Mitigation is the technically sound path because it addresses the consensus authorization rule directly.
- Mitigation almost certainly pushes the schedule past March 9 and should be treated as an `rc2` path unless it lands immediately and clears the full rerun set.
- That schedule cost is real, but it is preferable to GA promotion on an under-justified acceptance rule.

### Bottom Line

- Mitigation is the recommended path if `v1.0.0` is still intended to carry production security claims.

## Recommendation

1. Do not waive issue `#48` for March 9 GA on current evidence.
2. If a reviewed mitigation is not ready and rerun before Saturday, March 7, 2026, hold GA and plan `v1.0.0-rc2`.
3. Keep the verify path frozen until the team chooses one of two explicit dispositions:
   - mitigate and rerun the full gate set
   - or hold GA and continue burn-in without promotion

## Decision Rule

- `GO` to GA requires mitigation plus a fresh green evidence bundle.
- No mitigation by March 7 means the March 9 decision should default to `Hold and cut v1.0.0-rc2`.
- "Waive and ship GA anyway" is not supported by the current evidence.
