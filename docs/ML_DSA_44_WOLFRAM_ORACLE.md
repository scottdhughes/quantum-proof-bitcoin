# ML-DSA-44 Wolfram Exact-Model Evidence

## Status: SUPPLEMENTAL EVIDENCE
## Spec-ID: ML-DSA-44-WOLFRAM-EXACT-v1
## Updated: 2026-07-19
## Consensus-Relevant: NO

## Decision

Use Wolfram Language as an independent exact-arithmetic cross-check for the
bounded algebra and encoding rules in FIPS 204. Do not count it as a fourth
cryptographic implementation or as satisfaction of the external-review gate.

## Evidence Added

The model and tests in `contrib/ml-dsa-ref/wolfram/` cover:

- Algorithms 41 and 42 against both the defining transform equation and direct
  negacyclic polynomial multiplication;
- the exact centered-reduction, `Power2Round`, `Decompose`, `HighBits`,
  `LowBits`, `MakeHint`, and `UseHint` boundaries;
- strict hint encoding and rejection of repeated positions, decreasing or
  oversized cumulative counts, and nonzero padding;
- Montgomery reduction congruence at its stated input boundaries; and
- independent constants, field facts, inverse facts, and Appendix B twiddle
  factors.

The deterministic test polynomials and boundary corpora are generated inside
the test file. Constants are transcribed into the model from FIPS 204 rather
than derived from the repository manifest. The existing Python reference tests
separately enforce the corresponding `vectors.json` profile values.

## Reproduction

Run the Wolfram test file with a fresh kernel:

```wolfram
TestReport[
  "contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wlt"
]
```

For MCP execution, mechanically concatenate the package and test file because
the service does not preserve sibling-file loading:

```bash
awk 'BEGIN { print "Quiet[Remove[\"MLDSA44ExactOracle`*\"]];" } { print }' \
  contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wl \
  contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wlt \
  > /private/tmp/MLDSA44ExactOracle.bundled.wlt
```

Pass the transient bundle to MCP `TestReport`; do not commit it. On 2026-07-19,
Wolfram Language `15.0.0 for Mac OS X ARM (64-bit)` passed all 18 tests through
the MCP managed kernel. MCP `CodeInspector` also reported no issues at
confidence `0.75` with formatting and scoping findings excluded. A separate
fresh test kernel could not be started, so the successful report used the
managed kernel after explicitly removing the package context and loading the
exact package content into the bundle.

## Limits

This evidence does not cover SHAKE, sampling, key generation, signing,
verification, native integer overflow, memory safety, constant-time behavior,
side channels, fault injection, or secret erasure. The production hold and the
external cryptographic review requirement remain unchanged.
