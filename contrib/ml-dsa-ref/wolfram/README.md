# ML-DSA-44 Exact Wolfram Model

This directory contains an independently transcribed, exact-integer model of
selected FIPS 204 operations for the `ML-DSA-44` parameter set. It supplements
the native three-oracle comparator; it is not a fourth implementation oracle.

## Covered Operations

- centered reduction and eight-bit reversal
- FIPS 204 Algorithms 41 and 42, checked against the defining NTT equation
- pointwise NTT multiplication, checked against direct multiplication in
  `Z_q[X]/(X^256 + 1)`
- Algorithms 35 through 40 for rounding, decomposition, and hints
- strict Algorithm 20 and 21 hint packing and malformed-encoding rejection
- Algorithm 49 Montgomery reduction
- the exact `ML-DSA-44` constants and leading Appendix B twiddle factors

The tests use arbitrary-precision integer arithmetic. They include explicit
boundary corpora rather than machine-integer approximations.

## Run

From a Wolfram Language kernel:

```wolfram
TestReport[
  "contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wlt"
]
```

Codex can run the same file through the Wolfram MCP `TestReport` tool. A local
Wolfram desktop activation is not required for that MCP execution path. The
MCP runner does not preserve sibling-file loading, so create a transient test
bundle containing the exact package followed by the test file:

```bash
awk 'BEGIN { print "Quiet[Remove[\"MLDSA44ExactOracle`*\"]];" } { print }' \
  contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wl \
  contrib/ml-dsa-ref/wolfram/MLDSA44ExactOracle.wlt \
  > /private/tmp/MLDSA44ExactOracle.bundled.wlt
```

Pass that transient `.wlt` path to the MCP `TestReport` tool. The bundle is a
transport artifact only and must not be committed as a separate source of
truth.

## Evidence Boundary

The model is a specification-level cross-check. It does not implement SHAKE,
sampling, key generation, signing, or verification. It is not constant-time,
does not model native overflow or memory behavior, and provides no side-channel
or secret-erasure evidence. It is not linked into PQBTC, does not define
consensus behavior, and does not authorize an `ALG_ID`, wallet integration, or
production release.

The controlling source is the final NIST FIPS 204 PDF pinned in
`../vectors.json` with SHA256
`57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b`.
Potential corrections remain separately pinned and do not silently alter this
model.
