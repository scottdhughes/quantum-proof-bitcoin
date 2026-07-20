# ML-DSA-44 Engineering Contracts

This directory contains executable design contracts and an isolated portable-C
wrapper prototype for the selected `ML-DSA-44` engineering candidate. It is
separate from the frozen comparator in `contrib/ml-dsa-ref/` and is not linked
into the node, wallet, Script, or consensus code.

`hedged_signing_contract.py` models the fail-closed boundary required before a
future production signer can be proposed:

- the public API exposes hedged signing only;
- the 32-byte randomizer is generated inside that boundary;
- zero, repeated, short, unavailable, or failed entropy produces no signature;
- signing and self-verification failures produce no signature;
- calls through one signer are serialized and randomizer reuse detection is
  atomic across concurrent callers; and
- the local randomizer buffer is overwritten on every return path.

The Python module deliberately uses opaque key handles and a backend protocol.
It does not provide consensus code or claim that Python buffer clearing
establishes production secret erasure. Test-only entropy injection is private
to the executable contract tests. The private backend protocol is a model
seam, not a production FFI.

`backend_admission.json` records the bounded backend decision. It admits the
pinned `mldsa-native` portable-C path for a separate isolated wrapper prototype
only. The production backend remains unset, OpenSSL and libcrux remain oracles,
and every production gate remains open. The manifest also freezes the proposed
single-translation-unit, static-symbol, portable-C build contract.

`pqbtc_mldsa44.c` implements that contract as a production-shaped but
research-only wrapper. The checked-in `vendor/mldsa-native/` capsule contains
only the exact 34-file portable dependency closure and upstream license. The
normal build exports only `pqbtc_mldsa44_sign_hedged` and
`pqbtc_mldsa44_verify_strict`; deterministic, fixed-randomizer, seeded-keygen,
and failure controls exist only in a separately compiled test build. The
network-free harness checks source hashes, symbols, frozen vectors, OS entropy,
failure behavior, concurrency, and ASan/UBSan execution.

The normative requirements and lifecycle limits are in
`docs/ML_DSA_44_HEDGED_SIGNING_CONTRACT.md`. The admission disposition and
candidate comparison are in `docs/ML_DSA_44_BACKEND_ADMISSION.md`.
The implemented evidence and remaining boundaries are in
`docs/ML_DSA_44_WRAPPER_PROTOTYPE.md`.
