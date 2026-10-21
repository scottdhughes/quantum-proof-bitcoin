# ML-DSA-44 production-contract draft vectors

This directory is an executable **design model**, not a node backend, signer,
wallet, transaction implementation, consensus parser or admission tool.

Read [the contract](../../docs/ML_DSA_44_PRODUCTION_CONTRACT.md) and
[staged admission](../../docs/ML_DSA_44_STAGED_ADMISSION.md) first. The initial
scope is Linux x86_64 software signing with GCC/Clang; hardware wallets are
deferred. No crypto implementation or existing source pin changes here.

In the approved offline Linux test environment, run:

```
python3 contrib/ml-dsa-production-contract/contract_model.py \
  --vectors contrib/ml-dsa-production-contract/vectors.json
python3 -m unittest ci.test.test_ml_dsa_production_contract
```

The corpus freezes literal bytes, signing-message digest and chain/profile-bound
public-key commitment for one synthetic public encoding fixture, plus rejecting
requests/envelopes. The unit tests separately transcribe the byte grammar and
check all field bindings, networks, CompactSize boundaries and malformed input.
The checker never regenerates its expected answers. These are not ML-DSA
signature KATs, fresh oracle comparisons or proof of cryptographic validity.

The envelope is deliberately domain-separated from older research fixtures and
is **not network transaction wire format**. A PASS grants no stage advancement,
human-review completion, resource promotion, ALG_ID allocation, backend enablement
or hold removal. No private keys, entropy, native libraries, subprocesses or
network access are used by the model itself.
