# ML-DSA actual-node UTXO bridge implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline. Continue under the owner's existing just-continue direction, no new design approval loop.

**Goal:** Build and test a public-only bridge from actual CTransaction/CCoinsViewCache
objects to CONTRACT-1, then continue to the separately gated Script/network/wallet
integration. This bridge alone is not an accepted-spend or live-backend claim.

**Architecture:** An immutable transaction reference and copied validated Coin
outputs produce one PreparedTransaction snapshot. The bridge reads the real Coin
view, not SIGN_TX metadata. Exact effective chain parameters resolve the frozen
network binding or fail closed. Public verification stays separate from signer
code; an optional build target does not change default node rules.

**Tech Stack:** Existing C++20 transaction/Coin/chain-parameter classes, C11 public
ML-DSA verifier, Boost unit tests, optional CMake targets, bounded offline Linux.

**Spec:** docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md and docs/ML_DSA_44_OWNER_CONTINUATION.md.

## Global constraints

- Base0245b38cd95e1c864b80685f5f6cb9a5f9dc8919; preserve sealed signer evidence.
- Target Linux x86_64 GCC/Clang; new local runtime is ARM supplemental only.
- Runtime image767891744587d93faf96d0f9d8ce2c66ebe3a73695b2a7389f82b62735b8ad3a,
  networknone/ROroot/4GiB4CPU/capdropALL/no-newprivileges/source.gitRO. No host native.
- Provisioning network was separate, no source/user-data mounts; not qualification.
- No private signer/key-owner/libcrypto in node bridge or node unit fixtures.
- No arbitrary signer digest API, frozen vendor/old proofs/admission/pointer changes.
- Default build/rc2/Taproot/520-byte/unknown-witness accepted rules unchanged here.
- No production H/checkpoint/inventory assertion, live funds or public deployment.
- External human review remains NOT PERFORMED under disclosed owner exception.

## Review focus

- A cached snapshot must not silently switch to another transaction or changed UTXO.
- Missing/spent/negative/mismatched Coin metadata must never produce acceptance.
- Internal txid bytes must not be reversed into display order by the adapter.
- Inherited Bitcoin chain parameters must not be mistaken for frozen PQBTC B.
- Signer policy bounds100/1MiB must not silently become consensus limits.

### Task 1: Actual CTransaction/Coin bridge and optional public build

**Files:** create src/crypto/mldsa44/node.h,node.cpp;
modify CMakeLists.txt,src/CMakeLists.txt,src/test/CMakeLists.txt;
create src/test/mldsa44_node_tests.cpp and public test vector data if needed.

**Interfaces:** namespace pqbtc::mldsa44::node:
`Network ResolveNetwork(const CChainParams&)` compares message-start plus internal
genesis bytes to all3 frozen B values, throwing invalid_argument on mismatch.
`class Snapshot` consumes `CTransactionRef,const CCoinsViewCache&`; owns the
immutable ref, copied prevout scripts and one PreparedTransaction. Public methods
`Hash Message(Network,size_t) const` (byte-model interoperability only),
`bool VerifyInput(const CChainParams&,size_t) const` (uses the stored actual
prevout's native-v2/32 program and immutable input witness, no caller program),
`const CTransaction& Transaction() const`. Caller holds the node's Coin-view
validation lock while constructing; no lazy references to mutable Coin entries.

- [ ] Verify inherited node baseline builds pqbtcd,pqbtc-cli,test_pqbtc in offline
  Linux; run the complete unit executable and record actual result before edits.
- [ ] Add RED unit tests: actual CTransaction+Coin view message matches fixed
  independently encoded model; missing/spent/negative Coin rejected; changed
  amount/script/outpoint/output/index invalidates a literal public signature;
  old snapshot stable after Coin view changes; inherited RegTest B rejected.
- [ ] Observe missing node bridge RED, then implement conversion/snapshot using
  PreparedTransaction directly, never SerializeUnsigned's signer-only limits.
- [ ] Add ENABLE_EXPERIMENTAL_MLDSA44 defaultOFF; public verifier and node bridge
  optional targets, test file conditional. C enabled only as needed. No signer
  sources, key generation, entropy or OpenSSL link dependency in those targets.
- [ ] Build/run targeted Boost tests with the optionON and test optionOFF default
  remains unchanged; check actual link inputs/symbols. Commit only green source.

### Task 2: Review, evidence and continuation to accepted-spend integration

**Files:** new packet20261022-mldsa-node.r7Ij9C, plan-specific ledger and review;
source fixes only if independently found/reproduced within this bridge scope.

- [ ] Supply complete NEW bridge patch/context to one Claude tools-disabled
  review; this is new code, not an unchanged re-review of the signer.
- [ ] Regrade by effect, one RED/GREEN required fix pass/full suite, disposition
  all declined items and costs. No cleanup of older work or sealed packets.
- [ ] Exact clean GCC/Clang bridge/default-build/unit evidence with actual platform
  labels, source/build/ELF/link joins and new seal. No x86 relabeling of ARM.
- [ ] Continue actual experimental Script checker/network absence guard/cache
  transitions, public wallet persistence/signer IPC and cross-node spend/restore/
  reorg/reindex tests; then distinct supported x86_64/system qualification. These
  remain implementation obligations, not satisfied by this bridge's unit tests.
