# ML-DSA production contract v1 execution plan

Scope: finish the proposed wire/address, private HD wallet persistence and local
signer IPC contract for Linux x86_64 GCC/Clang. No backend integration,
activation, admission/pointer change, live wallet, deployment or hold removal.

1. Freeze byte-level choices and explicit trust/activation boundaries in a new
   v1 document; preserve draft-0 implementation, corpus and receipts.
2. Add failing public-data tests for wire, Bech32m, domain-separated digest,
   private derivation, wallet record framing and IPC. Observe RED in the
   existing offline Linux container before implementing the models.
3. Implement pure byte models and independent literal vectors. Test malformed,
   truncated, nonminimal, wrong-network and boundary inputs. No cryptographic
   signing/encryption, socket service or persistence implementation in this slice.
4. Run narrow tests, full contained suite, frozen preflights and unchanged-source
   validators at an exact clean local commit. This container is aarch64; do not
   describe these model tests as x86_64 binary qualification.
5. Supply the complete frozen contract, models, tests and diff to one separate
   cross-family reviewer without tools or mutation authority. Preserve its raw
   report and rule on every finding; RED/GREEN any behavioral corrections.
6. Retain a source-bound receipt, hashes, review/rulings and continuation. No
   push, PR, merge or backend integration is authorized by completing this plan.

Independent automated review is supporting evidence, not issue #181's human
review. Encryption, entropy, side-channel, crash durability, aggregate resource
qualification, public testnet and soak remain later system work.
