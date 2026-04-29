# PQBTC Wallet Raw-Signing And Import Posture

## Status: ACTIVE
## Spec-ID: WALLET-RAW-SIGNING-IMPORT-POSTURE-v1
## Updated: 2026-04-28
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet raw transaction signing and descriptor import
contracts under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_importdescriptors.py](../test/functional/wallet_importdescriptors.py)
- [wallet_signrawtransactionwithwallet.py](../test/functional/wallet_signrawtransactionwithwallet.py)

The owned boundary covers:

- `importdescriptors` missing descriptor errors, checksum and range validation,
  pkh and sh(wpkh) descriptor imports, duplicate public-key imports, label
  updates, internal-label rejection, invalid-key validation, multisig
  descriptor imports, ranged descriptor handling, private-key-enabled wallet
  constraints, and descriptor persistence across wallet reload
- `signrawtransactionwithwallet` locked encrypted wallet rejection, invalid
  sighash validation, script verification error reporting, fully signed
  transaction no-op behavior, OP_1NEGATE signing, and CSV/CLTV witness signing

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- inherited wallet crosschain, backwards-compatibility, or
  `createwalletdescriptor` behavior outside these raw-signing and
  descriptor-import contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-28:

- `build/test/functional/test_runner.py --jobs=1 wallet_signrawtransactionwithwallet.py wallet_importdescriptors.py`
  - result: passed
- `build/test/functional/test_runner.py --jobs=1 wallet_signrawtransactionwithwallet.py wallet_importdescriptors.py wallet_migration.py`
  - result: `wallet_migration.py` skipped because previous releases are
    unavailable; the two promoted suites passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=74`, `pq_backlog=51`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet raw transaction signing
and descriptor import behavior that already passes under the current
PQC-compatible legacy profile.

`wallet_migration.py` remains blocked locally because the previous-release
fixtures are unavailable. The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. Until then, the repo-local wallet alternate moved to remaining
wallet transaction breadth beyond this raw-signing/import gate; that adjacent
surface is now covered by `WALLET_REMAINING_TRANSACTION_BREADTH_POSTURE.md`.
