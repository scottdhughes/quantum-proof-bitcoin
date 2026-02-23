# Wallet Plan for PQBTC

## Status: FROZEN
## Spec-ID: WALLET-v1-deferred
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: NO

## v1 Delivery Boundary
Wallet keypool batching UX is deferred from node+consensus v1.

## Deferred Work Items
- Hardened-only child derivation for hash-based signing seeds.
- Public key batch export and replenishment workflow.
- Restore and gap-limit scanning behavior for PQ keypools.

## Interim Strategy
Node validates PQ spends; test/tooling signer flows provide transaction generation during v1.
Reference tooling path: `contrib/pqsign/pqsign.py`.
