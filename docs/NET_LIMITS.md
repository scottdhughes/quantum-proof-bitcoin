# Network Limits for PQBTC v1

## Status: FROZEN
## Spec-ID: NET-LIMITS-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: NO

## Scope
Network-level relay and transport limits that interact with larger PQ witness payloads.

## v1 Requirements
- Maintain bounded per-message and per-peer resource usage.
- Preserve existing anti-DoS behavior while accommodating larger standard witness data.
- Keep serialization and relay paths deterministic under large transaction sizes.
