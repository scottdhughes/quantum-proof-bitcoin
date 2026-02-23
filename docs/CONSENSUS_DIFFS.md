# Consensus Diffs Ledger

## Status: FROZEN
## Spec-ID: CONSENSUS-DIFFS-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Required v1 Consensus Diffs
1. Chain identity changes from Bitcoin defaults to deterministic PQBTC constants.
2. Block weight limit from 4,000,000 to 16,000,000 WU.
3. Script element size limit increased from 520 to at least 10,000 bytes.
4. Signature validation semantics switch from secp-based checks to PQSig checks.
5. PQSig key and signature fixed-size wire rules become consensus-critical.
6. Taproot activation disabled for v1 deployment profile.

## Audit Requirement
Every merged consensus diff must reference this document and corresponding tests.
