# PQBTC Naming Conventions

This document defines the naming conventions for the PQBTC project, including binary names, data directories, and user-visible identifiers.

## Purpose

Rename all user-visible identifiers from "bitcoin" to "pqbtc" to:
- Avoid operator confusion between Bitcoin Core and PQBTC
- Prevent accidental mixing of datadirs and configurations
- Clearly signal this is a separate chain with incompatible consensus rules

## Binary Names

| Original | PQBTC |
|----------|-------|
| `bitcoin` | `pqbtc` |
| `bitcoind` | `pqbtcd` |
| `bitcoin-cli` | `pqbtc-cli` |
| `bitcoin-tx` | `pqbtc-tx` |
| `bitcoin-util` | `pqbtc-util` |
| `bitcoin-wallet` | `pqbtc-wallet` |
| `bitcoin-chainstate` | `pqbtc-chainstate` |
| `bitcoin-qt` | `pqbtc-qt` |
| `bitcoin-gui` | `pqbtc-gui` |
| `bitcoin-node` | `pqbtc-node` |
| `test_bitcoin` | `test_pqbtc` |
| `test_bitcoin-qt` | `test_pqbtc-qt` |

## Data Directories

| Platform | Original | PQBTC |
|----------|----------|-------|
| Linux | `~/.bitcoin` | `~/.pqbtc` |
| macOS | `~/Library/Application Support/Bitcoin` | `~/Library/Application Support/PQBTC` |
| Windows | `%APPDATA%\Bitcoin` | `%APPDATA%\PQBTC` |

## Configuration Files

| Original | PQBTC |
|----------|-------|
| `bitcoin.conf` | `pqbtc.conf` |

## User Agent

| Field | Original | PQBTC |
|-------|----------|-------|
| Client Name | `Bitcoin Core` | `PQBTC Core` |
| User Agent | `Satoshi` | `PQBTC` |

The user agent string will follow the format: `/PQBTC:X.Y.Z/`

## Service Names (Init Systems)

| Original | PQBTC |
|----------|-------|
| `bitcoind.service` | `pqbtcd.service` |
| `bitcoind.conf` | `pqbtcd.conf` |
| `org.bitcoin.bitcoind.plist` | `org.pqbtc.pqbtcd.plist` |

## What Is NOT Changed

The following are intentionally NOT renamed:

1. **Historical Release Notes**: `doc/release-notes/` documents Bitcoin Core history
2. **Internal Code Paths**: No renaming of source file names or internal identifiers unless necessary
3. **License Files**: COPYING remains unchanged
4. **Upstream Attribution**: Bitcoin Core attribution preserved in documentation

## Rationale

### Why "PQBTC"?

- **PQ**: Post-Quantum (cryptography)
- **BTC**: Bitcoin (derivative chain)
- Short, memorable, clearly indicates purpose

### Why Not Keep "Bitcoin"?

Running both Bitcoin Core and PQBTC on the same system with identical binary names and datadirs would create:
- Confusion about which daemon is running
- Risk of accidentally connecting to wrong network
- Potential data corruption if wrong binary accesses wrong datadir

### Case Sensitivity

- Binary names: lowercase (`pqbtcd`, `pqbtc-cli`)
- Data directory (Windows/macOS): mixed case (`PQBTC`)
- Data directory (Linux): lowercase (`.pqbtc`)
- User agent: uppercase (`PQBTC`)

## Implementation Notes

### Build System (CMake)

All `add_executable()` calls must use the new binary names:
- `add_executable(pqbtcd ...)` instead of `add_executable(bitcoind ...)`

### Test Framework

The Python test framework (`test/functional/`) must be updated:
- Binary name references
- Config file names
- PID file names
- Logger names

### Man Pages

Man pages must be renamed and their contents updated:
- File names: `pqbtcd.1`, `pqbtc-cli.1`, etc.
- Internal references to binary names and config files

## Changelog

- 2026-01-18: Initial naming conventions established (Gate 0.75)
