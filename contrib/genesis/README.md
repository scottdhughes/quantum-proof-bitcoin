# Deterministic Genesis/Identity Generator

This directory contains deterministic tooling to derive PQBTC network identity
constants and genesis parameters from a fixed seed phrase.

## Usage

```bash
python3 contrib/genesis/generate_constants.py \
  --seed "PqbtcGenesis/v1/2026-02-22" \
  --out contrib/genesis/generated_constants.json
```

The output JSON is stable for a given seed and script version.
It includes message start bytes, ports, HRP, base58/xkey prefixes, and
genesis header+hash commitments for `main`, `test`, and `regtest`.
