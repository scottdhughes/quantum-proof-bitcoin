# PQBTC v1 Test Signer

Deterministic signer utility for PQBTC v1 test flows. The implementation uses
the locked reference model in `contrib/pqsig-ref/pqsig_ref.py` and is intended
for test/regtest tooling only.

## Usage

```bash
python3 contrib/pqsign/pqsign.py \
  --msg32 <32-byte-hex> \
  --pk-script33 <33-byte-hex> \
  --sk-seed <hex> \
  --max-counter 1048576 \
  --out sig.hex
```

Notes:
- `msg32` must be exactly 32 bytes.
- `pk-script33` must be exactly 33 bytes and start with `00`.
- Signature output is always exactly 4480 bytes.
- This is not a wallet UX flow and not a production key manager.
