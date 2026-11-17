# Selected public L preflights

This selected-public packet preserves two separate attempts on [frozen source L](https://github.com/scottdhughes/quantum-proof-bitcoin/tree/7223772e76d2d0a0bb7fd1d35e0e16fba61918fd).

| Attempt | Result | Public evidence |
| --- | --- | --- |
| L01 | FAIL during Research upgrade | 2429 events, 17 confirmed payments, 10 normal successes, zero misses, five completed phases |
| L02 | PREFLIGHT_PASS | 2663 events, 22 confirmed payments, 12 normal successes, three declared-fault misses, all seven phases; 900.172816125 monotonic seconds and 900.177095 wall seconds |

L01's Research upgrade returned ConsoleError after dispatch. Its inner cause remains **UNKNOWN / unreproduced**. A separate private transition diagnostic passed; that diagnostic and L02's fresh pass do not establish a fix for L01. L01's original report remains FAIL.

L02 includes final old selected-record recovery and a confirmed spend. Public recovery preserved the independent public floor journal. This packet does not claim public recovery after both the selected record and journal are missing, or uniqueness of change-branch addresses. Separate private profiles cover the other orphan case.

**All 24-hour credit is zero.** These are preflight records. H/L native qualification and L CI are separate selected-record packets; they do not establish a completed public soak, production admission, or human review. No active soak output is included.

The original report, declaration and inventory JSON bytes are unchanged. Each events.jsonl.gz expands exactly to the original inventory-bound event bytes. Both independent reviews and the L02 root review are unchanged selected records. The backend/observer closeout is a selected public metadata receipt; its referenced raw process trace is external and is not included or claimed locally closed. No private configurations, wallets, backup data, binaries or image archives are included.

Run offline from any physical, nonsymlink directory on a POSIX system with Python 3.10 or newer:

```sh
python3 -I -B verify.py .
shasum -a256 -c SHA256SUMS
```

The verifier requires isolated Python, refuses optimized Python, validates every path component with no-follow directory/file opens, and enforces exact membership. It checks all byte seals before parsing selected pure validators from the byte-pinned frozen driver. It never imports the driver's runtime module, invokes main(), runs a node, reads private inputs, or performs network operations. Source, clock, phase, outcome and credit constraints remain mandatory even when a mutant packet is resealed.

SOURCE.json records original and packet size/SHA256 provenance. SHA256SUMS covers every local member except itself. The seal is a reproducible custody check; preserve a separately reviewed copy of its digest when publishing.
