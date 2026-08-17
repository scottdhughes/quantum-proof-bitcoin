# Vendored libshrincs component seam

Upstream: `https://github.com/remix7531/libshrincs`

Pinned commit: `53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5`

This directory contains only the portable WOTS+C/SHA-256 component seam used
by the PQBTC-SHRINCS-v0 verifier:

- `src/sha256.c`
- `src/thash.c`
- `src/util.c`
- `src/wots.c`
- their four public headers
- upstream MIT license

The full current-profile stateful and stateless verifiers are project-owned
sources in `src/crypto/shrincs/`. This vendoring does not claim that upstream
`libshrincs` is a complete SHRINCS implementation.
