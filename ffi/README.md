SHRINCS FFI (dev stub)
======================

This folder contains a minimal C prototype (`shrincs.c`) matching the ABI expected by the Rust `shrinics-ffi` feature.
It is a **stub**: it only checks lengths and returns success; replace `lms_verify` / `slh_verify` with real implementations.

Build
-----
```bash
gcc -shared -fPIC -o libshrincs.so shrincs.c
# macOS
cc -dynamiclib -o libshrincs.dylib shrincs.c
```

Use with Rust
-------------
```bash
export SHRINCS_LIB_PATH=/full/path/to/libshrincs.so   # or .dylib/.dll
cargo test --features shrincs-ffi
cargo run --features shrincs-ffi --bin qpb-cli -- 3 207fffff
```

Notes
-----
- ABI: `int shrincs_verify(const uint8_t* msg, size_t msglen, const uint8_t* pk, size_t pklen, const uint8_t* sig, size_t siglen)`.
- QPB expects pk=64 bytes, sig=324 bytes, msg=32 bytes.
- Stub behavior: succeeds if lengths match and LMS state index (sig[0..3], big endian) < 1024; otherwise falls back to SLH stub (length check). `sig[0..3]` are the 4-byte LMS leaf index; set ≥1024 to simulate state loss and force SLH fallback.
- If the library is absent or fails to load, the Rust code falls back to the Rust length-check stub.

Replacing stubs with real crypto
--------------------------------
- LMS: link a real liblms (e.g., https://github.com/rustyrussell/lms or other C port) and map `lms_verify(msg, msglen, pk, 32, sig, 162)`.
- SLH: use liboqs SPHINCS+ (SLH-DSA) and map `slh_verify(msg, msglen, pk, 32, sig, 162)` to a selected parameter set.
- Keep the `shrincs_verify` ABI and 64/324-byte sizes, or adjust Rust constants if the real scheme sizes differ.
