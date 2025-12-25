// shrincs.c - SHRINCS prototype (LMS + SLH fallback with state simulation)
// Dev stub: length checks plus a simple LMS state index in sig[0..3] (big endian) with MAX_INDEX bound.
// Replace lms_verify/slh_verify with real implementations for production.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Max allowed index (simulates LMS one-time state); reuse beyond this fails.
#define MAX_INDEX 1024

// Placeholder LMS verify (length/state check only)
int lms_verify(const uint8_t* msg, size_t msglen, const uint8_t* pk, size_t pklen, const uint8_t* sig, size_t siglen) {
    (void)msg;
    (void)msglen;
    if (pklen != 32 || siglen != 162) return 0;
    uint32_t index = ((uint32_t)sig[0] << 24) | ((uint32_t)sig[1] << 16) | ((uint32_t)sig[2] << 8) | sig[3];
    return (index < MAX_INDEX);
}

// Placeholder SLH verify (length check only)
int slh_verify(const uint8_t* msg, size_t msglen, const uint8_t* pk, size_t pklen, const uint8_t* sig, size_t siglen) {
    (void)msg;
    (void)msglen;
    return (pklen == 32 && siglen == 162) ? 1 : 0;
}

// Exported SHRINCS verifier: expects pk=64 bytes, sig=324 bytes, msg arbitrary (32 bytes in QPB)
// Returns 1 on success, 0 on failure.
int shrincs_verify(const uint8_t* msg, size_t msglen, const uint8_t* pk, size_t pklen, const uint8_t* sig, size_t siglen) {
    if (pklen != 64 || siglen != 324) return 0;

    const uint8_t* lms_pk = pk;
    const uint8_t* slh_pk = pk + 32;
    const uint8_t* lms_sig = sig;
    const uint8_t* slh_sig = sig + 162;

    if (lms_verify(msg, msglen, lms_pk, 32, lms_sig, 162)) return 1;
    return slh_verify(msg, msglen, slh_pk, 32, slh_sig, 162);
}

// Deterministic keygen stub: pk = 64 bytes derived from a fixed pattern.
int shrincs_keygen(uint8_t* pk, size_t pklen) {
    if (pklen != 64) return 0;
    for (size_t i = 0; i < pklen; i++) {
        pk[i] = (uint8_t)i;
    }
    return 1;
}

// Deterministic sign stub: fills sig with repeated msg bytes; sets sig[0..3]=0 for LMS state.
int shrincs_sign(const uint8_t* msg, size_t msglen, const uint8_t* pk, size_t pklen, uint8_t* sig, size_t siglen) {
    if (pklen != 64 || siglen != 324 || msglen == 0) return 0;
    sig[0] = sig[1] = sig[2] = sig[3] = 0; // state index 0
    for (size_t i = 4; i < siglen; i++) {
        sig[i] = (uint8_t)(msg[i % msglen]);
    }
    return 1;
}
