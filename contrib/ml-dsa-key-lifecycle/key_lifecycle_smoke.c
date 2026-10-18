// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include "key_lifecycle.h"

#include <stdio.h>
#include <string.h>

#ifdef PQBTC_MLDSA44_TESTING
#include "../ml-dsa-engineering/pqbtc_mldsa44_test.h"
#include "key_lifecycle_test.h"
#endif

static int failures;
static int checks;
#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int IsZero(const uint8_t* data, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) if (data[i] != 0) return 0;
    return 1;
}

/* Public deterministic fixture, never a real wallet seed. */
static const uint8_t SEED[32] = {
    0xd7, 0x13, 0x61, 0xc0, 0x00, 0xf9, 0xa7, 0xbc,
    0x99, 0xdf, 0xb4, 0x25, 0xbc, 0xb6, 0xbb, 0x27,
    0xc3, 0x2c, 0x36, 0xab, 0x44, 0x4f, 0xf3, 0x70,
    0x8b, 0x2d, 0x93, 0xb4, 0xe6, 0x6d, 0x5b, 0x5b,
};

int main(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    struct pqbtc_mldsa44_key* restored = NULL;
    struct pqbtc_mldsa44_key* original;
    uint8_t public_key[1312] = {0};
    uint8_t restored_public[1312] = {0};
    uint8_t backup[32] = {0};
    uint8_t signature[2420];
    uint8_t second_signature[2420];
    uint8_t message[32] = {1};
    uint8_t context[] = "PQBTC/tx-signature/v1";
#ifdef PQBTC_MLDSA44_TESTING
    uint8_t randomizer[32];
    memset(randomizer, 0x7a, sizeof(randomizer));
    pqbtc_mldsa44_test_reset();
#endif
    if (pqbtc_mldsa44_key_import_seed(NULL, SEED, sizeof(SEED)) != -1) {
        fprintf(stderr, "FAIL invalid owner must reject as invalid argument\n");
        ++failures;
    }
    if (pqbtc_mldsa44_key_import_seed(&key, SEED, sizeof(SEED)) != 0 || key == NULL) {
        fprintf(stderr, "FAIL valid seed must construct an owned key\n");
        ++failures;
    }
    if (key == NULL) return 1;
    original = key;
    CHECK(pqbtc_mldsa44_key_import_seed(&key, SEED, 32) == -1);
    CHECK(key == original);
    CHECK(pqbtc_mldsa44_key_import_seed(&restored, SEED, 31) == -1);
    CHECK(restored == NULL);
    CHECK(pqbtc_mldsa44_key_import_seed(&restored, NULL, 32) == -1);
    CHECK(pqbtc_mldsa44_key_public(key, public_key, sizeof(public_key)) == 0);
    CHECK(!IsZero(public_key, sizeof(public_key)));
    CHECK(pqbtc_mldsa44_key_export_seed(key, backup, sizeof(backup)) == 0);
    CHECK(memcmp(backup, SEED, sizeof(backup)) == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&restored, backup, sizeof(backup)) == 0);
    CHECK(pqbtc_mldsa44_key_public(restored, restored_public, sizeof(restored_public)) == 0);
    CHECK(memcmp(public_key, restored_public, sizeof(public_key)) == 0);

    memset(backup, 0xa5, sizeof(backup));
    CHECK(pqbtc_mldsa44_key_export_seed(key, backup, 31) == -1);
    CHECK(backup[0] == 0xa5 && backup[31] == 0xa5);
    CHECK(pqbtc_mldsa44_key_public(key, (uint8_t*)key, sizeof(public_key)) == -1);
    CHECK(pqbtc_mldsa44_key_export_seed(key, (uint8_t*)key, 32) == -1);
    CHECK(pqbtc_mldsa44_key_public(key, restored_public, sizeof(restored_public)) == 0);
    CHECK(memcmp(public_key, restored_public, sizeof(public_key)) == 0);
#ifdef PQBTC_MLDSA44_TESTING
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
#endif
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == 0);
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == 0);
#ifdef PQBTC_MLDSA44_TESTING
    randomizer[0] ^= 1;
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
#endif
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, second_signature, sizeof(second_signature),
        message, sizeof(message), context, sizeof(context) - 1) == 0);
    CHECK(memcmp(signature, second_signature, sizeof(signature)) != 0);
    CHECK(pqbtc_mldsa44_key_verify_strict(second_signature, sizeof(second_signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == 0);
    restored_public[0] ^= 1;
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        restored_public, sizeof(restored_public), message, sizeof(message), context, sizeof(context) - 1) == -9);
    message[0] ^= 1;
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == -9);
    message[0] ^= 1;
    context[0] ^= 1;
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == -9);
    context[0] ^= 1;
    signature[0] ^= 1;
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == -9);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, (uint8_t*)key, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == -1);
    CHECK(pqbtc_mldsa44_key_public(key, restored_public, sizeof(restored_public)) == 0);
    CHECK(memcmp(public_key, restored_public, sizeof(public_key)) == 0);
    memset(signature, 0xa5, sizeof(signature));
    CHECK(pqbtc_mldsa44_key_sign_hedged(NULL, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == -1);
    CHECK(IsZero(signature, sizeof(signature)));
    pqbtc_mldsa44_key_destroy(&key);
    pqbtc_mldsa44_key_destroy(&restored);
    CHECK(key == NULL && restored == NULL);
    pqbtc_mldsa44_key_destroy(&key);
    pqbtc_mldsa44_key_destroy(NULL);
#ifdef PQBTC_MLDSA44_TESTING
    pqbtc_mldsa44_key_test_reset();
    pqbtc_mldsa44_key_test_fail_allocation(1);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, SEED, 32) == -11);
    CHECK(key == NULL);
    pqbtc_mldsa44_key_destroy(&key);
    pqbtc_mldsa44_key_test_fail_allocation(0);
    pqbtc_mldsa44_key_test_fail_keygen(1);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, SEED, 32) == -6);
    CHECK(key == NULL);
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(pqbtc_mldsa44_key_test_releases() >= 1);
    CHECK(pqbtc_mldsa44_key_test_release_zero() == 1);
    pqbtc_mldsa44_key_test_fail_keygen(0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -2);
    CHECK(key == NULL);
    CHECK(pqbtc_mldsa44_key_test_seed_zero() == 1);
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 31) == 0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -3);
    CHECK(key == NULL);
    memset(randomizer, 0, sizeof(randomizer));
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -4);
    CHECK(key == NULL);
    memset(randomizer, 0x63, sizeof(randomizer));
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == 0);
    CHECK(key != NULL);
    CHECK(pqbtc_mldsa44_key_test_seed_zero() == 1);
    /* Generation and signing must not share the same repeat-digest state. */
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == 0);
    CHECK(pqbtc_mldsa44_key_generate(&restored) == -5);
    CHECK(restored == NULL);
    CHECK(pqbtc_mldsa44_key_export_seed(key, backup, 32) == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&restored, backup, 32) == 0);
    CHECK(pqbtc_mldsa44_key_public(key, public_key, sizeof(public_key)) == 0);
    CHECK(pqbtc_mldsa44_key_public(restored, restored_public, sizeof(restored_public)) == 0);
    CHECK(memcmp(public_key, restored_public, sizeof(public_key)) == 0);
    pqbtc_mldsa44_key_destroy(&key);
    pqbtc_mldsa44_key_destroy(&restored);
    CHECK(pqbtc_mldsa44_key_test_release_zero() == 1);
    /* An accepted generation sample is consumed even when allocation fails. */
    randomizer[0] ^= 1;
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
    pqbtc_mldsa44_key_test_fail_allocation(1);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -11);
    CHECK(key == NULL);
    CHECK(pqbtc_mldsa44_key_test_seed_zero() == 1);
    pqbtc_mldsa44_key_test_fail_allocation(0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -5);
    CHECK(key == NULL);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, SEED, 32) == 0);
    /* Failures after accepting a signature output must clear the entire output. */
    pqbtc_mldsa44_test_reset();
    memset(signature, 0xa5, sizeof(signature));
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == -2);
    CHECK(IsZero(signature, sizeof(signature)));
    CHECK(pqbtc_mldsa44_test_set_entropy(1, randomizer, 32) == 0);
    pqbtc_mldsa44_test_force_backend_result(-1);
    memset(signature, 0xa5, sizeof(signature));
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == -6);
    CHECK(IsZero(signature, sizeof(signature)));
    pqbtc_mldsa44_key_destroy(&key);
    /* Generation/import must honor the existing module lifecycle gate too. */
    pqbtc_mldsa44_test_force_fork_lifecycle_failure(1);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -10);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, SEED, 32) == -10);
    CHECK(key == NULL);
    pqbtc_mldsa44_test_force_fork_lifecycle_failure(0);
#else
    CHECK(pqbtc_mldsa44_key_generate(&key) == 0);
    CHECK(key != NULL);
    CHECK(pqbtc_mldsa44_key_public(key, public_key, sizeof(public_key)) == 0);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, sizeof(signature),
        message, sizeof(message), context, sizeof(context) - 1) == 0);
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), message, sizeof(message), context, sizeof(context) - 1) == 0);
    pqbtc_mldsa44_key_destroy(&key);
#endif
    /* Backup is an intentional caller-owned copy; the caller wipes it. */
    memset(backup, 0, sizeof(backup));
    if (!failures) printf("key lifecycle smoke: PASS (%d checks)\n", checks);
    return failures ? 1 : 0;
}
