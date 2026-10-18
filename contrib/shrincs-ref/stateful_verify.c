/* SPDX-License-Identifier: MIT
 *
 * Independent research verifier for the stateful path of the pinned SHRINCS
 * draft. This file is consensus-disabled and not a production backend.
 */

#include <sha256.h>
#include <thash.h>
#include <wots.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PQBTC_SHRINCS_PUBLIC_KEY_BYTES 48U
#define PQBTC_SHRINCS_RANDOMIZER_BYTES 16U
#define PQBTC_SHRINCS_LEAF_INDEX_BYTES 8U
#define PQBTC_SHRINCS_HEADER_BYTES 24U
#define PQBTC_SHRINCS_FXMSS_HEIGHT 255U
#define PQBTC_SHRINCS_NODE_BYTES 16U
#define PQBTC_SHRINCS_MIN_LEAF_DEPTH 1U
#define PQBTC_SHRINCS_MAX_LEAF_DEPTH 255U
#define PQBTC_SHRINCS_MIN_STATEFUL_SIGNATURE_BYTES 554U
#define PQBTC_SHRINCS_MAX_STATEFUL_SIGNATURE_BYTES 4618U
#define PQBTC_SHRINCS_MAX_MESSAGE_BYTES 4096U
#define PQBTC_SHRINCS_SF_FXMSS_TREE 18U

static uint64_t read_u64_be(const uint8_t in[8])
{
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < 8; ++i) {
        value = (value << 8) | (uint64_t)in[i];
    }
    return value;
}

static void write_u64_be(uint8_t out[8], uint64_t value)
{
    size_t i;
    for (i = 0; i < 8; ++i) {
        out[7U - i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static int equal_16(const uint8_t left[16], const uint8_t right[16])
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < 16; ++i) {
        difference |= (uint8_t)(left[i] ^ right[i]);
    }
    return difference == 0;
}

static int compute_stateful_message_digest(uint8_t out[32],
                                           const uint8_t randomizer[16],
                                           const uint8_t pk_seed[16],
                                           const uint8_t stateless_root[16],
                                           const uint8_t stateful_root[16],
                                           const uint8_t address_prefix[9],
                                           const uint8_t *message,
                                           size_t message_len,
                                           const uint8_t *context,
                                           size_t context_len)
{
    uint8_t inner_hash[32];
    uint8_t outer_input[73];
    uint8_t *inner_input;
    size_t inner_len;
    size_t offset = 0;

    if (context_len > 255U || message_len > PQBTC_SHRINCS_MAX_MESSAGE_BYTES) {
        return 0;
    }
    if ((message_len > 0U && message == NULL) || (context_len > 0U && context == NULL)) {
        return 0;
    }
    if (message_len > SIZE_MAX - context_len - 75U) {
        return 0;
    }

    inner_len = 75U + context_len + message_len;
    inner_input = (uint8_t *)malloc(inner_len);
    if (inner_input == NULL) {
        return 0;
    }

    memcpy(inner_input + offset, randomizer, 16U);
    offset += 16U;
    memcpy(inner_input + offset, pk_seed, 16U);
    offset += 16U;
    memcpy(inner_input + offset, stateful_root, 16U);
    offset += 16U;
    memcpy(inner_input + offset, address_prefix, 9U);
    offset += 9U;
    inner_input[offset++] = 0U;
    inner_input[offset++] = (uint8_t)context_len;
    if (context_len > 0U) {
        memcpy(inner_input + offset, context, context_len);
        offset += context_len;
    }
    memcpy(inner_input + offset, stateless_root, 16U);
    offset += 16U;
    if (message_len > 0U) {
        memcpy(inner_input + offset, message, message_len);
        offset += message_len;
    }

    if (offset != inner_len) {
        free(inner_input);
        return 0;
    }
    shrincs_sha256(inner_hash, inner_input, inner_len);
    free(inner_input);

    offset = 0;
    memcpy(outer_input + offset, randomizer, 16U);
    offset += 16U;
    memcpy(outer_input + offset, pk_seed, 16U);
    offset += 16U;
    memcpy(outer_input + offset, address_prefix, 9U);
    offset += 9U;
    memcpy(outer_input + offset, inner_hash, 32U);
    offset += 32U;
    if (offset != sizeof(outer_input)) {
        return 0;
    }
    shrincs_sha256(out, outer_input, sizeof(outer_input));
    return 1;
}

/* Returns 1 for a valid stateful signature and 0 for invalid input/signature.
 * This is a narrow research ABI, not a production or consensus API.
 */
int pqbtc_shrincs_stateful_verify(const uint8_t *public_key,
                                  size_t public_key_len,
                                  const uint8_t *signature,
                                  size_t signature_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  const uint8_t *context,
                                  size_t context_len)
{
    const uint8_t *pk_seed;
    const uint8_t *stateless_root;
    const uint8_t *stateful_root;
    const uint8_t *randomizer;
    const uint8_t *wots_signature;
    const uint8_t *authentication_path;
    uint8_t address[SHRINCS_WOTS_ADDR_BYTES] = {0};
    uint8_t digest[SHRINCS_WOTS_MSG_BYTES];
    uint8_t node[PQBTC_SHRINCS_NODE_BYTES];
    uint8_t hash_input[2U * PQBTC_SHRINCS_NODE_BYTES];
    uint64_t leaf_index;
    size_t fxmss_len;
    size_t authentication_len;
    size_t leaf_depth;
    size_t k;

    if (public_key == NULL || signature == NULL) {
        return 0;
    }
    if (public_key_len != PQBTC_SHRINCS_PUBLIC_KEY_BYTES) {
        return 0;
    }
    if (signature_len < PQBTC_SHRINCS_MIN_STATEFUL_SIGNATURE_BYTES ||
        signature_len > PQBTC_SHRINCS_MAX_STATEFUL_SIGNATURE_BYTES) {
        return 0;
    }

    fxmss_len = signature_len - PQBTC_SHRINCS_HEADER_BYTES;
    if (fxmss_len < SHRINCS_WOTS_SIG_BYTES) {
        return 0;
    }
    authentication_len = fxmss_len - SHRINCS_WOTS_SIG_BYTES;
    if (authentication_len % PQBTC_SHRINCS_NODE_BYTES != 0U) {
        return 0;
    }
    leaf_depth = authentication_len / PQBTC_SHRINCS_NODE_BYTES;
    if (leaf_depth < PQBTC_SHRINCS_MIN_LEAF_DEPTH ||
        leaf_depth > PQBTC_SHRINCS_MAX_LEAF_DEPTH) {
        return 0;
    }

    pk_seed = public_key;
    stateless_root = public_key + 16U;
    stateful_root = public_key + 32U;
    randomizer = signature;
    leaf_index = read_u64_be(signature + PQBTC_SHRINCS_RANDOMIZER_BYTES);
    if (leaf_depth < 64U && leaf_index >= (((uint64_t)1U) << leaf_depth)) {
        return 0;
    }

    address[0] = (uint8_t)(PQBTC_SHRINCS_FXMSS_HEIGHT - leaf_depth);
    write_u64_be(address + 1U, leaf_index);
    if (!compute_stateful_message_digest(digest,
                                         randomizer,
                                         pk_seed,
                                         stateless_root,
                                         stateful_root,
                                         address,
                                         message,
                                         message_len,
                                         context,
                                         context_len)) {
        return 0;
    }

    wots_signature = signature + PQBTC_SHRINCS_HEADER_BYTES;
    authentication_path = wots_signature + SHRINCS_WOTS_SIG_BYTES;
    if (shrincs_wots_pubkey_from_sig(node, wots_signature, digest, pk_seed, address) !=
        SHRINCS_WOTS_OK) {
        return 0;
    }

    address[9] = PQBTC_SHRINCS_SF_FXMSS_TREE;
    memset(address + 10U, 0, 12U);

    for (k = 0; k < leaf_depth; ++k) {
        const uint8_t *sibling = authentication_path + k * PQBTC_SHRINCS_NODE_BYTES;
        uint64_t parent_index = 0;
        int leaf_is_right = 0;

        address[0] = (uint8_t)(address[0] + 1U);
        if (k + 1U < 64U) {
            parent_index = leaf_index >> (k + 1U);
        }
        write_u64_be(address + 1U, parent_index);

        if (k < 64U) {
            leaf_is_right = (int)((leaf_index >> k) & 1U);
        }
        if (leaf_is_right) {
            memcpy(hash_input, sibling, PQBTC_SHRINCS_NODE_BYTES);
            memcpy(hash_input + PQBTC_SHRINCS_NODE_BYTES, node, PQBTC_SHRINCS_NODE_BYTES);
        } else {
            memcpy(hash_input, node, PQBTC_SHRINCS_NODE_BYTES);
            memcpy(hash_input + PQBTC_SHRINCS_NODE_BYTES, sibling, PQBTC_SHRINCS_NODE_BYTES);
        }
        shrincs_thash(node, pk_seed, address, hash_input, sizeof(hash_input));
    }

    return equal_16(node, stateful_root);
}
