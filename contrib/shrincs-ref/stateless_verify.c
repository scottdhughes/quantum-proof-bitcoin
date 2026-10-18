/* SPDX-License-Identifier: MIT
 *
 * Independent research verifier for the stateless recovery path of the pinned
 * SHRINCS draft. This file is consensus-disabled and not a production backend.
 */

#include <sha256.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PQBTC_SHRINCS_PUBLIC_KEY_BYTES 48U
#define PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES 5776U
#define PQBTC_SHRINCS_NODE_BYTES 16U
#define PQBTC_SHRINCS_MAX_MESSAGE_BYTES 4096U

#define PQBTC_WOTS_TW_CHAIN_BITS 4U
#define PQBTC_WOTS_TW_CHAIN_COUNT1 32U
#define PQBTC_WOTS_TW_CHAIN_COUNT2 3U
#define PQBTC_WOTS_TW_CHAIN_COUNT 35U
#define PQBTC_WOTS_TW_SIGNATURE_BYTES 560U
#define PQBTC_WOTS_TW_CHECKSUM_MAX 480U

#define PQBTC_SPHX_LAYER_COUNT 5U
#define PQBTC_SPHX_XMSS_HEIGHT 9U
#define PQBTC_SPHX_XMSS_SIGNATURE_BYTES 704U
#define PQBTC_SPHX_HYPERTREE_SIGNATURE_BYTES 3520U
#define PQBTC_SPHX_FORS_HEIGHT 13U
#define PQBTC_SPHX_FORS_COUNT 10U
#define PQBTC_SPHX_FORS_DIGEST_BYTES 17U
#define PQBTC_SPHX_FORS_SIGNATURE_BYTES 2240U
#define PQBTC_SPHX_TREE_INDEX_BITS 36U

#define PQBTC_SL_WOTS_TW_HASH 0U
#define PQBTC_SL_WOTS_TW_PK 1U
#define PQBTC_SL_XMSS_TREE 2U
#define PQBTC_SL_FORS_TREE 3U
#define PQBTC_SL_FORS_ROOTS 4U

#define PQBTC_ADRS_BYTES 22U
#define PQBTC_THASH_MAX_MESSAGE_BYTES 560U
#define PQBTC_THASH_BUFFER_BYTES (16U + 48U + PQBTC_ADRS_BYTES + PQBTC_THASH_MAX_MESSAGE_BYTES)

static void write_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void write_u64_be(uint8_t out[8], uint64_t value)
{
    size_t i;
    for (i = 0; i < 8U; ++i) {
        out[7U - i] = (uint8_t)(value & 0xffU);
        value >>= 8;
    }
}

static uint64_t read_be(const uint8_t *input, size_t length)
{
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < length; ++i) {
        value = (value << 8) | (uint64_t)input[i];
    }
    return value;
}

static int equal_16(const uint8_t left[16], const uint8_t right[16])
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < 16U; ++i) {
        difference |= (uint8_t)(left[i] ^ right[i]);
    }
    return difference == 0U;
}

static int base_2b(const uint8_t *input,
                   size_t input_len,
                   unsigned bits_per_value,
                   size_t output_len,
                   uint32_t *output)
{
    uint64_t accumulator = 0;
    unsigned bits_filled = 0;
    uint64_t value_mask;
    size_t input_offset = 0;
    size_t i;

    if (input == NULL || output == NULL || bits_per_value == 0U || bits_per_value > 31U) {
        return 0;
    }
    if (output_len > (SIZE_MAX - 7U) / bits_per_value) {
        return 0;
    }
    if (input_len < (output_len * bits_per_value + 7U) / 8U) {
        return 0;
    }

    value_mask = (((uint64_t)1U) << bits_per_value) - 1U;
    for (i = 0; i < output_len; ++i) {
        while (bits_filled < bits_per_value) {
            accumulator = (accumulator << 8) | input[input_offset++];
            bits_filled += 8U;
        }
        bits_filled -= bits_per_value;
        output[i] = (uint32_t)((accumulator >> bits_filled) & value_mask);
        if (bits_filled == 0U) {
            accumulator = 0;
        } else {
            accumulator &= (((uint64_t)1U) << bits_filled) - 1U;
        }
    }
    return 1;
}

static int thash(uint8_t out[16],
                 const uint8_t pk_seed[16],
                 const uint8_t address[PQBTC_ADRS_BYTES],
                 const uint8_t *message,
                 size_t message_len)
{
    uint8_t buffer[PQBTC_THASH_BUFFER_BYTES];
    uint8_t digest[32];
    size_t offset = 0;

    if (out == NULL || pk_seed == NULL || address == NULL) {
        return 0;
    }
    if (message_len > PQBTC_THASH_MAX_MESSAGE_BYTES ||
        (message_len > 0U && message == NULL)) {
        return 0;
    }

    memcpy(buffer + offset, pk_seed, 16U);
    offset += 16U;
    memset(buffer + offset, 0, 48U);
    offset += 48U;
    memcpy(buffer + offset, address, PQBTC_ADRS_BYTES);
    offset += PQBTC_ADRS_BYTES;
    if (message_len > 0U) {
        memcpy(buffer + offset, message, message_len);
        offset += message_len;
    }
    shrincs_sha256(digest, buffer, offset);
    memcpy(out, digest, 16U);
    return 1;
}

static int compute_stateless_digest(uint8_t digest[32],
                                    const uint8_t randomizer[16],
                                    const uint8_t pk_seed[16],
                                    const uint8_t stateless_root[16],
                                    const uint8_t stateful_root[16],
                                    const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *context,
                                    size_t context_len)
{
    uint8_t inner_hash[32];
    uint8_t outer_input[68];
    uint8_t *inner_input;
    size_t inner_len;
    size_t offset = 0;

    if (context_len > 255U || message_len > PQBTC_SHRINCS_MAX_MESSAGE_BYTES) {
        return 0;
    }
    if ((message_len > 0U && message == NULL) || (context_len > 0U && context == NULL)) {
        return 0;
    }
    if (message_len > SIZE_MAX - context_len - 66U) {
        return 0;
    }

    inner_len = 66U + context_len + message_len;
    inner_input = (uint8_t *)malloc(inner_len);
    if (inner_input == NULL) {
        return 0;
    }

    memcpy(inner_input + offset, randomizer, 16U);
    offset += 16U;
    memcpy(inner_input + offset, pk_seed, 16U);
    offset += 16U;
    memcpy(inner_input + offset, stateless_root, 16U);
    offset += 16U;
    inner_input[offset++] = 0U;
    inner_input[offset++] = (uint8_t)context_len;
    if (context_len > 0U) {
        memcpy(inner_input + offset, context, context_len);
        offset += context_len;
    }
    memcpy(inner_input + offset, stateful_root, 16U);
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
    memcpy(outer_input + offset, inner_hash, 32U);
    offset += 32U;
    memset(outer_input + offset, 0, 4U);
    offset += 4U;
    if (offset != sizeof(outer_input)) {
        return 0;
    }
    shrincs_sha256(digest, outer_input, sizeof(outer_input));
    return 1;
}

static void wots_tw_message_indexes(const uint8_t message[16], uint32_t indexes[PQBTC_WOTS_TW_CHAIN_COUNT])
{
    uint32_t checksum = PQBTC_WOTS_TW_CHECKSUM_MAX;
    size_t i;

    for (i = 0; i < PQBTC_WOTS_TW_CHAIN_COUNT1; ++i) {
        uint8_t byte = message[i / 2U];
        uint32_t value = (i % 2U == 0U) ? (uint32_t)(byte >> 4) : (uint32_t)(byte & 0x0fU);
        indexes[i] = value;
        checksum -= value;
    }
    indexes[32] = (checksum >> 8) & 0x0fU;
    indexes[33] = (checksum >> 4) & 0x0fU;
    indexes[34] = checksum & 0x0fU;
}

static int wots_tw_chain(uint8_t node[16],
                         uint32_t start,
                         uint32_t steps,
                         const uint8_t pk_seed[16],
                         uint8_t address[PQBTC_ADRS_BYTES])
{
    uint32_t j;
    uint8_t next[16];

    if (start > 15U || steps > 15U || start + steps > 15U) {
        return 0;
    }
    address[9] = PQBTC_SL_WOTS_TW_HASH;
    for (j = start; j < start + steps; ++j) {
        write_u32_be(address + 18U, j);
        if (!thash(next, pk_seed, address, node, 16U)) {
            return 0;
        }
        memcpy(node, next, 16U);
    }
    return 1;
}

static int wots_tw_public_key_from_signature(uint8_t out[16],
                                             const uint8_t signature[PQBTC_WOTS_TW_SIGNATURE_BYTES],
                                             const uint8_t message[16],
                                             const uint8_t pk_seed[16],
                                             uint8_t address[PQBTC_ADRS_BYTES])
{
    uint32_t indexes[PQBTC_WOTS_TW_CHAIN_COUNT];
    uint8_t chain_tips[PQBTC_WOTS_TW_SIGNATURE_BYTES];
    size_t i;

    wots_tw_message_indexes(message, indexes);
    for (i = 0; i < PQBTC_WOTS_TW_CHAIN_COUNT; ++i) {
        uint8_t *tip = chain_tips + i * 16U;
        memcpy(tip, signature + i * 16U, 16U);
        write_u32_be(address + 14U, (uint32_t)i);
        if (!wots_tw_chain(tip, indexes[i], 15U - indexes[i], pk_seed, address)) {
            return 0;
        }
    }

    address[9] = PQBTC_SL_WOTS_TW_PK;
    memset(address + 14U, 0, 8U);
    return thash(out, pk_seed, address, chain_tips, sizeof(chain_tips));
}

static int xmss_public_key_from_signature(uint8_t out[16],
                                          uint32_t keypair_index,
                                          const uint8_t signature[PQBTC_SPHX_XMSS_SIGNATURE_BYTES],
                                          const uint8_t message[16],
                                          const uint8_t pk_seed[16],
                                          uint8_t address[PQBTC_ADRS_BYTES])
{
    const uint8_t *authentication_path = signature + PQBTC_WOTS_TW_SIGNATURE_BYTES;
    uint8_t node[16];
    uint8_t pair[32];
    size_t k;

    write_u32_be(address + 10U, keypair_index);
    if (!wots_tw_public_key_from_signature(node, signature, message, pk_seed, address)) {
        return 0;
    }

    address[9] = PQBTC_SL_XMSS_TREE;
    memset(address + 10U, 0, 4U);
    for (k = 0; k < PQBTC_SPHX_XMSS_HEIGHT; ++k) {
        const uint8_t *sibling = authentication_path + k * 16U;
        write_u32_be(address + 14U, (uint32_t)(k + 1U));
        write_u32_be(address + 18U, keypair_index >> (k + 1U));
        if (((keypair_index >> k) & 1U) != 0U) {
            memcpy(pair, sibling, 16U);
            memcpy(pair + 16U, node, 16U);
        } else {
            memcpy(pair, node, 16U);
            memcpy(pair + 16U, sibling, 16U);
        }
        if (!thash(node, pk_seed, address, pair, sizeof(pair))) {
            return 0;
        }
    }
    memcpy(out, node, 16U);
    return 1;
}

static int fors_public_key_from_signature(uint8_t out[16],
                                          const uint8_t signature[PQBTC_SPHX_FORS_SIGNATURE_BYTES],
                                          const uint8_t digest[PQBTC_SPHX_FORS_DIGEST_BYTES],
                                          const uint8_t pk_seed[16],
                                          uint8_t address[PQBTC_ADRS_BYTES])
{
    uint32_t indexes[PQBTC_SPHX_FORS_COUNT];
    uint8_t roots[PQBTC_SPHX_FORS_COUNT * 16U];
    uint8_t node[16];
    uint8_t pair[32];
    size_t offset = 0;
    size_t i;

    if (!base_2b(digest,
                 PQBTC_SPHX_FORS_DIGEST_BYTES,
                 PQBTC_SPHX_FORS_HEIGHT,
                 PQBTC_SPHX_FORS_COUNT,
                 indexes)) {
        return 0;
    }

    for (i = 0; i < PQBTC_SPHX_FORS_COUNT; ++i) {
        uint32_t tree_index = (uint32_t)(i * (1U << PQBTC_SPHX_FORS_HEIGHT)) + indexes[i];
        size_t j;

        address[9] = PQBTC_SL_FORS_TREE;
        memset(address + 14U, 0, 4U);
        write_u32_be(address + 18U, tree_index);
        if (!thash(node, pk_seed, address, signature + offset, 16U)) {
            return 0;
        }
        offset += 16U;

        for (j = 0; j < PQBTC_SPHX_FORS_HEIGHT; ++j) {
            const uint8_t *sibling = signature + offset;
            write_u32_be(address + 14U, (uint32_t)(j + 1U));
            write_u32_be(address + 18U, tree_index >> (j + 1U));
            if (((indexes[i] >> j) & 1U) != 0U) {
                memcpy(pair, sibling, 16U);
                memcpy(pair + 16U, node, 16U);
            } else {
                memcpy(pair, node, 16U);
                memcpy(pair + 16U, sibling, 16U);
            }
            if (!thash(node, pk_seed, address, pair, sizeof(pair))) {
                return 0;
            }
            offset += 16U;
        }
        memcpy(roots + i * 16U, node, 16U);
    }

    if (offset != PQBTC_SPHX_FORS_SIGNATURE_BYTES) {
        return 0;
    }
    address[9] = PQBTC_SL_FORS_ROOTS;
    memset(address + 14U, 0, 8U);
    return thash(out, pk_seed, address, roots, sizeof(roots));
}

static int hypertree_verify(const uint8_t message[16],
                            const uint8_t signature[PQBTC_SPHX_HYPERTREE_SIGNATURE_BYTES],
                            const uint8_t pk_seed[16],
                            uint64_t tree_index,
                            uint32_t leaf_index,
                            const uint8_t stateless_root[16])
{
    uint8_t address[PQBTC_ADRS_BYTES] = {0};
    uint8_t node[16];
    size_t layer;

    memcpy(node, message, 16U);
    for (layer = 0; layer < PQBTC_SPHX_LAYER_COUNT; ++layer) {
        address[0] = (uint8_t)layer;
        write_u64_be(address + 1U, tree_index);
        if (!xmss_public_key_from_signature(
                node,
                leaf_index,
                signature + layer * PQBTC_SPHX_XMSS_SIGNATURE_BYTES,
                node,
                pk_seed,
                address)) {
            return 0;
        }
        if (layer + 1U < PQBTC_SPHX_LAYER_COUNT) {
            leaf_index = (uint32_t)(tree_index & ((1U << PQBTC_SPHX_XMSS_HEIGHT) - 1U));
            tree_index >>= PQBTC_SPHX_XMSS_HEIGHT;
        }
    }
    return equal_16(node, stateless_root);
}

/* Returns 1 for a valid stateless signature and 0 for invalid input/signature.
 * This is a narrow research ABI, not a production or consensus API.
 */
int pqbtc_shrincs_stateless_verify(const uint8_t *public_key,
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
    const uint8_t *fors_signature;
    const uint8_t *hypertree_signature;
    uint8_t digest[32];
    uint8_t fors_public_key[16];
    uint8_t address[PQBTC_ADRS_BYTES] = {0};
    uint64_t tree_index;
    uint32_t leaf_index;

    if (public_key == NULL || signature == NULL) {
        return 0;
    }
    if (public_key_len != PQBTC_SHRINCS_PUBLIC_KEY_BYTES ||
        signature_len != PQBTC_SHRINCS_STATELESS_SIGNATURE_BYTES) {
        return 0;
    }

    pk_seed = public_key;
    stateless_root = public_key + 16U;
    stateful_root = public_key + 32U;
    randomizer = signature;
    fors_signature = signature + 16U;
    hypertree_signature = fors_signature + PQBTC_SPHX_FORS_SIGNATURE_BYTES;

    if (!compute_stateless_digest(digest,
                                  randomizer,
                                  pk_seed,
                                  stateless_root,
                                  stateful_root,
                                  message,
                                  message_len,
                                  context,
                                  context_len)) {
        return 0;
    }

    tree_index = read_be(digest + PQBTC_SPHX_FORS_DIGEST_BYTES, 5U) &
                 ((((uint64_t)1U) << PQBTC_SPHX_TREE_INDEX_BITS) - 1U);
    leaf_index = (uint32_t)(read_be(digest + PQBTC_SPHX_FORS_DIGEST_BYTES + 5U, 2U) &
                            ((1U << PQBTC_SPHX_XMSS_HEIGHT) - 1U));

    write_u64_be(address + 1U, tree_index);
    write_u32_be(address + 10U, leaf_index);
    if (!fors_public_key_from_signature(fors_public_key,
                                        fors_signature,
                                        digest,
                                        pk_seed,
                                        address)) {
        return 0;
    }

    return hypertree_verify(fors_public_key,
                            hypertree_signature,
                            pk_seed,
                            tree_index,
                            leaf_index,
                            stateless_root);
}
