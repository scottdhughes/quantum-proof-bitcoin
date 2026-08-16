/* SPDX-License-Identifier: MIT
 *
 * libFuzzer entry point for the consensus-disabled full SHRINCS verifier.
 */

#include <stddef.h>
#include <stdint.h>

#define HEADER_BYTES 7U
#define MAX_PUBLIC_KEY_BYTES 64U
#define MAX_SIGNATURE_BYTES 6000U
#define MAX_MESSAGE_BYTES 4097U
#define MAX_CONTEXT_BYTES 256U

int pqbtc_shrincs_verify(const uint8_t *public_key,
                         size_t public_key_len,
                         const uint8_t *signature,
                         size_t signature_len,
                         const uint8_t *message,
                         size_t message_len,
                         const uint8_t *context,
                         size_t context_len);

static size_t read_u16_be(const uint8_t *input)
{
    return ((size_t)input[0] << 8) | (size_t)input[1];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t public_key_len;
    size_t signature_len;
    size_t message_len;
    size_t context_len;
    size_t required;
    const uint8_t *cursor;
    const uint8_t *public_key;
    const uint8_t *signature;
    const uint8_t *message;
    const uint8_t *context;

    if (data == NULL || size < HEADER_BYTES) {
        return 0;
    }

    public_key_len = data[0];
    signature_len = read_u16_be(data + 1U);
    message_len = read_u16_be(data + 3U);
    context_len = read_u16_be(data + 5U);
    if (public_key_len > MAX_PUBLIC_KEY_BYTES ||
        signature_len > MAX_SIGNATURE_BYTES ||
        message_len > MAX_MESSAGE_BYTES ||
        context_len > MAX_CONTEXT_BYTES) {
        return 0;
    }
    if (public_key_len > SIZE_MAX - signature_len ||
        public_key_len + signature_len > SIZE_MAX - message_len ||
        public_key_len + signature_len + message_len > SIZE_MAX - context_len ||
        HEADER_BYTES > SIZE_MAX - public_key_len - signature_len - message_len - context_len) {
        return 0;
    }
    required = HEADER_BYTES + public_key_len + signature_len + message_len + context_len;
    if (required != size) {
        return 0;
    }

    cursor = data + HEADER_BYTES;
    public_key = cursor;
    cursor += public_key_len;
    signature = cursor;
    cursor += signature_len;
    message = cursor;
    cursor += message_len;
    context = cursor;

    (void)pqbtc_shrincs_verify(
        public_key_len == 0U ? NULL : public_key,
        public_key_len,
        signature_len == 0U ? NULL : signature,
        signature_len,
        message_len == 0U ? NULL : message,
        message_len,
        context_len == 0U ? NULL : context,
        context_len);
    return 0;
}
