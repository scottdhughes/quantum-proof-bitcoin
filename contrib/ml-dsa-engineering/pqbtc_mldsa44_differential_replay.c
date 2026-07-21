// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PQBTC_MLDSA44_FUZZ_MAX_FRAME_BYTES 8096U

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size)
{
    (void)data;
    (void)max_size;
    return size;
}

static int ReplayFile(const char* program, const char* path)
{
    uint8_t input[PQBTC_MLDSA44_FUZZ_MAX_FRAME_BYTES + 1U];
    FILE* stream;
    size_t input_size;
    int saved_errno;

    errno = 0;
    stream = fopen(path, "rb");
    if (stream == NULL) {
        saved_errno = errno;
        fprintf(
            stderr,
            "%s: cannot open %s: %s\n",
            program,
            path,
            strerror(saved_errno));
        return 0;
    }

    errno = 0;
    input_size = fread(input, 1, sizeof(input), stream);
    if (ferror(stream)) {
        saved_errno = errno;
        if (saved_errno != 0) {
            fprintf(
                stderr,
                "%s: cannot read %s: %s\n",
                program,
                path,
                strerror(saved_errno));
        } else {
            fprintf(stderr, "%s: cannot read %s\n", program, path);
        }
        (void)fclose(stream);
        return 0;
    }
    if (input_size > PQBTC_MLDSA44_FUZZ_MAX_FRAME_BYTES) {
        fprintf(
            stderr,
            "%s: input exceeds %u bytes: %s\n",
            program,
            (unsigned int)PQBTC_MLDSA44_FUZZ_MAX_FRAME_BYTES,
            path);
        (void)fclose(stream);
        return 0;
    }
    if (fclose(stream) != 0) {
        saved_errno = errno;
        fprintf(
            stderr,
            "%s: cannot close %s: %s\n",
            program,
            path,
            strerror(saved_errno));
        return 0;
    }

    if (LLVMFuzzerTestOneInput(input, input_size) != 0) {
        fprintf(stderr, "%s: fuzz target returned a failure for %s\n", program, path);
        return 0;
    }
    return 1;
}

int main(int argc, char** argv)
{
    int index;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <fuzz-input> [<fuzz-input> ...]\n", argv[0]);
        return 2;
    }
    for (index = 1; index < argc; ++index) {
        if (!ReplayFile(argv[0], argv[index])) return 1;
    }
    printf("replayed %d ML-DSA-44 fuzz input(s)\n", argc - 1);
    return 0;
}
