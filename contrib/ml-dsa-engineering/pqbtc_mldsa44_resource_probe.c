// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#define _POSIX_C_SOURCE 200809L

#include "pqbtc_mldsa44.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error The ML-DSA-44 resource probe is scoped to Linux x86_64
#endif

#define RESOURCE_SCHEMA_VERSION 1U
#define RESOURCE_BUNDLE_MAGIC "PQRSC001"
#define RESOURCE_BUNDLE_MAGIC_BYTES 8U
#define RESOURCE_BUNDLE_HEADER_BYTES 16U
#define RESOURCE_RECORD_HEADER_BYTES 12U
#define RESOURCE_FRAME_HEADER_BYTES 10U
#define RESOURCE_FRAME_VERSION 1U
#define RESOURCE_MAX_BUNDLE_BYTES (4U * 1024U * 1024U)
#define RESOURCE_EXPECTED_RECORDS 240U
#define RESOURCE_MAX_RECORDS 240U
#define RESOURCE_SAMPLE_COUNT 31U
#define RESOURCE_BATCH_CALLS 4287U
#define RESOURCE_BATCH_COUNT 4U
#define RESOURCE_THREAD_STACK_BYTES 131072U
#define RESOURCE_THREAD_GUARD_BYTES 4096U
#define RESOURCE_ADDRESS_SPACE_BYTES (256U * 1024U * 1024U)
#define RESOURCE_OPEN_FILES 64U
#define RESOURCE_OUTPUT_FILE_BYTES 65536U
#define RESOURCE_CPU_WATCHDOG_SECONDS 120U
#define RESOURCE_WALL_WATCHDOG_SECONDS 180U

#define RESOURCE_FLAG_VALID 0x01U
#define RESOURCE_FLAG_DEEP_REJECT 0x02U
#define RESOURCE_FLAG_SAME_KEY 0x04U
#define RESOURCE_FLAG_FIRST_CALL 0x08U
#define RESOURCE_FLAG_MASK 0x0fU

#define RESOURCE_NULL_SIGNATURE 0x01U
#define RESOURCE_NULL_PUBLIC_KEY 0x02U
#define RESOURCE_NULL_CONTEXT 0x04U
#define RESOURCE_NULL_MESSAGE 0x08U
#define RESOURCE_NULL_MASK 0x0fU

enum resource_batch_id {
    RESOURCE_BATCH_MIXED_ROTATING = 0,
    RESOURCE_BATCH_VALID_ROTATING = 1,
    RESOURCE_BATCH_DEEP_REJECT_ROTATING = 2,
    RESOURCE_BATCH_SAME_KEY_MIXED = 3
};

struct resource_record {
    const uint8_t* frame;
    uint32_t frame_size;
    int32_t expected;
    uint32_t flags;
};

struct resource_frame {
    uint8_t null_flags;
    uint16_t signature_size;
    uint16_t public_key_size;
    uint16_t context_size;
    uint16_t message_size;
    size_t signature_offset;
    size_t public_key_offset;
    size_t context_offset;
    size_t message_offset;
};

struct resource_batch_result {
    uint64_t wall_samples_ns[RESOURCE_SAMPLE_COUNT];
    uint64_t cpu_samples_ns[RESOURCE_SAMPLE_COUNT];
    uint64_t ok;
    uint64_t invalid_argument;
    uint64_t verify_rejection;
};

struct resource_result {
    int failed;
    uint32_t failed_batch;
    uint32_t failed_record;
    int32_t expected;
    int32_t actual;
    uint64_t first_wall_ns;
    uint64_t first_cpu_ns;
    int32_t first_result;
    struct resource_batch_result batches[RESOURCE_BATCH_COUNT];
    uint64_t control_wall_samples_ns[RESOURCE_SAMPLE_COUNT];
    uint64_t control_cpu_samples_ns[RESOURCE_SAMPLE_COUNT];
    uint64_t completed_calls;
};

static uint8_t g_bundle[RESOURCE_MAX_BUNDLE_BYTES];
static size_t g_bundle_size;
static struct resource_record g_records[RESOURCE_MAX_RECORDS];
static uint32_t g_record_count;
static uint32_t g_batch_indices[RESOURCE_BATCH_COUNT][RESOURCE_MAX_RECORDS];
static uint32_t g_batch_record_counts[RESOURCE_BATCH_COUNT];
static uint32_t g_first_record;
static struct resource_result g_result;
static volatile int64_t g_result_accumulator;

static atomic_ulong g_malloc_calls;
static atomic_ulong g_calloc_calls;
static atomic_ulong g_realloc_calls;
static atomic_ulong g_free_calls;
static atomic_ulong g_aligned_alloc_calls;
static atomic_ulong g_posix_memalign_calls;

void* __wrap_malloc(size_t size)
{
    (void)size;
    atomic_fetch_add_explicit(&g_malloc_calls, 1, memory_order_relaxed);
    return NULL;
}

void* __wrap_calloc(size_t count, size_t size)
{
    (void)count;
    (void)size;
    atomic_fetch_add_explicit(&g_calloc_calls, 1, memory_order_relaxed);
    return NULL;
}

void* __wrap_realloc(void* pointer, size_t size)
{
    (void)pointer;
    (void)size;
    atomic_fetch_add_explicit(&g_realloc_calls, 1, memory_order_relaxed);
    return NULL;
}

void __wrap_free(void* pointer)
{
    (void)pointer;
    atomic_fetch_add_explicit(&g_free_calls, 1, memory_order_relaxed);
}

void* __wrap_aligned_alloc(size_t alignment, size_t size)
{
    (void)alignment;
    (void)size;
    atomic_fetch_add_explicit(&g_aligned_alloc_calls, 1, memory_order_relaxed);
    return NULL;
}

int __wrap_posix_memalign(void** output, size_t alignment, size_t size)
{
    (void)alignment;
    (void)size;
    atomic_fetch_add_explicit(&g_posix_memalign_calls, 1, memory_order_relaxed);
    if (output != NULL) *output = NULL;
    return ENOMEM;
}

static int Fail(const char* message)
{
    fprintf(stderr, "ML-DSA-44 resource probe: %s\n", message);
    return 1;
}

static uint16_t ReadU16(const uint8_t* bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t ReadU32(const uint8_t* bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int32_t ReadI32(const uint8_t* bytes)
{
    const uint32_t value = ReadU32(bytes);
    if (value <= (uint32_t)INT32_MAX) return (int32_t)value;
    return -(int32_t)(UINT32_MAX - value) - 1;
}

static uint64_t TimespecNanoseconds(struct timespec value)
{
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static uint64_t ElapsedNanoseconds(struct timespec start, struct timespec end)
{
    const uint64_t start_ns = TimespecNanoseconds(start);
    const uint64_t end_ns = TimespecNanoseconds(end);
    return end_ns >= start_ns ? end_ns - start_ns : 0;
}

static uint64_t BundleHash(void)
{
    uint64_t hash = 14695981039346656037ULL;
    size_t i;
    for (i = 0; i < g_bundle_size; ++i) {
        hash ^= g_bundle[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int ParseFrame(
    const uint8_t* frame_bytes, size_t frame_size, struct resource_frame* frame)
{
    size_t expected_size;

    if (frame_size < RESOURCE_FRAME_HEADER_BYTES ||
        frame_bytes[0] != RESOURCE_FRAME_VERSION ||
        (frame_bytes[1] & ~RESOURCE_NULL_MASK) != 0) {
        return 0;
    }
    frame->null_flags = frame_bytes[1];
    frame->signature_size = ReadU16(frame_bytes + 2);
    frame->public_key_size = ReadU16(frame_bytes + 4);
    frame->context_size = ReadU16(frame_bytes + 6);
    frame->message_size = ReadU16(frame_bytes + 8);
    frame->signature_offset = RESOURCE_FRAME_HEADER_BYTES;
    frame->public_key_offset = frame->signature_offset + frame->signature_size;
    frame->context_offset = frame->public_key_offset + frame->public_key_size;
    frame->message_offset = frame->context_offset + frame->context_size;
    expected_size = frame->message_offset + frame->message_size;
    return expected_size == frame_size;
}

static const uint8_t* MaybeNull(
    const uint8_t* frame,
    size_t offset,
    uint8_t null_flags,
    uint8_t null_flag)
{
    return (null_flags & null_flag) != 0 ? NULL : frame + offset;
}

static int CallRecord(uint32_t index)
{
    struct resource_frame frame;
    const struct resource_record* record = &g_records[index];
    if (!ParseFrame(record->frame, record->frame_size, &frame)) {
        return 1;
    }
    return pqbtc_mldsa44_verify_strict(
        MaybeNull(
            record->frame,
            frame.signature_offset,
            frame.null_flags,
            RESOURCE_NULL_SIGNATURE),
        frame.signature_size,
        MaybeNull(
            record->frame,
            frame.public_key_offset,
            frame.null_flags,
            RESOURCE_NULL_PUBLIC_KEY),
        frame.public_key_size,
        MaybeNull(
            record->frame,
            frame.message_offset,
            frame.null_flags,
            RESOURCE_NULL_MESSAGE),
        frame.message_size,
        MaybeNull(
            record->frame,
            frame.context_offset,
            frame.null_flags,
            RESOURCE_NULL_CONTEXT),
        frame.context_size);
}

static int LoadBundle(const char* path)
{
    FILE* input;
    long file_size;
    size_t received;
    size_t cursor;
    uint32_t i;
    int trailing_byte;
    int close_result;

    input = fopen(path, "rb");
    if (input == NULL) return Fail("cannot open the corpus bundle");
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return Fail("cannot seek the corpus bundle");
    }
    file_size = ftell(input);
    if (file_size < (long)RESOURCE_BUNDLE_HEADER_BYTES ||
        file_size > (long)RESOURCE_MAX_BUNDLE_BYTES ||
        fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return Fail("corpus bundle size is outside the frozen bound");
    }
    g_bundle_size = (size_t)file_size;
    received = fread(g_bundle, 1, g_bundle_size, input);
    trailing_byte = fgetc(input);
    close_result = fclose(input);
    if (received != g_bundle_size || trailing_byte != EOF || close_result != 0) {
        return Fail("cannot read the corpus bundle exactly");
    }
    if (memcmp(g_bundle, RESOURCE_BUNDLE_MAGIC, RESOURCE_BUNDLE_MAGIC_BYTES) != 0 ||
        ReadU32(g_bundle + 8) != RESOURCE_SCHEMA_VERSION) {
        return Fail("corpus bundle header differs");
    }
    g_record_count = ReadU32(g_bundle + 12);
    if (g_record_count != RESOURCE_EXPECTED_RECORDS) {
        return Fail("corpus bundle record count differs");
    }

    cursor = RESOURCE_BUNDLE_HEADER_BYTES;
    for (i = 0; i < g_record_count; ++i) {
        uint32_t frame_size;
        int32_t expected;
        uint32_t flags;
        struct resource_frame parsed;
        if (cursor > g_bundle_size ||
            g_bundle_size - cursor < RESOURCE_RECORD_HEADER_BYTES) {
            return Fail("truncated corpus record header");
        }
        frame_size = ReadU32(g_bundle + cursor);
        expected = ReadI32(g_bundle + cursor + 4);
        flags = ReadU32(g_bundle + cursor + 8);
        cursor += RESOURCE_RECORD_HEADER_BYTES;
        if (frame_size == 0 || frame_size > 8096U ||
            cursor > g_bundle_size || frame_size > g_bundle_size - cursor ||
            (expected != PQBTC_MLDSA44_OK &&
             expected != PQBTC_MLDSA44_ERR_INVALID_ARGUMENT &&
             expected != PQBTC_MLDSA44_ERR_VERIFY) ||
            (flags & ~RESOURCE_FLAG_MASK) != 0 ||
            ((flags & RESOURCE_FLAG_VALID) != 0 &&
             expected != PQBTC_MLDSA44_OK) ||
            ((flags & RESOURCE_FLAG_DEEP_REJECT) != 0 &&
             expected != PQBTC_MLDSA44_ERR_VERIFY)) {
            return Fail("invalid corpus record contract");
        }
        if (!ParseFrame(g_bundle + cursor, frame_size, &parsed)) {
            return Fail("non-canonical corpus frame");
        }
        g_records[i].frame = g_bundle + cursor;
        g_records[i].frame_size = frame_size;
        g_records[i].expected = expected;
        g_records[i].flags = flags;
        cursor += frame_size;
    }
    if (cursor != g_bundle_size) return Fail("corpus bundle has trailing bytes");
    return 0;
}

static int BuildSelections(void)
{
    uint32_t first_count = 0;
    uint32_t i;

    for (i = 0; i < g_record_count; ++i) {
        g_batch_indices[RESOURCE_BATCH_MIXED_ROTATING]
                       [g_batch_record_counts[RESOURCE_BATCH_MIXED_ROTATING]++] = i;
        if ((g_records[i].flags & RESOURCE_FLAG_VALID) != 0) {
            g_batch_indices[RESOURCE_BATCH_VALID_ROTATING]
                           [g_batch_record_counts[RESOURCE_BATCH_VALID_ROTATING]++] = i;
        }
        if ((g_records[i].flags & RESOURCE_FLAG_DEEP_REJECT) != 0) {
            g_batch_indices[RESOURCE_BATCH_DEEP_REJECT_ROTATING]
                           [g_batch_record_counts
                               [RESOURCE_BATCH_DEEP_REJECT_ROTATING]++] = i;
        }
        if ((g_records[i].flags & RESOURCE_FLAG_SAME_KEY) != 0) {
            g_batch_indices[RESOURCE_BATCH_SAME_KEY_MIXED]
                           [g_batch_record_counts[RESOURCE_BATCH_SAME_KEY_MIXED]++] = i;
        }
        if ((g_records[i].flags & RESOURCE_FLAG_FIRST_CALL) != 0) {
            g_first_record = i;
            ++first_count;
        }
    }
    if (g_batch_record_counts[RESOURCE_BATCH_MIXED_ROTATING] !=
            RESOURCE_EXPECTED_RECORDS ||
        g_batch_record_counts[RESOURCE_BATCH_VALID_ROTATING] == 0 ||
        g_batch_record_counts[RESOURCE_BATCH_DEEP_REJECT_ROTATING] == 0 ||
        g_batch_record_counts[RESOURCE_BATCH_SAME_KEY_MIXED] == 0 ||
        first_count != 1 ||
        g_records[g_first_record].expected != PQBTC_MLDSA44_OK) {
        return Fail("corpus batch selection contract differs");
    }
    return 0;
}

static int ApplyLimit(int resource_name, rlim_t soft, rlim_t hard)
{
    struct rlimit limit;
    limit.rlim_cur = soft;
    limit.rlim_max = hard;
    return setrlimit(resource_name, &limit);
}

static int ApplyResourceLimits(void)
{
    if (ApplyLimit(
            RLIMIT_CPU,
            RESOURCE_CPU_WATCHDOG_SECONDS,
            RESOURCE_CPU_WATCHDOG_SECONDS + 1U) != 0 ||
        ApplyLimit(
            RLIMIT_AS,
            RESOURCE_ADDRESS_SPACE_BYTES,
            RESOURCE_ADDRESS_SPACE_BYTES) != 0 ||
        ApplyLimit(RLIMIT_NOFILE, RESOURCE_OPEN_FILES, RESOURCE_OPEN_FILES) != 0 ||
        ApplyLimit(
            RLIMIT_FSIZE,
            RESOURCE_OUTPUT_FILE_BYTES,
            RESOURCE_OUTPUT_FILE_BYTES) != 0 ||
        ApplyLimit(RLIMIT_CORE, 0, 0) != 0) {
        return Fail("cannot apply the frozen process limits");
    }
    return 0;
}

static int RecordOutcome(struct resource_batch_result* batch, int result)
{
    if (result == PQBTC_MLDSA44_OK) {
        ++batch->ok;
    } else if (result == PQBTC_MLDSA44_ERR_INVALID_ARGUMENT) {
        ++batch->invalid_argument;
    } else if (result == PQBTC_MLDSA44_ERR_VERIFY) {
        ++batch->verify_rejection;
    } else {
        return 0;
    }
    return 1;
}

static void* RunResourceProbe(void* unused)
{
    struct timespec wall_start;
    struct timespec wall_end;
    struct timespec cpu_start;
    struct timespec cpu_end;
    uint32_t batch_id;
    uint32_t sample;

    (void)unused;
    if (clock_gettime(CLOCK_MONOTONIC, &wall_start) != 0 ||
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start) != 0) {
        g_result.failed = 1;
        return NULL;
    }
    g_result.first_result = CallRecord(g_first_record);
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &wall_end) != 0) {
        g_result.failed = 1;
        return NULL;
    }
    g_result.first_wall_ns = ElapsedNanoseconds(wall_start, wall_end);
    g_result.first_cpu_ns = ElapsedNanoseconds(cpu_start, cpu_end);
    if (g_result.first_result != g_records[g_first_record].expected) {
        g_result.failed = 1;
        g_result.failed_record = g_first_record;
        g_result.expected = g_records[g_first_record].expected;
        g_result.actual = g_result.first_result;
        return NULL;
    }
    g_result_accumulator ^= g_result.first_result;
    ++g_result.completed_calls;

    for (batch_id = 0; batch_id < RESOURCE_BATCH_COUNT; ++batch_id) {
        uint32_t cursor = 0;
        const uint32_t selected_count = g_batch_record_counts[batch_id];
        for (sample = 0; sample < RESOURCE_SAMPLE_COUNT; ++sample) {
            uint32_t sample_calls =
                RESOURCE_BATCH_CALLS / RESOURCE_SAMPLE_COUNT +
                (sample < RESOURCE_BATCH_CALLS % RESOURCE_SAMPLE_COUNT ? 1U : 0U);
            uint32_t call;
            if (clock_gettime(CLOCK_MONOTONIC, &wall_start) != 0 ||
                clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start) != 0) {
                g_result.failed = 1;
                return NULL;
            }
            for (call = 0; call < sample_calls; ++call) {
                const uint32_t record_index =
                    g_batch_indices[batch_id][cursor % selected_count];
                const int result = CallRecord(record_index);
                ++cursor;
                if (result != g_records[record_index].expected ||
                    !RecordOutcome(&g_result.batches[batch_id], result)) {
                    g_result.failed = 1;
                    g_result.failed_batch = batch_id;
                    g_result.failed_record = record_index;
                    g_result.expected = g_records[record_index].expected;
                    g_result.actual = result;
                    return NULL;
                }
                g_result_accumulator ^= (int64_t)result + (int64_t)record_index;
                ++g_result.completed_calls;
            }
            if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) != 0 ||
                clock_gettime(CLOCK_MONOTONIC, &wall_end) != 0) {
                g_result.failed = 1;
                return NULL;
            }
            g_result.batches[batch_id].wall_samples_ns[sample] =
                ElapsedNanoseconds(wall_start, wall_end);
            g_result.batches[batch_id].cpu_samples_ns[sample] =
                ElapsedNanoseconds(cpu_start, cpu_end);
        }
        if (cursor != RESOURCE_BATCH_CALLS) {
            g_result.failed = 1;
            return NULL;
        }
    }

    for (sample = 0; sample < RESOURCE_SAMPLE_COUNT; ++sample) {
        uint32_t sample_calls =
            RESOURCE_BATCH_CALLS / RESOURCE_SAMPLE_COUNT +
            (sample < RESOURCE_BATCH_CALLS % RESOURCE_SAMPLE_COUNT ? 1U : 0U);
        uint32_t call;
        if (clock_gettime(CLOCK_MONOTONIC, &wall_start) != 0 ||
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start) != 0) {
            g_result.failed = 1;
            return NULL;
        }
        for (call = 0; call < sample_calls; ++call) {
            g_result_accumulator ^=
                (int64_t)g_records[call % g_record_count].expected + (int64_t)call;
        }
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) != 0 ||
            clock_gettime(CLOCK_MONOTONIC, &wall_end) != 0) {
            g_result.failed = 1;
            return NULL;
        }
        g_result.control_wall_samples_ns[sample] =
            ElapsedNanoseconds(wall_start, wall_end);
        g_result.control_cpu_samples_ns[sample] =
            ElapsedNanoseconds(cpu_start, cpu_end);
    }
    return NULL;
}

static void PrintSamples(const uint64_t* samples)
{
    uint32_t i;
    putchar('[');
    for (i = 0; i < RESOURCE_SAMPLE_COUNT; ++i) {
        if (i != 0) putchar(',');
        printf("%llu", (unsigned long long)samples[i]);
    }
    putchar(']');
}

static void PrintBatch(const char* id, const struct resource_batch_result* result)
{
    printf(
        "{\"id\":\"%s\",\"calls\":%u,\"outcomes\":{\"ok\":%llu,"
        "\"invalid_argument\":%llu,\"verify_rejection\":%llu},"
        "\"wall_samples_ns\":",
        id,
        RESOURCE_BATCH_CALLS,
        (unsigned long long)result->ok,
        (unsigned long long)result->invalid_argument,
        (unsigned long long)result->verify_rejection);
    PrintSamples(result->wall_samples_ns);
    printf(",\"cpu_samples_ns\":");
    PrintSamples(result->cpu_samples_ns);
    putchar('}');
}

static unsigned long HeapCallTotal(void)
{
    return atomic_load_explicit(&g_malloc_calls, memory_order_relaxed) +
        atomic_load_explicit(&g_calloc_calls, memory_order_relaxed) +
        atomic_load_explicit(&g_realloc_calls, memory_order_relaxed) +
        atomic_load_explicit(&g_free_calls, memory_order_relaxed) +
        atomic_load_explicit(&g_aligned_alloc_calls, memory_order_relaxed) +
        atomic_load_explicit(&g_posix_memalign_calls, memory_order_relaxed);
}

static int RunHeapPositiveControl(void)
{
    void* pointer;
    atomic_store_explicit(&g_malloc_calls, 0, memory_order_relaxed);
    pointer = malloc(1);
    if (pointer != NULL) {
        free(pointer);
        return Fail("heap interposition positive control returned storage");
    }
    if (atomic_load_explicit(&g_malloc_calls, memory_order_relaxed) != 1 ||
        HeapCallTotal() != 1) {
        return Fail("heap interposition positive control did not trip");
    }
    puts("{\"control\":\"heap_interposition\",\"status\":\"PASS\",\"calls\":1}");
    return 0;
}

static int RunStackConfigurationPositiveControl(void)
{
    pthread_attr_t attributes;
    int result;
    if (pthread_attr_init(&attributes) != 0) {
        return Fail("cannot initialize stack positive control");
    }
    result =
        pthread_attr_setstacksize(&attributes, (size_t)PTHREAD_STACK_MIN - 1U);
    if (pthread_attr_destroy(&attributes) != 0) {
        return Fail("cannot destroy stack positive-control attributes");
    }
    if (result != EINVAL) {
        return Fail("undersized pthread stack was not rejected");
    }
    puts(
        "{\"control\":\"undersized_stack_rejection\","
        "\"status\":\"PASS\"}");
    return 0;
}

static int RunCpuPositiveControl(void)
{
    volatile uint64_t counter = 0;
    if (ApplyLimit(RLIMIT_CORE, 0, 0) != 0 ||
        ApplyLimit(RLIMIT_CPU, 1, 2) != 0) {
        return Fail("cannot apply CPU positive-control limits");
    }
    alarm(5);
    for (;;) {
        ++counter;
    }
}

static int RunWallPositiveControl(void)
{
    if (ApplyLimit(RLIMIT_CORE, 0, 0) != 0) {
        return Fail("cannot apply wall positive-control limits");
    }
    alarm(1);
    for (;;) {
        pause();
    }
}

int main(int argc, char** argv)
{
    static const char* batch_names[RESOURCE_BATCH_COUNT] = {
        "mixed_rotating",
        "valid_rotating",
        "deep_reject_rotating",
        "same_key_mixed",
    };
    pthread_attr_t attributes;
    pthread_t worker;
    struct timespec monotonic_resolution;
    struct timespec cpu_resolution;
    struct rusage usage;
    uint64_t input_hash_before;
    uint64_t input_hash_after;
    size_t stack_size = 0;
    size_t guard_size = 0;
    uint32_t i;

    if (argc != 2) return Fail("expected exactly one corpus-bundle path");
    if (strcmp(argv[1], "--heap-positive-control") == 0) {
        return RunHeapPositiveControl();
    }
    if (strcmp(argv[1], "--stack-positive-control") == 0) {
        return RunStackConfigurationPositiveControl();
    }
    if (strcmp(argv[1], "--cpu-positive-control") == 0) {
        return RunCpuPositiveControl();
    }
    if (strcmp(argv[1], "--wall-positive-control") == 0) {
        return RunWallPositiveControl();
    }
    if (LoadBundle(argv[1]) != 0 || BuildSelections() != 0) return 1;
    input_hash_before = BundleHash();

    atomic_store_explicit(&g_malloc_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_calloc_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_realloc_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_free_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_aligned_alloc_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&g_posix_memalign_calls, 0, memory_order_relaxed);

    if (ApplyResourceLimits() != 0 ||
        clock_getres(CLOCK_MONOTONIC, &monotonic_resolution) != 0 ||
        clock_getres(CLOCK_THREAD_CPUTIME_ID, &cpu_resolution) != 0 ||
        pthread_attr_init(&attributes) != 0 ||
        pthread_attr_setstacksize(&attributes, RESOURCE_THREAD_STACK_BYTES) != 0 ||
        pthread_attr_setguardsize(&attributes, RESOURCE_THREAD_GUARD_BYTES) != 0 ||
        pthread_attr_getstacksize(&attributes, &stack_size) != 0 ||
        pthread_attr_getguardsize(&attributes, &guard_size) != 0 ||
        stack_size != RESOURCE_THREAD_STACK_BYTES ||
        guard_size != RESOURCE_THREAD_GUARD_BYTES) {
        return Fail("cannot establish the guarded-thread measurement contract");
    }

    alarm(RESOURCE_WALL_WATCHDOG_SECONDS);
    if (pthread_create(&worker, &attributes, RunResourceProbe, NULL) != 0) {
        pthread_attr_destroy(&attributes);
        return Fail("cannot create the guarded verifier thread");
    }
    if (pthread_attr_destroy(&attributes) != 0) {
        (void)pthread_join(worker, NULL);
        return Fail("cannot destroy the guarded verifier thread attributes");
    }
    if (pthread_join(worker, NULL) != 0) {
        return Fail("cannot complete the guarded verifier thread");
    }
    alarm(0);
    input_hash_after = BundleHash();
    if (g_result.failed || input_hash_before != input_hash_after ||
        g_result.completed_calls !=
            1U + RESOURCE_BATCH_COUNT * RESOURCE_BATCH_CALLS ||
        HeapCallTotal() != 0 ||
        getrusage(RUSAGE_SELF, &usage) != 0) {
        return Fail("direct-verifier resource invariant failed");
    }

    printf(
        "{\"schema_version\":%u,\"status\":\"PASS\","
        "\"records\":%u,\"sample_count\":%u,\"batch_calls\":%u,"
        "\"completed_calls\":%llu,"
        "\"selection_counts\":{\"mixed_rotating\":%u,"
        "\"valid_rotating\":%u,\"deep_reject_rotating\":%u,"
        "\"same_key_mixed\":%u},"
        "\"first_call\":{\"record\":%u,\"result\":%d,"
        "\"wall_ns\":%llu,\"cpu_ns\":%llu},\"batches\":[",
        RESOURCE_SCHEMA_VERSION,
        g_record_count,
        RESOURCE_SAMPLE_COUNT,
        RESOURCE_BATCH_CALLS,
        (unsigned long long)g_result.completed_calls,
        g_batch_record_counts[RESOURCE_BATCH_MIXED_ROTATING],
        g_batch_record_counts[RESOURCE_BATCH_VALID_ROTATING],
        g_batch_record_counts[RESOURCE_BATCH_DEEP_REJECT_ROTATING],
        g_batch_record_counts[RESOURCE_BATCH_SAME_KEY_MIXED],
        g_first_record,
        g_result.first_result,
        (unsigned long long)g_result.first_wall_ns,
        (unsigned long long)g_result.first_cpu_ns);
    for (i = 0; i < RESOURCE_BATCH_COUNT; ++i) {
        if (i != 0) putchar(',');
        PrintBatch(batch_names[i], &g_result.batches[i]);
    }
    printf("],\"control\":{\"iterations\":%u,\"wall_samples_ns\":", RESOURCE_BATCH_CALLS);
    PrintSamples(g_result.control_wall_samples_ns);
    printf(",\"cpu_samples_ns\":");
    PrintSamples(g_result.control_cpu_samples_ns);
    printf(
        "},\"heap_calls\":{\"malloc\":%lu,\"calloc\":%lu,"
        "\"realloc\":%lu,\"free\":%lu,\"aligned_alloc\":%lu,"
        "\"posix_memalign\":%lu},"
        "\"thread_stack_bytes\":%zu,\"thread_guard_bytes\":%zu,"
        "\"peak_rss_kib\":%ld,"
        "\"clock_resolution_ns\":{\"monotonic\":%llu,"
        "\"thread_cpu\":%llu},"
        "\"input_fnv1a64_before\":\"%016llx\","
        "\"input_fnv1a64_after\":\"%016llx\","
        "\"result_accumulator\":%lld}\n",
        atomic_load_explicit(&g_malloc_calls, memory_order_relaxed),
        atomic_load_explicit(&g_calloc_calls, memory_order_relaxed),
        atomic_load_explicit(&g_realloc_calls, memory_order_relaxed),
        atomic_load_explicit(&g_free_calls, memory_order_relaxed),
        atomic_load_explicit(&g_aligned_alloc_calls, memory_order_relaxed),
        atomic_load_explicit(&g_posix_memalign_calls, memory_order_relaxed),
        stack_size,
        guard_size,
        usage.ru_maxrss,
        (unsigned long long)TimespecNanoseconds(monotonic_resolution),
        (unsigned long long)TimespecNanoseconds(cpu_resolution),
        (unsigned long long)input_hash_before,
        (unsigned long long)input_hash_after,
        (long long)g_result_accumulator);
    return 0;
}
