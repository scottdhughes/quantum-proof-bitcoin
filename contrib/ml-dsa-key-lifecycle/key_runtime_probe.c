// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#define _GNU_SOURCE
#include "key_lifecycle.c"

#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* The initial absent-API RED used a weak declaration; the implemented API is
 * now linked normally and the exact shared-library exports are tested too. */
static unsigned checks;
static unsigned failures;
static atomic_uint entropy_calls;
static atomic_uint keypair_entries, signature_entries, randomized_entries;
static uint8_t fixed_sample[32];
static int use_fixed_sample;
static int observed_map_flags = -1;
static pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char* scenario;
static const char* fail_operation;
static unsigned zero_releases, nonzero_releases;
struct ProbeMapping {
    void* base;
    size_t total;
    uint8_t* body;
    size_t body_size;
};
static struct ProbeMapping maps[16];
static unsigned map_count;

void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void* function, void* caller)
{
    (void)caller;
    if (function == (void*)pqbtc_mldsa44_upstream_keypair_internal) ++keypair_entries;
    if (function == (void*)pqbtc_mldsa44_upstream_signature_internal) ++signature_entries;
    if (function == (void*)pqbtc_mldsa44_upstream_signature) ++randomized_entries;
}
void __attribute__((no_instrument_function)) __cyg_profile_func_exit(void* function, void* caller)
{
    (void)function;
    (void)caller;
}
static int RuntimeInitAvailable(void)
{
    int (*volatile initializer)(void) = pqbtc_mldsa44_key_runtime_init;
    return initializer != NULL;
}
#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL runtime %s: %s\n", scenario, #condition); \
        ++failures; \
    } \
} while (0)

int __real_getentropy(void* output, size_t size);
int __wrap_getentropy(void* output, size_t size)
{
    ++entropy_calls;
    if (fail_operation != NULL && strcmp(fail_operation, "entropy") == 0) {
        memset(output, 0x7b, size / 2);
        errno = EIO;
        return -1;
    }
    if (use_fixed_sample && size == 32) {
        memcpy(output, fixed_sample, 32);
        return 0;
    }
    return __real_getentropy(output, size);
}

static int Fail(const char* operation)
{
    if (fail_operation != NULL && strcmp(fail_operation, operation) == 0) {
        errno = EPERM;
        return 1;
    }
    return 0;
}

int __real_prctl(int operation, ...);
int __wrap_prctl(int operation, ...)
{
    unsigned long value = 0;
    if (operation == PR_SET_DUMPABLE) {
        va_list args;
        va_start(args, operation);
        value = va_arg(args, unsigned long);
        va_end(args);
    }
    if (Fail(operation == PR_SET_DUMPABLE ? "prctl-set" : "prctl-get")) return -1;
    return __real_prctl(operation, value, 0UL, 0UL, 0UL);
}
int __real_setrlimit(__rlimit_resource_t resource, const struct rlimit* limit);
int __wrap_setrlimit(__rlimit_resource_t resource, const struct rlimit* limit)
{
    return Fail("setrlimit") ? -1 : __real_setrlimit(resource, limit);
}
int __real_getrlimit(__rlimit_resource_t resource, struct rlimit* limit);
int __wrap_getrlimit(__rlimit_resource_t resource, struct rlimit* limit)
{
    return Fail("getrlimit") ? -1 : __real_getrlimit(resource, limit);
}
long __real_sysconf(int name);
long __wrap_sysconf(int name)
{
    return name == _SC_PAGESIZE && Fail("pagesize") ? -1 : __real_sysconf(name);
}
void* __real_mmap(void*, size_t, int, int, int, off_t);
void* __wrap_mmap(void* address, size_t size, int prot, int flags, int fd, off_t offset)
{
    void* result;
    if (Fail("mmap")) return MAP_FAILED;
    result = __real_mmap(address, size, prot, flags, fd, offset);
    pthread_mutex_lock(&map_mutex);
    if (result != MAP_FAILED && map_count < 16) maps[map_count++] = (struct ProbeMapping){result, size, NULL, 0};
    pthread_mutex_unlock(&map_mutex);
    return result;
}
int __real_mprotect(void*, size_t, int);
int __wrap_mprotect(void* address, size_t size, int prot)
{
    unsigned i;
    int result;
    if (Fail("mprotect")) return -1;
    result = __real_mprotect(address, size, prot);
    pthread_mutex_lock(&map_mutex);
    if (result == 0 && prot == (PROT_READ | PROT_WRITE)) {
        for (i = 0; i < map_count; ++i) {
            if ((uintptr_t)address > (uintptr_t)maps[i].base &&
                (uintptr_t)address < (uintptr_t)maps[i].base + maps[i].total) {
                maps[i].body = address;
                maps[i].body_size = size;
            }
        }
    }
    pthread_mutex_unlock(&map_mutex);
    return result;
}
long __real_syscall(long operation, ...);
long __wrap_syscall(long operation, ...)
{
    void* address;
    size_t size;
    va_list args;
    if (operation != SYS_mlock) { errno = ENOSYS; return -1; }
    va_start(args, operation);
    address = va_arg(args, void*);
    size = va_arg(args, size_t);
    va_end(args);
    return Fail("mlock") ? -1 : __real_syscall(operation, address, size);
}
int __real_madvise(void*, size_t, int);
int __wrap_madvise(void* address, size_t size, int advice)
{
    if (Fail(advice == MADV_DONTDUMP ? "dontdump" : "dontfork")) return -1;
    return __real_madvise(address, size, advice);
}
int __real_munmap(void*, size_t);
int __wrap_munmap(void* address, size_t size)
{
    unsigned i;
    pthread_mutex_lock(&map_mutex);
    for (i = 0; i < map_count; ++i) {
        if (maps[i].base == address && maps[i].total == size) {
            if (maps[i].body != NULL) {
                size_t n;
                uint8_t nonzero = 0;
                for (n = 0; n < maps[i].body_size; ++n) nonzero |= maps[i].body[n];
                if (nonzero) ++nonzero_releases;
                else ++zero_releases;
            }
            /* A failed unmap is observed once, not traversed again after a
             * later allocation happens to reuse its nonsecret address. */
            maps[i].body = NULL;
            maps[i].base = NULL;
        }
    }
    pthread_mutex_unlock(&map_mutex);
    return Fail("munmap") ? -1 : __real_munmap(address, size);
}

static void Uninitialized(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1}; /* Public synthetic fixture. */
    int result = pqbtc_mldsa44_key_import_seed(&key, seed, sizeof(seed));
    CHECK(result == -12);
    CHECK(key == NULL);
    pqbtc_mldsa44_key_destroy(&key);
    result = pqbtc_mldsa44_key_generate(&key);
    CHECK(result == -12);
    CHECK(key == NULL);
    CHECK(entropy_calls == 0);
    pqbtc_mldsa44_key_destroy(&key);
}

static void PublicOnly(void)
{
    const uint8_t signature[2420] = {0}, public_key[1312] = {0};
    struct rlimit before, after;
    const int dumpable = prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
    CHECK(getrlimit(RLIMIT_CORE, &before) == 0);
    CHECK(pqbtc_mldsa44_key_verify_strict(signature, sizeof(signature),
        public_key, sizeof(public_key), NULL, 0, NULL, 0) == -9);
    CHECK(getrlimit(RLIMIT_CORE, &after) == 0);
    CHECK(before.rlim_cur == after.rlim_cur && before.rlim_max == after.rlim_max);
    CHECK(prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == dumpable);
}

static void Healthy(void)
{
    struct rlimit limit;
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(getrlimit(RLIMIT_CORE, &limit) == 0);
    CHECK(limit.rlim_cur == 0 && limit.rlim_max == 0);
    CHECK(prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == 0);
}

static void ForkBeforeInit(void)
{
    int status = 0;
    pid_t pid;
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(pqbtc_mldsa44_key_runtime_init() == -13 ? 0 : 1);
    if (pid < 0) return;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
}

static void InitFailure(const char* operation)
{
    struct pqbtc_mldsa44_key* key = NULL;
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    fail_operation = operation;
    CHECK(pqbtc_mldsa44_key_runtime_init() == -12);
    fail_operation = NULL;
    CHECK(pqbtc_mldsa44_key_runtime_init() == -12);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -12);
    CHECK(key == NULL && entropy_calls == 0);
}

static void AllocationFailure(const char* operation)
{
    struct pqbtc_mldsa44_key* key = NULL;
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    fail_operation = operation;
    CHECK(pqbtc_mldsa44_key_generate(&key) == -11);
    CHECK(key == NULL);
    CHECK(entropy_calls == 0);
    fail_operation = NULL;
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(nonzero_releases == 0);
}

static void MemlockLimit(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    struct rlimit limit = {0, 0};
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(__real_setrlimit(RLIMIT_MEMLOCK, &limit) == 0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -11);
    CHECK(key == NULL && entropy_calls == 0);
    CHECK(__real_getrlimit(RLIMIT_MEMLOCK, &limit) == 0);
    CHECK(limit.rlim_cur == 0 && limit.rlim_max == 0);
    CHECK(zero_releases == 1 && nonzero_releases == 0);
}

static unsigned MappingFlags(const struct ProbeMapping* map)
{
    FILE* input = fopen("/proc/self/smaps", "r");
    char line[1024];
    int selected = 0;
    unsigned found = 0;
    if (input == NULL) return 0;
    while (fgets(line, sizeof(line), input) != NULL) {
        unsigned long begin, end, locked;
        if (sscanf(line, "%lx-%lx", &begin, &end) == 2) {
            selected = begin == (uintptr_t)map->body && end == begin + map->body_size;
        } else if (selected && sscanf(line, "Locked: %lu kB", &locked) == 1) {
            if (locked >= map->body_size / 1024) found |= 8;
        } else if (selected && strncmp(line, "VmFlags:", 8) == 0) {
            if (strstr(line, " lo ")) found |= 1;
            if (strstr(line, " dd ")) found |= 2;
            if (strstr(line, " dc ")) found |= 4;
        }
    }
    fclose(input);
    return found;
}

static void Mapping(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1};
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(map_count == 1);
    if (map_count == 1) {
        const size_t page = (size_t)__real_sysconf(_SC_PAGESIZE);
        CHECK(maps[0].body == (uint8_t*)key);
        CHECK(maps[0].body_size >= sizeof(*key));
        CHECK(maps[0].body_size % page == 0);
        CHECK(maps[0].total == maps[0].body_size + 2 * page);
        const unsigned flags = MappingFlags(&maps[0]);
        observed_map_flags = (int)flags;
        CHECK((flags & 9U) == 9U);
        CHECK((flags & 2U) == 2U);
        CHECK((flags & 4U) == 4U);
    }
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(key == NULL);
    CHECK(zero_releases == 1 && nonzero_releases == 0);
}

static void BodyAlias(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1};
    uint8_t* copy;
    size_t size;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(map_count == 1);
    if (key == NULL || map_count != 1) return;
    size = maps[0].body_size;
    copy = malloc(size);
    CHECK(copy != NULL);
    if (copy == NULL) { pqbtc_mldsa44_key_destroy(&key); return; }
    memcpy(copy, key, size);
    CHECK(pqbtc_mldsa44_key_public(key, (uint8_t*)key, 1312) == -1);
    CHECK(memcmp(copy, key, size) == 0);
    CHECK(pqbtc_mldsa44_key_export_seed(key, (uint8_t*)key + size - 32, 32) == -1);
    CHECK(memcmp(copy, key, size) == 0);
    pqbtc_mldsa44_zeroize(copy, size);
    free(copy);
    pqbtc_mldsa44_key_destroy(&key);
}

static void Drift(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1};
    uint8_t output[32];
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(__real_prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL) == 0);
    memset(output, 0xa5, sizeof(output));
    CHECK(pqbtc_mldsa44_key_export_seed(key, output, 32) == -12);
    CHECK(output[0] == 0xa5 && output[31] == 0xa5);
    CHECK(__real_prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == 0);
    CHECK(pqbtc_mldsa44_key_runtime_init() == -12);
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(key == NULL);
    CHECK(zero_releases == 1 && nonzero_releases == 0);
}

static void UnmapFailure(void)
{
    struct pqbtc_mldsa44_key *key = NULL, *other = NULL, *rejected = NULL;
    const uint8_t seed[32] = {1};
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&other, seed, 32) == 0);
    fail_operation = "munmap";
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(key == NULL && zero_releases == 1 && nonzero_releases == 0);
    fail_operation = NULL;
    CHECK(pqbtc_mldsa44_key_generate(&rejected) == -12 && rejected == NULL);
    CHECK(pqbtc_mldsa44_key_runtime_init() == -12);
    pqbtc_mldsa44_key_destroy(&other);
    CHECK(other == NULL && zero_releases == 2 && nonzero_releases == 0);
}

static void PageLayout(void)
{
    size_t body = 13, total = 17;
    CHECK(KeyPageLayout(1, 4096, &body, &total) == 0 && body == 4096 && total == 12288);
    CHECK(KeyPageLayout(5000, 4096, &body, &total) == 0 && body == 8192 && total == 16384);
    CHECK(KeyPageLayout(1, 65536, &body, &total) == 0 && body == 65536 && total == 196608);
    CHECK(KeyPageLayout(1, 0, &body, &total) == -11);
    CHECK(KeyPageLayout(0, 4096, &body, &total) == -11);
    CHECK(KeyPageLayout(SIZE_MAX, 4096, &body, &total) == -11);
    CHECK(KeyPageLayout(1, SIZE_MAX, &body, &total) == -11);
    CHECK(KeyPageLayout(SIZE_MAX - 4095, 4096, &body, &total) == -11);
}

static void FaultExit(int sig)
{
    _exit(sig == SIGSEGV ? 77 : 78);
}

static void GuardFault(uint8_t* address)
{
    const pid_t pid = fork();
    int status = 0;
    CHECK(pid >= 0);
    if (pid == 0) {
        signal(SIGSEGV, FaultExit);
        *(volatile uint8_t*)address = 1;
        _exit(1);
    }
    if (pid < 0) return;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

static void Guards(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1};
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(map_count == 1);
    if (key == NULL || map_count != 1) return;
    GuardFault(maps[0].body - 1);
    GuardFault(maps[0].body + maps[0].body_size);
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(key == NULL && nonzero_releases == 0 && zero_releases == 1);
}

static void EntropyFailure(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    CHECK(RuntimeInitAvailable());
    if (!RuntimeInitAvailable()) return;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    fail_operation = "entropy";
    CHECK(pqbtc_mldsa44_key_generate(&key) == -2);
    CHECK(key == NULL);
    CHECK(entropy_calls == 1);
    pqbtc_mldsa44_key_destroy(&key);
}

static void Sample(void)
{
#ifdef PQBTC_MLDSA44_TESTING
    CHECK(pqbtc_mldsa44_test_set_entropy(1, fixed_sample, 32) == 0);
#else
    use_fixed_sample = 1;
#endif
}

static void SharedGuard(int sign_first)
{
    struct pqbtc_mldsa44_key *key = NULL, *other = NULL;
    const uint8_t seed[32] = {1}, message[1] = {2};
    uint8_t signature[2420];
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    memset(fixed_sample, 0x43, 32);
    Sample();
    if (sign_first) {
        CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
        CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == 0);
        CHECK(pqbtc_mldsa44_key_generate(&other) == -5 && other == NULL);
    } else {
        CHECK(pqbtc_mldsa44_key_generate(&key) == 0);
    }
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0); /* No repeat-history reset. */
    memset(signature, 0xa5, sizeof(signature));
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == -5);
    CHECK(ConstantTimeAllZero(signature, sizeof(signature)));
    CHECK(pqbtc_mldsa44_key_generate(&other) == -5 && other == NULL);
    fixed_sample[0] ^= 1;
    Sample();
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == 0);
    pqbtc_mldsa44_key_destroy(&key);
}

static void EntropyBoundaries(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1}, message[1] = {2};
    uint8_t signature[2420];
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    fail_operation = "entropy";
    CHECK(pqbtc_mldsa44_key_generate(&key) == -2 && key == NULL);
    CHECK(keypair_entries == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(keypair_entries == 1); /* Positive calibration of the actual entry observer. */
    memset(signature, 0xa5, sizeof(signature));
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == -2);
    CHECK(ConstantTimeAllZero(signature, sizeof(signature)));
    CHECK(randomized_entries == 1 && signature_entries == 0);
    fail_operation = NULL;
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == 0);
    CHECK(randomized_entries == 2 && signature_entries == 1);
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(zero_releases == 2 && nonzero_releases == 0);
}

struct GenerateThread { struct pqbtc_mldsa44_key* owner; int result; };
static void* GenerateWorker(void* argument)
{
    struct GenerateThread* task = argument;
    task->result = pqbtc_mldsa44_key_generate(&task->owner);
    return NULL;
}
static void ConcurrentDuplicate(void)
{
    struct GenerateThread tasks[2] = {{NULL, 1}, {NULL, 1}};
    pthread_t threads[2];
    int first, second;
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    memset(fixed_sample, 0x45, 32);
    Sample();
    first = pthread_create(&threads[0], NULL, GenerateWorker, &tasks[0]);
    second = pthread_create(&threads[1], NULL, GenerateWorker, &tasks[1]);
    CHECK(first == 0 && second == 0);
    if (first == 0) CHECK(pthread_join(threads[0], NULL) == 0);
    if (second == 0) CHECK(pthread_join(threads[1], NULL) == 0);
    CHECK((tasks[0].result == 0 && tasks[1].result == -5) ||
        (tasks[1].result == 0 && tasks[0].result == -5));
    CHECK((tasks[0].owner != NULL) != (tasks[1].owner != NULL));
    pqbtc_mldsa44_key_destroy(&tasks[0].owner);
    pqbtc_mldsa44_key_destroy(&tasks[1].owner);
    CHECK(zero_releases == 2 && nonzero_releases == 0);
}

static void ForkLive(void)
{
    struct pqbtc_mldsa44_key* key = NULL;
    const uint8_t seed[32] = {1}, message[1] = {2};
    uint8_t signature[2420], public_key[1312];
    int status = 0, channel[2];
    pid_t pid;
    struct { unsigned checks; unsigned failures; } summary = {0, 0};
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(pqbtc_mldsa44_key_public(key, public_key, 1312) == 0);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == 0);
    CHECK(pipe(channel) == 0);
    if (failures) { pqbtc_mldsa44_key_destroy(&key); return; }
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        unsigned char vector[1];
        uint8_t output[2420];
        struct pqbtc_mldsa44_key* fresh = NULL;
        checks = failures = 0;
        close(channel[0]);
        CHECK(pqbtc_mldsa44_key_runtime_init() == -13);
        /* The guard mutant must stop at its named failure, not crash later. */
        if (!failures) {
            errno = 0;
            CHECK(mincore(key, 1, vector) == -1 && errno == ENOMEM);
        }
        if (!failures) {
            CHECK(pqbtc_mldsa44_key_public(key, output, 1312) == -13);
            CHECK(pqbtc_mldsa44_key_export_seed(key, output, 32) == -13);
            CHECK(pqbtc_mldsa44_key_sign_hedged(key, output, 2420, message, 1, NULL, 0) == -13);
            CHECK(pqbtc_mldsa44_key_import_seed(&fresh, seed, 32) == -13 && fresh == NULL);
            CHECK(pqbtc_mldsa44_key_generate(&fresh) == -13 && fresh == NULL);
            CHECK(pqbtc_mldsa44_key_verify_strict(signature, 2420, public_key, 1312, message, 1, NULL, 0) == 0);
            pqbtc_mldsa44_key_destroy(&key);
            CHECK(key == NULL);
        }
        summary.checks = checks;
        summary.failures = failures;
        if (write(channel[1], &summary, sizeof(summary)) != sizeof(summary)) _exit(2);
        close(channel[1]);
        _exit(failures ? 1 : 0);
    }
    close(channel[1]);
    if (pid >= 0) {
        CHECK(read(channel[0], &summary, sizeof(summary)) == sizeof(summary));
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0 && summary.failures == 0);
        checks += summary.checks;
    }
    close(channel[0]);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        execl("/proc/self/exe", "key-runtime-probe", "exec-ready", (char*)NULL);
        _exit(2);
    }
    if (pid >= 0) {
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    pqbtc_mldsa44_key_destroy(&key);
    CHECK(key == NULL && nonzero_releases == 0 && zero_releases == 1);
}

#ifdef PQBTC_MLDSA44_TESTING
static void ConsumedSamples(void)
{
    struct pqbtc_mldsa44_key *key = NULL, *other = NULL;
    const uint8_t seed[32] = {1}, message[1] = {2};
    uint8_t signature[2420];
    CHECK(pqbtc_mldsa44_key_runtime_init() == 0);
    memset(fixed_sample, 0x47, 32);
    Sample();
    pqbtc_mldsa44_key_test_fail_keygen(1);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -6 && key == NULL);
    pqbtc_mldsa44_key_test_fail_keygen(0);
    CHECK(pqbtc_mldsa44_key_generate(&key) == -5 && key == NULL);
    CHECK(pqbtc_mldsa44_key_import_seed(&key, seed, 32) == 0);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == -5);
    fixed_sample[0] ^= 1;
    Sample();
    pqbtc_mldsa44_test_force_backend_result(-1);
    CHECK(pqbtc_mldsa44_key_sign_hedged(key, signature, 2420, message, 1, NULL, 0) == -6);
    pqbtc_mldsa44_test_force_backend_result(0);
    CHECK(pqbtc_mldsa44_key_generate(&other) == -5 && other == NULL);
    CHECK(ConstantTimeAllZero(signature, sizeof(signature)));
    pqbtc_mldsa44_key_destroy(&key);
}
#endif

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    scenario = argv[1];
    if (strcmp(scenario, "exec-ready") == 0) return pqbtc_mldsa44_key_runtime_init() == 0 ? 0 : 1;
    if (strcmp(scenario, "uninitialized") == 0) Uninitialized();
    else if (strcmp(scenario, "public-only-verify") == 0) PublicOnly();
    else if (strcmp(scenario, "healthy-init") == 0) Healthy();
    else if (strcmp(scenario, "fork-before-init") == 0) ForkBeforeInit();
    else if (strncmp(scenario, "init-fail-", 10) == 0) InitFailure(scenario + 10);
    else if (strncmp(scenario, "allocation-fail-", 16) == 0) AllocationFailure(scenario + 16);
    else if (strcmp(scenario, "mapping") == 0) Mapping();
    else if (strcmp(scenario, "whole-body-alias") == 0) BodyAlias();
    else if (strcmp(scenario, "policy-drift") == 0) Drift();
    else if (strcmp(scenario, "unmap-failure") == 0) UnmapFailure();
    else if (strcmp(scenario, "page-layout") == 0) PageLayout();
    else if (strcmp(scenario, "guards") == 0) Guards();
    else if (strcmp(scenario, "memlock-limit") == 0) MemlockLimit();
    else if (strcmp(scenario, "entropy-error") == 0) EntropyFailure();
    else if (strcmp(scenario, "entropy-boundaries") == 0) EntropyBoundaries();
    else if (strcmp(scenario, "generation-signing-repeat") == 0) SharedGuard(0);
    else if (strcmp(scenario, "signing-generation-repeat") == 0) SharedGuard(1);
    else if (strcmp(scenario, "concurrent-duplicate") == 0) ConcurrentDuplicate();
    else if (strcmp(scenario, "fork-live") == 0) ForkLive();
#ifdef PQBTC_MLDSA44_TESTING
    else if (strcmp(scenario, "consumed-samples") == 0) ConsumedSamples();
#endif
    else return 2;
    if (!failures) {
        struct rlimit core;
        const int core_zero = __real_getrlimit(RLIMIT_CORE, &core) == 0 && core.rlim_cur == 0 && core.rlim_max == 0;
        const int dump_zero = __real_prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == 0;
        printf("{\"schema\":2,\"scenario\":\"%s\",\"checks\":%u,\"result\":\"PASS\","
            "\"core_zero\":%s,\"dump_zero\":%s,\"map_flags\":%d,\"entropy_calls\":%u,"
            "\"keypair_entries\":%u,\"signature_entries\":%u,\"randomized_entries\":%u,"
            "\"zero_releases\":%u,\"nonzero_releases\":%u}\n", scenario, checks,
            core_zero ? "true" : "false", dump_zero ? "true" : "false", observed_map_flags,
            atomic_load(&entropy_calls), atomic_load(&keypair_entries), atomic_load(&signature_entries),
            atomic_load(&randomized_entries), zero_releases, nonzero_releases);
    }
    return failures ? 1 : 0;
}
