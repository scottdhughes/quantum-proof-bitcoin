// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

/* Private include: held wrapper and owned-key structure precede this file.
 * This unit applies process policy only through the explicit initializer. */
#if defined(__linux__)
static pid_t g_key_origin_pid;
static atomic_int g_key_runtime_state; /* 0 uninitialized, 1 ready, -1 failed. */

__attribute__((constructor)) static void CaptureKeyProcessOrigin(void)
{
    g_key_origin_pid = getpid();
}

static int KeyRuntimeOriginalProcess(void)
{
    return g_key_origin_pid != 0 && getpid() == g_key_origin_pid;
}

static int KeyRuntimeFail(void)
{
    atomic_store_explicit(&g_key_runtime_state, -1, memory_order_release);
    return PQBTC_MLDSA44_KEY_ERR_RUNTIME_POLICY;
}

static int KeyRuntimeCheck(void)
{
    struct rlimit core;
    if (!KeyRuntimeOriginalProcess()) return PQBTC_MLDSA44_KEY_ERR_PROCESS_ORIGIN;
    if (atomic_load_explicit(&g_key_runtime_state, memory_order_acquire) != 1) {
        return PQBTC_MLDSA44_KEY_ERR_RUNTIME_POLICY;
    }
    if (getrlimit(RLIMIT_CORE, &core) != 0 || core.rlim_cur != 0 || core.rlim_max != 0 ||
        prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0) return KeyRuntimeFail();
    return PQBTC_MLDSA44_KEY_OK;
}

static int KeyRuntimeInitialize(void)
{
    const struct rlimit core = {0, 0};
    const int state = atomic_load_explicit(&g_key_runtime_state, memory_order_acquire);
    if (!KeyRuntimeOriginalProcess()) return PQBTC_MLDSA44_KEY_ERR_PROCESS_ORIGIN;
    if (state == 1) return KeyRuntimeCheck();
    if (state == -1) return PQBTC_MLDSA44_KEY_ERR_RUNTIME_POLICY;
    /* Caller must initialize before threads. Failure can leave stricter policy;
     * do not relax either setting or reset an existing entropy history. */
    if (setrlimit(RLIMIT_CORE, &core) != 0 ||
        prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0) return KeyRuntimeFail();
    atomic_store_explicit(&g_key_runtime_state, 1, memory_order_release);
    return KeyRuntimeCheck();
}

static int KeyPageLayout(size_t object_size, size_t page_size,
    size_t* body_size, size_t* mapping_size)
{
    size_t body;
    if (object_size == 0 || page_size == 0 || body_size == NULL || mapping_size == NULL ||
        page_size > SIZE_MAX / 2 || object_size > SIZE_MAX - (page_size - 1)) {
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
    body = ((object_size + page_size - 1) / page_size) * page_size;
    if (body > SIZE_MAX - 2 * page_size) return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    *body_size = body;
    *mapping_size = body + 2 * page_size;
    return PQBTC_MLDSA44_KEY_OK;
}

static int AllocateKey(struct pqbtc_mldsa44_key** out)
{
    const long query = sysconf(_SC_PAGESIZE);
    size_t body_size, total_size;
    void* mapping;
    uint8_t* body;
#ifdef PQBTC_MLDSA44_TESTING
    if (atomic_load_explicit(&g_fail_key_allocation, memory_order_relaxed)) {
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
#endif
    if (query <= 0 || KeyPageLayout(sizeof(**out), (size_t)query, &body_size, &total_size) != 0) {
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
    mapping = mmap(NULL, total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    body = (uint8_t*)mapping + (size_t)query;
    if (mprotect(body, body_size, PROT_READ | PROT_WRITE) != 0) {
        if (munmap(mapping, total_size) != 0) (void)KeyRuntimeFail();
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
    /* AddressSanitizer's mlock interceptor reports success without locking.
     * Use the Linux kernel operation in every build, not a sanitizer-only
     * exception that would silently change the required protection profile. */
    if (syscall(SYS_mlock, body, body_size) != 0 || madvise(body, body_size, MADV_DONTDUMP) != 0 ||
        madvise(body, body_size, MADV_DONTFORK) != 0) {
        pqbtc_mldsa44_zeroize(body, body_size);
        if (munmap(mapping, total_size) != 0) (void)KeyRuntimeFail();
        return PQBTC_MLDSA44_KEY_ERR_ALLOCATION;
    }
    /* Only now write metadata; no seed/secret was accepted before protection. */
    *out = (struct pqbtc_mldsa44_key*)body;
    (*out)->mapping = mapping;
    (*out)->mapping_size = total_size;
    (*out)->body_size = body_size;
    return PQBTC_MLDSA44_KEY_OK;
}

static void DestroyAllocation(struct pqbtc_mldsa44_key* key)
{
    void* mapping = key->mapping;
    const size_t total_size = key->mapping_size, body_size = key->body_size;
    pqbtc_mldsa44_zeroize(key, body_size);
#ifdef PQBTC_MLDSA44_TESTING
    atomic_store_explicit(&g_key_release_zero,
        ConstantTimeAllZero((const uint8_t*)key, body_size), memory_order_relaxed);
    atomic_fetch_add_explicit(&g_key_releases, 1, memory_order_relaxed);
#endif
    if (munmap(mapping, total_size) != 0) (void)KeyRuntimeFail();
}
#else
static int KeyRuntimeOriginalProcess(void) { return 0; }
static int KeyRuntimeCheck(void) { return PQBTC_MLDSA44_KEY_ERR_UNSUPPORTED_PLATFORM; }
static int KeyRuntimeInitialize(void) { return PQBTC_MLDSA44_KEY_ERR_UNSUPPORTED_PLATFORM; }
static int AllocateKey(struct pqbtc_mldsa44_key** out)
{
    (void)out;
    return PQBTC_MLDSA44_KEY_ERR_UNSUPPORTED_PLATFORM;
}
static void DestroyAllocation(struct pqbtc_mldsa44_key* key) { (void)key; }
#endif
