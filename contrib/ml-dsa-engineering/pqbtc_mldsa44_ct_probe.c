// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <stdint.h>
#include <string.h>

#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

static volatile uint32_t g_sink;

static void ProbeBranch(void)
{
    volatile uint32_t secret = 1;
    VALGRIND_MAKE_MEM_UNDEFINED((void*)&secret, sizeof(secret));
    if ((secret & 1U) != 0) g_sink = 17;
}

static void ProbeAddress(void)
{
    volatile uint32_t secret = 1;
    static volatile uint32_t table[256];
    VALGRIND_MAKE_MEM_UNDEFINED((void*)&secret, sizeof(secret));
    g_sink = table[secret & 0xffU];
}

static void ProbeVariableLatency(void)
{
    volatile uint32_t secret = 3;
    VALGRIND_MAKE_MEM_UNDEFINED((void*)&secret, sizeof(secret));
    g_sink = 100U / (secret | 1U);
}

int main(int argc, char** argv)
{
    if (RUNNING_ON_VALGRIND == 0 || argc != 2) return 64;
    if (strcmp(argv[1], "branch") == 0) {
        ProbeBranch();
        return 0;
    }
    if (strcmp(argv[1], "address") == 0) {
        ProbeAddress();
        return 0;
    }
    if (strcmp(argv[1], "variable-latency") == 0) {
        ProbeVariableLatency();
        return 0;
    }
    return 65;
}
