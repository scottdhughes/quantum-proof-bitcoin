// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

// This program deliberately contains a data race. It is an isolated detector
// calibration control and must never be linked with the wrapper or clean
// harness.

#include <pthread.h>
#include <stdint.h>

#define RACY_INCREMENT_COUNT 100000U

static volatile uint32_t g_deliberately_racy_counter;

static void* IncrementWithoutSynchronization(void* unused)
{
    uint32_t iteration;
    (void)unused;

    for (iteration = 0; iteration < RACY_INCREMENT_COUNT; ++iteration) {
        ++g_deliberately_racy_counter;
    }
    return NULL;
}

int main(void)
{
    pthread_t first;
    pthread_t second;

    if (pthread_create(&first, NULL, IncrementWithoutSynchronization, NULL) !=
        0) {
        return 2;
    }
    if (pthread_create(&second, NULL, IncrementWithoutSynchronization, NULL) !=
        0) {
        return 2;
    }
    if (pthread_join(first, NULL) != 0)
        return 2;
    if (pthread_join(second, NULL) != 0)
        return 2;
    return 0;
}
