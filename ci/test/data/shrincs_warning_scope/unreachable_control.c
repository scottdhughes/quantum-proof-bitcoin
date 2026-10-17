// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

void unreachable_control(void)
{
    __builtin_trap();
    for (;;) {}
}
