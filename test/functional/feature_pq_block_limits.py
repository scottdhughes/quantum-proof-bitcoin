#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Block weight limit checks for PQBTC v1 consensus/profile."""

from test_framework.test_framework import BitcoinTestFramework


class PQBlockLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def _weightlimit(self) -> int:
        return self.nodes[0].getblocktemplate({"rules": ["segwit"]})["weightlimit"]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        assert self._weightlimit() == 16_000_000

        self.restart_node(0, extra_args=["-blockmaxweight=16000000"])
        assert self._weightlimit() == 16_000_000

        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-blockmaxweight=16000001"],
            expected_msg="Error: Specified -blockmaxweight (16000001) exceeds consensus maximum block weight (16000000)",
        )
        self.start_node(0, extra_args=["-blockmaxweight=16000000"])
        node = self.nodes[0]
        assert self._weightlimit() == 16_000_000

        self.generate(node, 1)


if __name__ == "__main__":
    PQBlockLimitsTest(__file__).main()
