#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test defined vs active Taproot replacement reporting boundary.

Validate that the frozen replacement deployment can reach ACTIVE_REPLACEMENT on
regtest while a default node remains DEPLOYMENT_DEFINED_NOT_SIGNALING, and that
the nodes can still share the same accepted chain when only plain blocks are
mined.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


TAPROOT_REPLACEMENT_NAME = "taproot_replacement"
NO_TIMEOUT = 0x7fffffffffffffff
TIME_STEP = 600
ACTIVE_HEIGHT = 432


class TaprootReplacementActiveBoundaryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False

    def set_network_mocktime(self, height):
        mocktime = TIME_GENESIS_BLOCK + height * TIME_STEP
        for node in self.nodes:
            node.setmocktime(mocktime)

    def restart_active_node(self):
        self.restart_node(1, extra_args=[f"-vbparams={TAPROOT_REPLACEMENT_NAME}:0:{NO_TIMEOUT}"])
        self.connect_nodes(0, 1)
        self.sync_blocks()

    def mine_to_height(self, target):
        while self.nodes[1].getblockcount() < target:
            next_height = self.nodes[1].getblockcount() + 1
            self.set_network_mocktime(next_height)
            self.generate(self.nodes[1], 1, sync_fun=self.sync_blocks)

    def assert_same_chain(self, expected_height):
        best_hash_0 = self.nodes[0].getbestblockhash()
        best_hash_1 = self.nodes[1].getbestblockhash()
        assert_equal(best_hash_0, best_hash_1)
        assert_equal(self.nodes[0].getblockcount(), expected_height)
        assert_equal(self.nodes[1].getblockcount(), expected_height)
        return best_hash_0

    def assert_directional_state_pair(self, local_idx, compared_idx, expected_local_status, expected_local_active, expected_compared_status, expected_compared_active):
        tip_hash = self.assert_same_chain(ACTIVE_HEIGHT)
        local_info = self.nodes[local_idx].getdeploymentinfo(tip_hash)
        compared_info = self.nodes[compared_idx].getdeploymentinfo(tip_hash)

        assert_equal(local_info["hash"], tip_hash)
        assert_equal(compared_info["hash"], tip_hash)
        assert_equal(local_info["height"], ACTIVE_HEIGHT)
        assert_equal(compared_info["height"], ACTIVE_HEIGHT)

        local_dep = local_info["deployments"][TAPROOT_REPLACEMENT_NAME]
        compared_dep = compared_info["deployments"][TAPROOT_REPLACEMENT_NAME]

        assert_equal(local_dep["type"], "bip9")
        assert_equal(compared_dep["type"], "bip9")
        assert_equal(local_dep["active"], expected_local_active)
        assert_equal(compared_dep["active"], expected_compared_active)
        assert_equal(local_dep["bip9"]["status"], expected_local_status)
        assert_equal(compared_dep["bip9"]["status"], expected_compared_status)

        if expected_local_active:
            assert_equal(local_dep["height"], ACTIVE_HEIGHT)
        else:
            assert "height" not in local_dep

        if expected_compared_active:
            assert_equal(compared_dep["height"], ACTIVE_HEIGHT)
        else:
            assert "height" not in compared_dep

    def run_test(self):
        self.log.info("Restart node1 with regtest vbparams override for taproot_replacement")
        self.restart_active_node()

        self.log.info("Mine plain blocks only to the active boundary")
        self.mine_to_height(ACTIVE_HEIGHT)

        self.log.info("Assert defined -> active reporting-only divergence on the same accepted chain")
        self.assert_directional_state_pair(
            0,
            1,
            "defined",
            False,
            "active",
            True,
        )

        self.log.info("Assert active -> defined reporting-only divergence on the same accepted chain")
        self.assert_directional_state_pair(
            1,
            0,
            "active",
            True,
            "defined",
            False,
        )


if __name__ == '__main__':
    TaprootReplacementActiveBoundaryTest(__file__).main()
