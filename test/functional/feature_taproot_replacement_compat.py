#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test pre-active cross-node Taproot replacement compatibility.

Validate the frozen migration-matrix rows the repo can exercise today:
- DEPLOYMENT_DEFINED_NOT_SIGNALING <-> SIGNALING
- DEPLOYMENT_DEFINED_NOT_SIGNALING <-> LOCKED_IN_PRE_ACTIVE

The nodes must remain on the same accepted chain while differing only in their
pre-active deployment reporting state.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


TAPROOT_REPLACEMENT_NAME = "taproot_replacement"
NO_TIMEOUT = 0x7fffffffffffffff
TIME_STEP = 600
STARTED_CHECKPOINT_HEIGHT = 207
LOCKED_IN_CHECKPOINT_HEIGHT = 288


class TaprootReplacementCompatTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False

    def set_network_mocktime(self, height):
        mocktime = TIME_GENESIS_BLOCK + height * TIME_STEP
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_to_height(self, target):
        while self.nodes[1].getblockcount() < target:
            next_height = self.nodes[1].getblockcount() + 1
            self.set_network_mocktime(next_height)
            self.generate(self.nodes[1], 1, sync_fun=self.sync_blocks)

    def restart_signalling_node(self):
        self.restart_node(1, extra_args=[f"-vbparams={TAPROOT_REPLACEMENT_NAME}:0:{NO_TIMEOUT}"])
        self.connect_nodes(0, 1)
        self.sync_blocks()

    def assert_same_chain(self, expected_height):
        best_hash_0 = self.nodes[0].getbestblockhash()
        best_hash_1 = self.nodes[1].getbestblockhash()
        assert_equal(best_hash_0, best_hash_1)
        assert_equal(self.nodes[0].getblockcount(), expected_height)
        assert_equal(self.nodes[1].getblockcount(), expected_height)
        assert_equal(self.nodes[0].getblockheader(best_hash_0)["height"], expected_height)
        assert_equal(self.nodes[1].getblockheader(best_hash_1)["height"], expected_height)
        return best_hash_0

    def assert_directional_state_pair(self, local_idx, compared_idx, expected_local_status, expected_compared_status, expected_height):
        tip_hash = self.assert_same_chain(expected_height)
        local_info = self.nodes[local_idx].getdeploymentinfo(tip_hash)
        compared_info = self.nodes[compared_idx].getdeploymentinfo(tip_hash)

        assert_equal(local_info["hash"], tip_hash)
        assert_equal(compared_info["hash"], tip_hash)
        assert_equal(local_info["height"], expected_height)
        assert_equal(compared_info["height"], expected_height)

        local_dep = local_info["deployments"][TAPROOT_REPLACEMENT_NAME]
        compared_dep = compared_info["deployments"][TAPROOT_REPLACEMENT_NAME]

        assert_equal(local_dep["type"], "bip9")
        assert_equal(compared_dep["type"], "bip9")
        assert_equal(local_dep["active"], False)
        assert_equal(compared_dep["active"], False)
        assert "height" not in local_dep
        assert "height" not in compared_dep
        assert_equal(local_dep["bip9"]["status"], expected_local_status)
        assert_equal(compared_dep["bip9"]["status"], expected_compared_status)
        self.log.debug(
            f"Directional check at height {expected_height}: "
            f"local node{local_idx}={expected_local_status}, "
            f"compared node{compared_idx}={expected_compared_status}, "
            f"tip={tip_hash}"
        )

    def assert_pre_active_divergence(self, expected_height, signalling_status):
        # defined -> pre-active signalling/locked_in
        self.assert_directional_state_pair(0, 1, "defined", signalling_status, expected_height)
        # pre-active signalling/locked_in -> defined
        self.assert_directional_state_pair(1, 0, signalling_status, "defined", expected_height)

    def run_test(self):
        self.log.info("Restart node1 with regtest vbparams override for taproot_replacement")
        self.restart_signalling_node()

        self.log.info("Mine to a same-chain defined vs started checkpoint")
        self.mine_to_height(STARTED_CHECKPOINT_HEIGHT)
        self.assert_pre_active_divergence(STARTED_CHECKPOINT_HEIGHT, "started")

        self.log.info("Mine to a same-chain defined vs locked_in checkpoint")
        self.mine_to_height(LOCKED_IN_CHECKPOINT_HEIGHT)
        self.assert_pre_active_divergence(LOCKED_IN_CHECKPOINT_HEIGHT, "locked_in")


if __name__ == '__main__':
    TaprootReplacementCompatTest(__file__).main()
