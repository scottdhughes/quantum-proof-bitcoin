#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Taproot replacement deployment reporting.

Validate that the replacement deployment is concretely configured but dormant by
default, and that regtest -vbparams overrides can deterministically exercise the
existing BIP9 reporting surface for the replacement slot.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


TAPROOT_REPLACEMENT_NAME = "taproot_replacement"
TAPROOT_REPLACEMENT_START_TIME = 4102444800
TAPROOT_REPLACEMENT_TIMEOUT = 4133980800
NO_TIMEOUT = 0x7fffffffffffffff
VB_PERIOD = 144
VB_THRESHOLD = 108
TIME_STEP = 600
STARTED_CHECKPOINT_HEIGHT = 207
LOCKED_IN_TRANSITION_HEIGHT = 287
ACTIVE_TRANSITION_HEIGHT = 431
ACTIVE_HEIGHT = 432


class TaprootReplacementDeploymentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def mine_to_height(self, target):
        while self.nodes[0].getblockcount() < target:
            next_height = self.nodes[0].getblockcount() + 1
            self.nodes[0].setmocktime(TIME_GENESIS_BLOCK + next_height * TIME_STEP)
            self.generate(self.nodes[0], 1)

    def assert_default_defined(self):
        deployment_info = self.nodes[0].getdeploymentinfo()
        deployments = deployment_info["deployments"]

        assert TAPROOT_REPLACEMENT_NAME in deployments
        assert "taproot" not in deployments

        dep = deployments[TAPROOT_REPLACEMENT_NAME]
        assert_equal(dep["type"], "bip9")
        assert_equal(dep["active"], False)
        assert "height" not in dep

        bip9 = dep["bip9"]
        assert_equal(bip9["start_time"], TAPROOT_REPLACEMENT_START_TIME)
        assert_equal(bip9["timeout"], TAPROOT_REPLACEMENT_TIMEOUT)
        assert_equal(bip9["min_activation_height"], 0)
        assert_equal(bip9["status"], "defined")
        assert_equal(bip9["status_next"], "defined")
        assert_equal(bip9["since"], 0)
        assert "bit" not in bip9
        assert "statistics" not in bip9
        assert "signalling" not in bip9

    def assert_signalling_state(self, height, status_next):
        deployment_info = self.nodes[0].getdeploymentinfo()
        assert_equal(deployment_info["height"], height)

        dep = deployment_info["deployments"][TAPROOT_REPLACEMENT_NAME]
        assert_equal(dep["type"], "bip9")
        assert_equal(dep["active"], False)

        bip9 = dep["bip9"]
        assert_equal(bip9["bit"], 2)
        assert_equal(bip9["start_time"], 0)
        assert_equal(bip9["timeout"], NO_TIMEOUT)
        assert_equal(bip9["min_activation_height"], 0)
        assert_equal(bip9["status"], "started")
        assert_equal(bip9["status_next"], status_next)
        assert_equal(bip9["since"], 144)

        stats = bip9["statistics"]
        assert_equal(stats["period"], VB_PERIOD)
        assert_equal(stats["threshold"], VB_THRESHOLD)
        assert_equal(stats["elapsed"], height - 143)
        assert_equal(stats["count"], height - 143)
        assert_equal(stats["possible"], True)
        assert_equal(bip9["signalling"], "#" * (height - 143))

    def assert_locked_in_transition(self, height):
        deployment_info = self.nodes[0].getdeploymentinfo()
        assert_equal(deployment_info["height"], height)

        dep = deployment_info["deployments"][TAPROOT_REPLACEMENT_NAME]
        assert_equal(dep["type"], "bip9")
        assert_equal(dep["active"], True)
        assert_equal(dep["height"], ACTIVE_HEIGHT)

        bip9 = dep["bip9"]
        assert_equal(bip9["bit"], 2)
        assert_equal(bip9["start_time"], 0)
        assert_equal(bip9["timeout"], NO_TIMEOUT)
        assert_equal(bip9["min_activation_height"], 0)
        assert_equal(bip9["status"], "locked_in")
        assert_equal(bip9["status_next"], "active")
        assert_equal(bip9["since"], 288)

        stats = bip9["statistics"]
        assert_equal(stats["period"], VB_PERIOD)
        assert_equal(stats["elapsed"], height - 287)
        assert_equal(stats["count"], height - 287)
        assert "threshold" not in stats
        assert "possible" not in stats
        assert_equal(bip9["signalling"], "#" * (height - 287))

    def assert_active_state(self, height):
        deployment_info = self.nodes[0].getdeploymentinfo()
        assert_equal(deployment_info["height"], height)

        dep = deployment_info["deployments"][TAPROOT_REPLACEMENT_NAME]
        assert_equal(dep["type"], "bip9")
        assert_equal(dep["active"], True)
        assert_equal(dep["height"], ACTIVE_HEIGHT)

        bip9 = dep["bip9"]
        assert_equal(bip9["start_time"], 0)
        assert_equal(bip9["timeout"], NO_TIMEOUT)
        assert_equal(bip9["min_activation_height"], 0)
        assert_equal(bip9["status"], "active")
        assert_equal(bip9["status_next"], "active")
        assert_equal(bip9["since"], ACTIVE_HEIGHT)
        assert "bit" not in bip9
        assert "statistics" not in bip9
        assert "signalling" not in bip9

    def run_test(self):
        self.assert_default_defined()

        self.stop_node(0)
        self.start_node(0, extra_args=[f"-vbparams={TAPROOT_REPLACEMENT_NAME}:0:{NO_TIMEOUT}"])

        self.mine_to_height(STARTED_CHECKPOINT_HEIGHT)
        self.assert_signalling_state(STARTED_CHECKPOINT_HEIGHT, "started")

        self.mine_to_height(LOCKED_IN_TRANSITION_HEIGHT)
        self.assert_signalling_state(LOCKED_IN_TRANSITION_HEIGHT, "locked_in")

        self.mine_to_height(ACTIVE_TRANSITION_HEIGHT)
        self.assert_locked_in_transition(ACTIVE_TRANSITION_HEIGHT)

        self.mine_to_height(ACTIVE_HEIGHT)
        self.assert_active_state(ACTIVE_HEIGHT)


if __name__ == '__main__':
    TaprootReplacementDeploymentTest(__file__).main()
