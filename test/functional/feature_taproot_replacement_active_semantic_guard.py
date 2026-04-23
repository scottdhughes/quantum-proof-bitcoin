#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the inherited-Taproot rejection guard under ACTIVE_REPLACEMENT.

This slice uses inherited Taproot machinery only as a negative-control fixture.
It first probes whether a default DEPLOYMENT_DEFINED_NOT_SIGNALING node accepts a
valid inherited witness-v1 keypath spend at block-validation level. If so, the
test proves defined-vs-active semantic divergence. If not, it degrades cleanly
to a single-node active rejection proof.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    TIME_GENESIS_BLOCK,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


TAPROOT_REPLACEMENT_NAME = "taproot_replacement"
NO_TIMEOUT = 0x7fffffffffffffff
TIME_STEP = 600
ACTIVE_HEIGHT = 432
POST_ACTIVE_HEIGHT = ACTIVE_HEIGHT + 1
ACTIVE_GUARD_REJECT_REASON = "Inherited Taproot witness-v1 semantics disallowed under active replacement"


class TaprootReplacementActiveSemanticGuardTest(BitcoinTestFramework):
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

    def mine_plain_blocks(self, node, target_height, *, sync_fun=None):
        while node.getblockcount() < target_height:
            next_height = node.getblockcount() + 1
            self.set_network_mocktime(next_height)
            if sync_fun is None:
                self.generate(node, 1, sync_fun=lambda: None)
            else:
                self.generate(node, 1, sync_fun=sync_fun)

    def mine_funding_block(self, node, script_pubkey):
        next_height = node.getblockcount() + 1
        self.set_network_mocktime(next_height)
        coinbase = create_coinbase(next_height, script_pubkey=script_pubkey)
        block = create_block(int(node.getbestblockhash(), 16), coinbase, TIME_GENESIS_BLOCK + next_height * TIME_STEP)
        block.solve()
        response = node.submitblock(block.serialize().hex())
        assert_equal(response, None)
        assert_equal(node.getbestblockhash(), block.hash_hex)
        return block

    def build_negative_control_fixture(self):
        internal_key = generate_privkey()
        internal_pubkey, _ = compute_xonly_pubkey(internal_key)
        tap = taproot_construct(internal_pubkey)

        funding_block = self.mine_funding_block(self.nodes[0], tap.scriptPubKey)
        funding_height = self.nodes[0].getblockcount()
        self.mine_plain_blocks(self.nodes[0], funding_height + COINBASE_MATURITY)

        return {
            "internal_key": internal_key,
            "tap": tap,
            "prevout": funding_block.vtx[0].vout[0],
            "outpoint": COutPoint(funding_block.vtx[0].txid_int, 0),
        }

    def build_negative_control_block(self, node, fixture):
        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(fixture["outpoint"], nSequence=SEQUENCE_FINAL)]
        spend_tx.vout = [CTxOut(fixture["prevout"].nValue - 1000, CScript([OP_TRUE]))]
        spend_tx.wit.vtxinwit = [CTxInWitness()]

        sighash = TaprootSignatureHash(spend_tx, [fixture["prevout"]], SIGHASH_DEFAULT, 0, scriptpath=False)
        tweaked_key = tweak_add_privkey(fixture["internal_key"], fixture["tap"].tweak)
        assert tweaked_key is not None
        signature = sign_schnorr(tweaked_key, sighash, aux=bytes([0] * 32))
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [signature]

        next_height = node.getblockcount() + 1
        self.set_network_mocktime(next_height)
        block = create_block(int(node.getbestblockhash(), 16), create_coinbase(next_height), TIME_GENESIS_BLOCK + next_height * TIME_STEP, txlist=[spend_tx])
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_block(self, node, block, *, expect_accept, reject_reason=None):
        prior_tip = node.getbestblockhash()
        response = node.submitblock(block.serialize().hex())
        if expect_accept:
            assert_equal(response, None)
            assert_equal(node.getbestblockhash(), block.hash_hex)
        else:
            assert_equal(node.getbestblockhash(), prior_tip)
            assert response is not None
            if reject_reason is not None:
                assert reject_reason in response, response
        return response

    def probe_block_acceptance(self, node, block):
        prior_tip = node.getbestblockhash()
        response = node.submitblock(block.serialize().hex())
        accepted = node.getbestblockhash() == block.hash_hex
        if not accepted:
            assert_equal(node.getbestblockhash(), prior_tip)
        return accepted, response, prior_tip

    def assert_same_chain_active_boundary(self):
        best_hash_0 = self.nodes[0].getbestblockhash()
        best_hash_1 = self.nodes[1].getbestblockhash()
        assert_equal(best_hash_0, best_hash_1)
        assert_equal(self.nodes[0].getblockcount(), ACTIVE_HEIGHT)
        assert_equal(self.nodes[1].getblockcount(), ACTIVE_HEIGHT)

        info_0 = self.nodes[0].getdeploymentinfo(best_hash_0)
        info_1 = self.nodes[1].getdeploymentinfo(best_hash_1)
        dep_0 = info_0["deployments"][TAPROOT_REPLACEMENT_NAME]
        dep_1 = info_1["deployments"][TAPROOT_REPLACEMENT_NAME]

        assert_equal(dep_0["bip9"]["status"], "defined")
        assert_equal(dep_0["active"], False)
        assert "height" not in dep_0

        assert_equal(dep_1["bip9"]["status"], "active")
        assert_equal(dep_1["active"], True)
        assert_equal(dep_1["height"], ACTIVE_HEIGHT)

    def run_test(self):
        dep = self.nodes[0].getdeploymentinfo()["deployments"][TAPROOT_REPLACEMENT_NAME]
        if dep["active"] and dep["bip9"]["status"] == "active":
            raise SkipTest("legacy-aligned regtest keeps taproot_replacement active from genesis")

        self.log.info("Disconnect node1 while probing the dormant-side negative-control precondition")
        self.disconnect_nodes(0, 1)

        self.log.info("Build and mature a raw inherited Taproot keypath funding output on node0")
        fixture = self.build_negative_control_fixture()

        self.log.info("Probe whether a default defined node accepts the negative-control block at block-validation level")
        precondition_block = self.build_negative_control_block(self.nodes[0], fixture)
        precondition_passed, precondition_response, precondition_tip = self.probe_block_acceptance(self.nodes[0], precondition_block)

        if precondition_passed:
            self.log.info("Default node accepted the negative-control block; invalidate it and proceed to defined-vs-active divergence")
            self.nodes[0].invalidateblock(precondition_block.hash_hex)
            assert_equal(self.nodes[0].getbestblockhash(), precondition_tip)
        else:
            self.log.info(f"Default node rejected the negative-control block ({precondition_response}); degrade to a single-node active rejection proof")

        self.log.info("Reconnect node1, restart it with active vbparams, and mine plain blocks to the active boundary")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.restart_active_node()
        self.mine_plain_blocks(self.nodes[1], ACTIVE_HEIGHT, sync_fun=self.sync_blocks)
        self.assert_same_chain_active_boundary()
        self.log.info("Mine one additional plain block inside ACTIVE_REPLACEMENT before exercising the semantic guard")
        self.mine_plain_blocks(self.nodes[1], POST_ACTIVE_HEIGHT, sync_fun=self.sync_blocks)

        candidate_block = self.build_negative_control_block(self.nodes[1], fixture)
        active_tip = self.nodes[1].getbestblockhash()

        self.log.info("Disconnect peers before submitting the negative-control block so the accept/reject outcomes stay explicit")
        self.disconnect_nodes(0, 1)

        self.log.info("Assert the active node rejects inherited Taproot semantics with the explicit replacement guard")
        self.submit_block(
            self.nodes[1],
            candidate_block,
            expect_accept=False,
            reject_reason=ACTIVE_GUARD_REJECT_REASON,
        )
        assert_equal(self.nodes[1].getbestblockhash(), active_tip)

        if precondition_passed:
            self.log.info("Assert the defined node still accepts the same inherited Taproot negative-control block")
            self.submit_block(self.nodes[0], candidate_block, expect_accept=True)
            assert self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash()


if __name__ == '__main__':
    TaprootReplacementActiveSemanticGuardTest(__file__).main()
