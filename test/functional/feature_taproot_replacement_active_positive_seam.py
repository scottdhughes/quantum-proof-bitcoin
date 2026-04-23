#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the first positive PQ-native ACTIVE_REPLACEMENT seam.

This slice is block-validation-only. It does not exercise mempool, relay,
policy, wallet, descriptor, address, RPC, or PSBT replacement behavior.
"""

import hashlib

from test_framework.blocktools import (
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
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    tx_from_hex,
)
from test_framework.pqsig import (
    build_pq_keypair,
    create_wallet_funded_tx,
    sign_segwitv0_input_pq,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKSIG,
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
POSITIVE_OUTPUT_AMOUNT = COIN
OUTPUT_FEE = 1000
PQ_SK_SEED = bytes.fromhex(
    "0711131719232931071113171923293107111317192329310711131719232931"
)


class TaprootReplacementActivePositiveSeamTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False

    def set_network_mocktime(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def advance_network_mocktime(self):
        mocktime = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        ) + TIME_STEP
        self.set_network_mocktime(mocktime)
        return mocktime

    def restart_active_node(self):
        self.restart_node(1, extra_args=[f"-vbparams={TAPROOT_REPLACEMENT_NAME}:0:{NO_TIMEOUT}"])
        self.connect_nodes(0, 1)
        self.sync_blocks()

    def mine_plain_blocks(self, node, target_height, *, sync_fun=None):
        while node.getblockcount() < target_height:
            self.advance_network_mocktime()
            if sync_fun is None:
                self.generate(node, 1, sync_fun=lambda: None)
            else:
                self.generate(node, 1, sync_fun=sync_fun)

    def mine_block_with_txs(self, node, txs, *, sync_fun=None):
        next_height = node.getblockcount() + 1
        block_time = self.advance_network_mocktime()
        block = create_block(
            int(node.getbestblockhash(), 16),
            create_coinbase(next_height),
            block_time,
            txlist=txs,
        )
        if any(not tx.wit.is_null() for tx in txs):
            add_witness_commitment(block)
        block.solve()
        response = node.submitblock(block.serialize().hex())
        assert_equal(response, None)
        assert_equal(node.getbestblockhash(), block.hash_hex)
        if sync_fun is not None:
            sync_fun()
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

    def build_positive_fixture(self):
        funding_node = self.nodes[1]
        _, pk_script = build_pq_keypair(PQ_SK_SEED)
        revealed_script = CScript([pk_script, OP_CHECKSIG])
        replacement_program = hashlib.sha256(bytes(revealed_script)).digest()
        replacement_script_pub_key = CScript([OP_1, replacement_program])
        funding_tx = create_wallet_funded_tx(funding_node, bytes(replacement_script_pub_key), POSITIVE_OUTPUT_AMOUNT)
        return {
            "sk_seed": PQ_SK_SEED,
            "pk_script": pk_script,
            "revealed_script": revealed_script,
            "script_pub_key": replacement_script_pub_key,
            "funding_tx": funding_tx,
            "prevout": funding_tx.vout[0],
            "outpoint": COutPoint(int(funding_tx.txid_hex, 16), 0),
        }

    def build_negative_control_fixture(self):
        funding_node = self.nodes[1]
        internal_key = generate_privkey()
        internal_pubkey, _ = compute_xonly_pubkey(internal_key)
        tap = taproot_construct(internal_pubkey)
        funding_tx = create_wallet_funded_tx(funding_node, bytes(tap.scriptPubKey), POSITIVE_OUTPUT_AMOUNT)
        return {
            "internal_key": internal_key,
            "tap": tap,
            "funding_tx": funding_tx,
            "prevout": funding_tx.vout[0],
            "outpoint": COutPoint(int(funding_tx.txid_hex, 16), 0),
        }

    def build_positive_block(self, node, fixture):
        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(fixture["outpoint"], nSequence=SEQUENCE_FINAL)]
        spend_tx.vout = [CTxOut(fixture["prevout"].nValue - OUTPUT_FEE, CScript([OP_TRUE]))]
        spend_tx.wit.vtxinwit = [CTxInWitness()]

        signature = sign_segwitv0_input_pq(
            spend_tx,
            fixture["revealed_script"],
            fixture["prevout"].nValue,
            fixture["sk_seed"],
            fixture["pk_script"],
        )
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [signature, bytes(fixture["revealed_script"])]
        spend_tx = tx_from_hex(spend_tx.serialize().hex())

        next_height = node.getblockcount() + 1
        block_time = self.advance_network_mocktime()
        block = create_block(
            int(node.getbestblockhash(), 16),
            create_coinbase(next_height),
            block_time,
            txlist=[spend_tx],
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def build_negative_control_block(self, node, fixture):
        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(fixture["outpoint"], nSequence=SEQUENCE_FINAL)]
        spend_tx.vout = [CTxOut(fixture["prevout"].nValue - OUTPUT_FEE, CScript([OP_TRUE]))]
        spend_tx.wit.vtxinwit = [CTxInWitness()]

        sighash = TaprootSignatureHash(spend_tx, [fixture["prevout"]], SIGHASH_DEFAULT, 0, scriptpath=False)
        tweaked_key = tweak_add_privkey(fixture["internal_key"], fixture["tap"].tweak)
        assert tweaked_key is not None
        signature = sign_schnorr(tweaked_key, sighash, aux=bytes([0] * 32))
        spend_tx.wit.vtxinwit[0].scriptWitness.stack = [signature]
        spend_tx = tx_from_hex(spend_tx.serialize().hex())

        next_height = node.getblockcount() + 1
        block_time = self.advance_network_mocktime()
        block = create_block(
            int(node.getbestblockhash(), 16),
            create_coinbase(next_height),
            block_time,
            txlist=[spend_tx],
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        dep = self.nodes[0].getdeploymentinfo()["deployments"][TAPROOT_REPLACEMENT_NAME]
        if dep["active"] and dep["bip9"]["status"] == "active":
            raise SkipTest("legacy-aligned regtest keeps taproot_replacement active from genesis")

        self.log.info("Restart node1 with active vbparams before building any fixture blocks")
        self.restart_active_node()

        self.log.info("Disconnect node0 while building raw funding fixtures on the signaling node")
        self.disconnect_nodes(0, 1)

        self.log.info("Build one raw PQ-native replacement output and one inherited Taproot negative-control output")
        positive_fixture = self.build_positive_fixture()
        negative_fixture = self.build_negative_control_fixture()

        self.log.info("Mine a shared raw funding block with both fixtures")
        self.mine_block_with_txs(
            self.nodes[1],
            [positive_fixture["funding_tx"], negative_fixture["funding_tx"]],
        )

        self.log.info("Reconnect node0 and mine plain blocks on the signaling node to the active boundary")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.mine_plain_blocks(self.nodes[1], ACTIVE_HEIGHT, sync_fun=self.sync_blocks)
        self.assert_same_chain_active_boundary()

        self.log.info("Mine one additional plain block inside ACTIVE_REPLACEMENT before exercising semantics")
        self.mine_plain_blocks(self.nodes[1], POST_ACTIVE_HEIGHT, sync_fun=self.sync_blocks)
        shared_tip = self.nodes[1].getbestblockhash()
        assert_equal(shared_tip, self.nodes[0].getbestblockhash())

        self.log.info("Disconnect peers before submitting the raw semantic fixtures")
        self.disconnect_nodes(0, 1)

        self.log.info("Assert the active node still rejects the inherited Taproot negative-control block")
        negative_block = self.build_negative_control_block(self.nodes[1], negative_fixture)
        self.submit_block(
            self.nodes[1],
            negative_block,
            expect_accept=False,
            reject_reason=ACTIVE_GUARD_REJECT_REASON,
        )
        assert_equal(self.nodes[1].getbestblockhash(), shared_tip)

        self.log.info("Assert the active node accepts the first positive PQ-native replacement block")
        positive_block = self.build_positive_block(self.nodes[1], positive_fixture)
        self.submit_block(self.nodes[1], positive_block, expect_accept=True)

        self.log.info("Assert the defined node rejects the same positive replacement block")
        self.submit_block(self.nodes[0], positive_block, expect_accept=False)
        assert self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash()


if __name__ == '__main__':
    TaprootReplacementActivePositiveSeamTest(__file__).main()
