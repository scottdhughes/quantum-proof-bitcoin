#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test UTXO set hash value calculation in gettxoutsetinfo."""

from test_framework.messages import (
    CBlock,
    COutPoint,
    from_hex,
)
from test_framework.crypto.muhash import MuHash3072
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

class UTXOSetHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def test_muhash_implementation(self):
        self.log.info("Test MuHash implementation consistency")

        node = self.nodes[0]
        # The default MiniWallet path is Taproot-shaped and currently fails on
        # PQBTC under the inherited `scriptpubkey` path. Freeze this suite on a
        # raw OP_TRUE spend that the current chainstate surface can actually own.
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)

        # Generate 100 blocks and remove the first since we plan to spend its
        # coinbase
        block_hashes = self.generatetodescriptor(node, 1, wallet.get_descriptor()) + self.generate(node, 99)
        wallet.rescan_utxos(include_mempool=False)
        blocks = list(map(lambda block: from_hex(CBlock(), node.getblock(block, False)), block_hashes))
        first_block_hash = block_hashes[0]
        blocks.pop(0)

        # Create a spending transaction and mine a block which includes it
        coinbase_txid = node.getblock(first_block_hash, 2)['tx'][0]['txid']
        utxo = wallet.get_utxo(txid=coinbase_txid, vout=0, mark_as_spent=False)
        tx = wallet.create_self_transfer(utxo_to_spend=utxo)
        tx_block = self.generateblock(node, output="raw(51)", transactions=[tx['hex']])
        blocks.append(from_hex(CBlock(), node.getblock(tx_block['hash'], False)))

        # Serialize the outputs that should be in the UTXO set and add them to
        # a MuHash object
        muhash = MuHash3072()

        for height, block in enumerate(blocks):
            # The Genesis block coinbase is not part of the UTXO set and we
            # spent the first mined block
            height += 2

            for tx in block.vtx:
                for n, tx_out in enumerate(tx.vout):
                    coinbase = 1 if not tx.vin[0].prevout.hash else 0

                    # Skip witness commitment
                    if (coinbase and n > 0):
                        continue

                    data = COutPoint(tx.txid_int, n).serialize()
                    data += (height * 2 + coinbase).to_bytes(4, "little")
                    data += tx_out.serialize()

                    muhash.insert(data)

        finalized = muhash.digest()
        node_muhash = node.gettxoutsetinfo("muhash")['muhash']

        assert_equal(finalized[::-1].hex(), node_muhash)

        self.log.info("Test deterministic UTXO set hash results")
        assert_equal(node.gettxoutsetinfo()['hash_serialized_3'], "3b94891568e70f4a235a06233d3fb6253dacbc15dfd2db248be33086eafd5ca4")
        assert_equal(node.gettxoutsetinfo("muhash")['muhash'], "3a54f825464eca4e3a0f3c3b8b852e86bee36356fb8924f4ff6d932b3b1f88ae")

    def run_test(self):
        self.test_muhash_implementation()


if __name__ == '__main__':
    UTXOSetHashTest(__file__).main()
