#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.messages import FromHex, ToHex
from test_framework.mininode import *
from test_framework.script import *
from test_framework.test_framework import DashTestFramework
from test_framework.util import *

'''
feature_dip0020_activation.py

This test checks activation of DIP0020 opcodes
'''

DISABLED_OPCODE_ERROR = "non-mandatory-script-verify-flag (Attempted to use a disabled opcode)"


class SpendableOutput:

    def __init__(self, tx=CTransaction(), n=-1):
        self.tx = tx
        self.n = n  # the output we're spending


def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    tx = CTransaction()
    assert (n < len(prevtx.vout))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(value, scriptPubKey))
    tx.calc_sha256()
    return tx


def create_tx(utxo, relayfee, script):
    tx = CTransaction()
    value = int(satoshi_round(utxo["amount"] - Decimal(relayfee)) * COIN)
    tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
    tx.vout = []
    tx.vout.append(CTxOut(value, script))
    return tx


class DIP0020ActivationTest(DashTestFramework):
    class PreviousSpendableOutput:
        def __init__(self, tx=CTransaction(), n=-1):
            self.tx = tx
            self.n = n  # the output we're spending

    def set_test_params(self):
        self.set_dash_test_params(2, 1, fast_dip3_enforcement=True)
        self.set_dash_dip8_activation(450)

    def run_test(self):
        self.node = self.nodes[0]
        self.relayfee = self.nodes[0].getnetworkinfo()["relayfee"]

        # First, we generate some coins to spend.
        self.node.generate(100)

        self.try_to_spend_dip0020_tx(expectFailure=True)

        # Generate enough blocks to activate DIP0020 opcodes.
        self.node.generate(200)

        self.try_to_spend_dip0020_tx(expectFailure=False)

    def try_to_spend_dip0020_tx(self, expectFailure):
        utxos = self.node.listunspent()
        assert (len(utxos) > 0)

        utxo = utxos[len(utxos) - 1]
        tx = create_tx(utxo, self.relayfee, CScript([b'1', b'2', OP_CAT]))
        tx_signed_hex = self.node.signrawtransaction(ToHex(tx))["hex"]
        txid = self.node.sendrawtransaction(tx_signed_hex)

        assert (txid in set(self.node.getrawmempool()))

        self.node.generate(1)

        assert (txid not in set(self.node.getrawmempool()))

        # register the spendable outputs.
        tx = FromHex(CTransaction(), tx_signed_hex)
        tx.rehash()
        spendable = [SpendableOutput(tx, i) for i in range(len(tx.vout))]

        def spend():
            outpoint = spendable.pop()
            out = outpoint.tx.vout[outpoint.n]
            value = int(out.nValue - (self.relayfee * COIN))
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(outpoint.tx.sha256, outpoint.n))]
            tx.vout = [CTxOut(value, CScript([]))]
            tx.rehash()
            return tx

        tx0 = spend()
        tx0_hex = ToHex(tx0)

        if expectFailure:
            assert_raises_rpc_error(-26, DISABLED_OPCODE_ERROR, self.node.sendrawtransaction, tx0_hex)
        else:
            tx0id = self.node.sendrawtransaction(tx0_hex)
            assert (tx0id in set(self.node.getrawmempool()))


if __name__ == '__main__':
    DIP0020ActivationTest().main()
