package org.scash.core.wallet.builder

import org.scash.core.config.TestNet3
import org.scash.core.currency.{ CurrencyUnits, Satoshis }
import org.scash.core.gen.ScriptGenerators
import org.scash.core.number.{ Int64, UInt32 }
import org.scash.core.protocol.script._
import org.scash.core.protocol.transaction._
import org.scash.core.script.crypto.HashType
import org.scash.core.util.BitcoinSLogger
import org.scash.core.wallet.fee.SatoshisPerByte
import org.scash.core.wallet.utxo.BitcoinUTXOSpendingInfo
import org.scalatest.{ AsyncFlatSpec, MustMatchers }

class BitcoinTxBuilderTest extends AsyncFlatSpec with MustMatchers {
  private val logger = BitcoinSLogger.logger
  val tc = TransactionConstants
  val (spk, privKey) = ScriptGenerators.p2pkhScriptPubKey.sample.get
  "TxBuilder" must "failed to build a transaction that mints money out of thin air" in {

    val creditingOutput = TransactionOutput(CurrencyUnits.zero, spk)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)
    val feeUnit = SatoshisPerByte(Satoshis.one)
    val txBuilder = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    val resultFuture = txBuilder.flatMap(_.sign)
    recoverToSucceededIf[IllegalArgumentException] {
      resultFuture
    }
  }

  it must "fail to build a transaction when we pass in a negative fee rate" in {
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, spk)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)
    val feeUnit = SatoshisPerByte(Satoshis(Int64(-1)))
    val txBuilder = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    recoverToSucceededIf[IllegalArgumentException] {
      txBuilder
    }
  }

  it must "fail a transaction when the user invariants fail" in {
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, spk)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)
    val feeUnit = SatoshisPerByte(Satoshis(Int64(1)))
    val txBuilder = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    //trivially false
    val f = (_: Seq[BitcoinUTXOSpendingInfo], _: Transaction) => false
    val resultFuture = txBuilder.flatMap(_.sign(f))
    recoverToSucceededIf[IllegalArgumentException] {
      resultFuture
    }
  }

  it must "be able to create a BitcoinTxBuilder from UTXOTuple and UTXOMap" in {
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, spk)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)
    val utxoSpendingInfo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)

    val feeUnit = SatoshisPerByte(Satoshis(Int64(1)))
    val txBuilderMap = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    val txBuilderTuple = BitcoinTxBuilder(destinations, Seq(utxoSpendingInfo), feeUnit, EmptyScriptPubKey, TestNet3)

    txBuilderTuple.flatMap { tup =>
      txBuilderMap.map { map =>
        assert(map == tup)
      }
    }
  }

  it must "fail to build a tx if you have the wrong redeemscript" in {
    val p2sh = P2SHScriptPubKey(spk)
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, p2sh)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), Some(EmptyScriptPubKey), HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)
    val feeUnit = SatoshisPerByte(Satoshis(Int64(1)))
    val txBuilderNoRedeem = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    val resultFuture = txBuilderNoRedeem.flatMap(_.sign)
    recoverToSucceededIf[IllegalArgumentException] {
      resultFuture
    }
  }

  it must "fail to sign a p2pkh if we don't pass in the public key" in {
    val p2pkh = P2PKHScriptPubKey(privKey.publicKey)
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, p2pkh)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)

    val feeUnit = SatoshisPerByte(Satoshis(Int64(1)))
    val txBuilderWitness = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    val resultFuture = txBuilderWitness.flatMap(_.sign)
    recoverToSucceededIf[IllegalArgumentException] {
      resultFuture
    }
  }

  it must "fail to sign a p2pkh if we pass in the wrong public key" in {
    val p2pkh = P2PKHScriptPubKey(privKey.publicKey)
    val creditingOutput = TransactionOutput(CurrencyUnits.zero, p2pkh)
    val destinations = Seq(TransactionOutput(Satoshis(Int64(1)), EmptyScriptPubKey))
    val creditingTx = BaseTransaction(tc.validLockVersion, Nil, Seq(creditingOutput), tc.lockTime)
    val outPoint = TransactionOutPoint(creditingTx.txId, UInt32.zero)
    val utxo = BitcoinUTXOSpendingInfo(outPoint, creditingOutput, Seq(privKey), None, HashType.sigHashAll)
    val utxoMap: BitcoinTxBuilder.UTXOMap = Map(outPoint -> utxo)

    val feeUnit = SatoshisPerByte(Satoshis(Int64(1)))
    val txBuilderWitness = BitcoinTxBuilder(destinations, utxoMap, feeUnit, EmptyScriptPubKey, TestNet3)
    val resultFuture = txBuilderWitness.flatMap(_.sign)
    recoverToSucceededIf[IllegalArgumentException] {
      resultFuture
    }
  }
}
