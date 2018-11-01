package org.scash.core.wallet.builder

import org.scash.core.crypto.TxSigComponent
import org.scash.core.currency.{ CurrencyUnits, Satoshis }
import org.scash.core.gen.{ ChainParamsGenerator, CreditingTxGen, ScriptGenerators, TransactionGenerators }
import org.scash.core.number.{ Int64, UInt32 }
import org.scash.core.policy.Policy
import org.scash.core.protocol.script._
import org.scash.core.protocol.transaction._
import org.scash.core.script.PreExecutionScriptProgram
import org.scash.core.script.interpreter.ScriptInterpreter
import org.scash.core.util.BitcoinSLogger
import org.scash.core.wallet.fee.SatoshisPerByte
import org.scash.core.wallet.utxo.{ BitcoinUTXOSpendingInfo, UTXOSpendingInfo }
import org.scalacheck.{ Prop, Properties }

import scala.annotation.tailrec
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt
import scala.util.Try

class BitcoinTxBuilderSpec extends Properties("TxBuilderSpec") {
  private val logger = BitcoinSLogger.logger
  private val tc = TransactionConstants
  val timeout = 7.seconds
  property("sign a mix of spks in a tx and then have it verified") = {
    Prop.forAllNoShrink(CreditingTxGen.outputs) {
      case creditingTxsInfo =>
        val creditingOutputs = creditingTxsInfo.map(c => c.output)
        val creditingOutputsAmt = creditingOutputs.map(_.value)
        val totalAmount = creditingOutputsAmt.fold(CurrencyUnits.zero)(_ + _)
        Prop.forAllNoShrink(TransactionGenerators.smallOutputs(totalAmount), ScriptGenerators.scriptPubKey, ChainParamsGenerator.bitcoinNetworkParams) {
          case (destinations: Seq[TransactionOutput], changeSPK, network) =>
            val fee = SatoshisPerByte(Satoshis(Int64(1000)))
            val outpointsWithKeys = buildCreditingTxInfo(creditingTxsInfo)
            val builder = BitcoinTxBuilder(destinations, outpointsWithKeys, fee, changeSPK._1, network)
            val tx = Await.result(builder.flatMap(_.sign), timeout)
            verifyScript(tx, creditingTxsInfo)
        }
    }
  }

  property("sign a mix of p2sh in a tx and then have it verified") = {
    Prop.forAllNoShrink(CreditingTxGen.nestedOutputs) {
      case creditingTxsInfo =>
        val creditingOutputs = creditingTxsInfo.map(c => c.output)
        val creditingOutputsAmt = creditingOutputs.map(_.value)
        val totalAmount = creditingOutputsAmt.fold(CurrencyUnits.zero)(_ + _)
        Prop.forAll(TransactionGenerators.smallOutputs(totalAmount), ScriptGenerators.scriptPubKey, ChainParamsGenerator.bitcoinNetworkParams) {
          case (destinations: Seq[TransactionOutput], changeSPK, network) =>
            val fee = SatoshisPerByte(Satoshis(Int64(1000)))
            val outpointsWithKeys = buildCreditingTxInfo(creditingTxsInfo)
            val builder = BitcoinTxBuilder(destinations, outpointsWithKeys, fee, changeSPK._1, network)
            val tx = Await.result(builder.flatMap(_.sign), timeout)
            verifyScript(tx, creditingTxsInfo)
        }
    }
  }
  /*
  property("random fuzz test for tx builder") = {
    Prop.forAllNoShrink(CreditingTxGen.randoms) {
      case creditingTxsInfo =>
        val creditingOutputs = creditingTxsInfo.map(c => c.output)
        val creditingOutputsAmt = creditingOutputs.map(_.value)
        val totalAmount = creditingOutputsAmt.fold(CurrencyUnits.zero)(_ + _)
        Prop.forAllNoShrink(TransactionGenerators.smallOutputs(totalAmount), ScriptGenerators.scriptPubKey, ChainParamsGenerator.bitcoinNetworkParams) {
          case (destinations: Seq[TransactionOutput], changeSPK, network) =>
            val fee = SatoshisPerByte(Satoshis(Int64(1000)))
            val outpointsWithKeys = buildCreditingTxInfo(creditingTxsInfo)
            val builder = BitcoinTxBuilder(destinations, outpointsWithKeys, fee, changeSPK._1, network)
            val result = Try(Await.result(builder.flatMap(_.sign), timeout))
            if (result.isFailure) true else !verifyScript(result.get, creditingTxsInfo)
        }
    }
  }
*/
  private def buildCreditingTxInfo(info: Seq[BitcoinUTXOSpendingInfo]): BitcoinTxBuilder.UTXOMap = {
    @tailrec
    def loop(
      rem: Seq[BitcoinUTXOSpendingInfo],
      accum: BitcoinTxBuilder.UTXOMap): BitcoinTxBuilder.UTXOMap = rem match {
      case Nil => accum
      case BitcoinUTXOSpendingInfo(txOutPoint, txOutput, signers, redeemScriptOpt, hashType) :: t =>
        val o = txOutPoint
        val output = txOutput
        val outPointsSpendingInfo = BitcoinUTXOSpendingInfo(o, output, signers, redeemScriptOpt, hashType)
        loop(t, accum.updated(o, outPointsSpendingInfo))
    }
    loop(info, Map.empty)
  }

  def verifyScript(tx: Transaction, utxos: Seq[UTXOSpendingInfo]): Boolean = {
    val programs: Seq[PreExecutionScriptProgram] = tx.inputs.zipWithIndex.map {
      case (input: TransactionInput, idx: Int) =>
        val outpoint = input.previousOutput
        val creditingTx = utxos.find(u => u.outPoint.txId == outpoint.txId).get
        val output = creditingTx.output
        val spk = output.scriptPubKey
        val amount = output.value
        val txSigComponent = spk match {
          case x @ (_: P2PKScriptPubKey | _: P2PKHScriptPubKey | _: MultiSignatureScriptPubKey
            | _: CSVScriptPubKey | _: CLTVScriptPubKey | _: NonStandardScriptPubKey | _: EscrowTimeoutScriptPubKey
            | EmptyScriptPubKey) =>
            val o = TransactionOutput(CurrencyUnits.zero, x)
            TxSigComponent(tx, UInt32(idx), o, Policy.standardFlags)
          case p2sh: P2SHScriptPubKey =>
            val o = TransactionOutput(CurrencyUnits.zero, p2sh)
            TxSigComponent(tx, UInt32(idx), o, Policy.standardFlags)
        }
        PreExecutionScriptProgram(txSigComponent)
    }
    ScriptInterpreter.runAllVerify(programs)
  }
}