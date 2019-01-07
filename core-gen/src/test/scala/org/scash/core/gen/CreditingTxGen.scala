package org.scash.core.gen

import org.scalacheck.Gen
import org.scash.core.crypto.Sign
import org.scash.core.number.UInt32
import org.scash.core.protocol.script.{ CLTVScriptPubKey, CSVScriptPubKey, P2SHScriptPubKey, ScriptPubKey }
import org.scash.core.protocol.transaction.{ BaseTransaction, TransactionConstants, TransactionOutPoint, TransactionOutput }
import org.scash.core.script.crypto.HashType
import org.scash.core.wallet.utxo.BitcoinUTXOSpendingInfo

sealed abstract class CreditingTxGen {
  /** Minimum amount of outputs to generate */
  private val min = 1
  /** Maximum amount of outputs to generate */
  private val max = 3

  /** Note this generator does NOT generate outputs with negative values */
  private def nonEmptyOutputs: Gen[Seq[TransactionOutput]] = Gen.choose(1, 5).flatMap { n =>
    Gen.listOfN(n, TransactionGenerators.realisticOutput)
  }

  def rawOutput: Gen[BitcoinUTXOSpendingInfo] = {
    Gen.oneOf(p2pkOutput, p2pkhOutput, multiSigOutput, csvOutput)
  }

  def rawOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = Gen.choose(min, max).flatMap(n => Gen.listOfN(n, rawOutput))

  def basicOutput: Gen[BitcoinUTXOSpendingInfo] = {
    Gen.oneOf(p2pkOutput, p2pkhOutput, multiSigOutput)
  }

  def nonP2WSHOutput: Gen[BitcoinUTXOSpendingInfo] = rawOutput

  def output: Gen[BitcoinUTXOSpendingInfo] = Gen.oneOf(
    p2pkOutput,
    p2pkhOutput, multiSigOutput, p2shOutput,
    csvOutput)

  def outputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = {
    Gen.choose(min, 5).flatMap(n => Gen.listOfN(n, output))
  }

  /** Generates a crediting tx with a p2pk spk at the returned index */
  def p2pkOutput: Gen[BitcoinUTXOSpendingInfo] = ScriptGenerators.p2pkScriptPubKey.flatMap { p2pk =>
    build(p2pk._1, Seq(p2pk._2))
  }

  /** Generates multiple crediting txs with p2pk spks at the returned index */
  def p2pkOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = {
    Gen.choose(min, max).flatMap(n => Gen.listOfN(n, p2pkOutput))
  }

  /**
   * Generates a transaction that has a p2pkh output at the returned index. This
   * output can be spent by the returned ECPrivateKey
   */
  def p2pkhOutput: Gen[BitcoinUTXOSpendingInfo] = ScriptGenerators.p2pkhScriptPubKey.flatMap { p2pkh =>
    build(p2pkh._1, Seq(p2pkh._2))
  }

  /** Generates a sequence of p2pkh outputs at the returned index */
  def p2pkhOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = {
    Gen.choose(min, max).flatMap(n => Gen.listOfN(n, p2pkhOutput))
  }

  def multiSigOutput: Gen[BitcoinUTXOSpendingInfo] = ScriptGenerators.multiSigScriptPubKey.flatMap { multisig =>
    build(multisig._1, multisig._2)
  }

  def multiSigOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = {
    Gen.choose(min, max).flatMap(n => Gen.listOfN(n, multiSigOutput))
  }

  def p2shOutput: Gen[BitcoinUTXOSpendingInfo] = rawOutput.flatMap { o =>
    CryptoGenerators.forkIdHashType.map { hashType =>
      val oldOutput = o.output
      val redeemScript = o.output.scriptPubKey
      val p2sh = P2SHScriptPubKey(redeemScript)
      val updatedOutput = TransactionOutput(oldOutput.value, p2sh)
      BitcoinUTXOSpendingInfo(TransactionOutPoint(o.outPoint.txId, o.outPoint.vout), updatedOutput, o.signers, Some(redeemScript), hashType)
    }
  }

  def p2shOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = {
    Gen.choose(min, max).flatMap(n => Gen.listOfN(n, p2shOutput))
  }

  def cltvOutput: Gen[BitcoinUTXOSpendingInfo] = TransactionGenerators.spendableCLTVValues.flatMap {
    case (scriptNum, _) =>
      basicOutput.flatMap { o =>
        CryptoGenerators.forkIdHashType.map { hashType =>
          val oldOutput = o.output
          val csvSPK = CLTVScriptPubKey(scriptNum, oldOutput.scriptPubKey)
          val updatedOutput = TransactionOutput(oldOutput.value, csvSPK)
          BitcoinUTXOSpendingInfo(TransactionOutPoint(o.outPoint.txId, o.outPoint.vout), updatedOutput, o.signers, o.redeemScriptOpt, hashType)
        }
      }
  }

  def cltvOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = Gen.choose(min, max).flatMap(n => Gen.listOfN(n, cltvOutput))

  def csvOutput: Gen[BitcoinUTXOSpendingInfo] = TransactionGenerators.spendableCSVValues.flatMap {
    case (scriptNum, _) =>
      basicOutput.flatMap { o =>
        CryptoGenerators.forkIdHashType.map { hashType =>
          val oldOutput = o.output
          val csvSPK = CSVScriptPubKey(scriptNum, oldOutput.scriptPubKey)
          val updatedOutput = TransactionOutput(oldOutput.value, csvSPK)
          BitcoinUTXOSpendingInfo(TransactionOutPoint(o.outPoint.txId, o.outPoint.vout), updatedOutput, o.signers, o.redeemScriptOpt, hashType)
        }
      }
  }

  def csvOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = Gen.choose(min, max).flatMap(n => Gen.listOfN(n, csvOutput))

  /** A nested output is a p2sh wrapped output */
  def nestedOutput: Gen[BitcoinUTXOSpendingInfo] = p2shOutput

  def nestedOutputs: Gen[Seq[BitcoinUTXOSpendingInfo]] = Gen.choose(min, max).flatMap(n => Gen.listOfN(n, nestedOutput))

  def random: Gen[BitcoinUTXOSpendingInfo] = nonEmptyOutputs.flatMap { outputs =>
    Gen.choose(0, outputs.size - 1).flatMap { outputIndex: Int =>
      ScriptGenerators.scriptPubKey.flatMap {
        case (spk, keys) =>
          CryptoGenerators.forkIdHashType.map { hashType: HashType =>
            val tc = TransactionConstants
            val signers: Seq[Sign] = keys
            val creditingTx = BaseTransaction(tc.validLockVersion, Nil, outputs, tc.lockTime)
            BitcoinUTXOSpendingInfo(
              TransactionOutPoint(creditingTx.txId, UInt32.apply(outputIndex)),
              TransactionOutput(
                creditingTx.outputs(outputIndex).value,
                creditingTx.outputs(outputIndex).scriptPubKey),
              signers,
              Some(spk),
              hashType)
          }
      }
    }
  }

  def randoms: Gen[Seq[BitcoinUTXOSpendingInfo]] = Gen.choose(min, max).flatMap(n => Gen.listOfN(n, random))

  private def build(
    spk: ScriptPubKey,
    signers: Seq[Sign]): Gen[BitcoinUTXOSpendingInfo] = nonEmptyOutputs.flatMap { outputs =>
    CryptoGenerators.forkIdHashType.flatMap { hashType =>
      Gen.choose(0, outputs.size - 1).map { idx =>
        val old = outputs(idx)
        val updated = outputs.updated(idx, TransactionOutput(old.value, spk))
        val tc = TransactionConstants
        val btx = BaseTransaction(tc.version, Nil, updated, tc.lockTime)
        BitcoinUTXOSpendingInfo(TransactionOutPoint(btx.txId, UInt32.apply(idx)), TransactionOutput(old.value, spk), signers, None, hashType)
      }
    }
  }
}

object CreditingTxGen extends CreditingTxGen {
}
