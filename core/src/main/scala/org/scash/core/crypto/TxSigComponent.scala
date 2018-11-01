package org.scash.core.crypto

import org.scash.core.protocol.transaction._
import org.scash.core.script.flag.ScriptFlag
import org.scash.core.currency.CurrencyUnit
import org.scash.core.number.UInt32
import org.scash.core.protocol.script.{ ScriptPubKey, ScriptSignature }

/**
 * Created by chris on 4/6/16.
 * Represents a transaction whose input is being checked against the spending conditions of a [[ScriptPubKey]]
 */
sealed abstract class TxSigComponent {

  /** The transaction being checked for the validity of signatures */
  def transaction: Transaction

  /** The index of the input whose script signature is being checked */
  def inputIndex: UInt32

  def input: TransactionInput = transaction.inputs(inputIndex.toInt)

  /** The script signature being checked */
  def scriptSignature: ScriptSignature = input.scriptSignature

  /** This is the output we are spending. We need this for script and digital signatures checks */
  def output: TransactionOutput

  /** The scriptPubKey for which the input is being checked against */
  def scriptPubKey: ScriptPubKey = output.scriptPubKey

  /** The amount of [[CurrencyUnit]] we are spending in this TxSigComponent */
  def amount: CurrencyUnit = output.value

  /** The flags that are needed to verify if the signature is correct */
  def flags: Seq[ScriptFlag]
}

object TxSigComponent {

  private case class TxSigComponentImpl(
    transaction: Transaction,
    inputIndex: UInt32,
    output: TransactionOutput,
    flags: Seq[ScriptFlag]) extends TxSigComponent

  def apply(
    transaction: Transaction,
    inputIndex: UInt32,
    output: TransactionOutput,
    flags: Seq[ScriptFlag]): TxSigComponent = TxSigComponentImpl(transaction, inputIndex, output, flags)

}
