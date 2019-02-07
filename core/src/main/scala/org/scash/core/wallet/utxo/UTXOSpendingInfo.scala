package org.scash.core.wallet.utxo

import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.{ TransactionOutPoint, TransactionOutput }
import org.scash.core.script.crypto.SigHashType
import org.scash.core.crypto.Sign

/**
 * Contains the information required to spend a unspent transaction output (UTXO)
 * on a blockchain.
 */
sealed abstract class UTXOSpendingInfo {
  /** The funding transaction's txid and the index of the output in the transaction we are spending */
  def outPoint: TransactionOutPoint
  /** the actual output itself we are spending */
  def output: TransactionOutput
  /** the signers needed to spend from the output above */
  def signers: Seq[Sign]
  /** a redeemScript, if required, to spend the output above */
  def redeemScriptOpt: Option[ScriptPubKey]

  def hashType: SigHashType
}

case class BitcoinUTXOSpendingInfo(
  outPoint: TransactionOutPoint,
  output: TransactionOutput,
  signers: Seq[Sign],
  redeemScriptOpt: Option[ScriptPubKey],
  hashType: SigHashType) extends UTXOSpendingInfo

