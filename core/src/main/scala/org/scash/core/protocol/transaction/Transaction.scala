package org.scash.core.protocol.transaction

import org.scash.core.crypto.DoubleSha256Digest
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.protocol.NetworkElement
import org.scash.core.serializers.transaction.RawBaseTransactionParser
import org.scash.core.util.{ CryptoUtil, Factory }
import scodec.bits.ByteVector

/**
 * Created by chris on 7/14/15.
 */
sealed abstract class Transaction extends NetworkElement {
  /**
   * The sha256(sha256(tx)) of this transaction
   * Note that this is the little endian encoding of the hash, NOT the big endian encoding shown in block
   * explorers. See this link for more info
   * [[https://bitcoin.stackexchange.com/questions/2063/why-does-the-bitcoin-protocol-use-the-little-endian-notation]]
   */
  def txId: DoubleSha256Digest = CryptoUtil.doubleSHA256(bytes)

  /**
   * This is the BIG ENDIAN encoding for the txid. This is commonly used for
   * RPC interfaces and block explorers, this encoding is NOT used at the protocol level
   * For more info see:
   * [[https://bitcoin.stackexchange.com/questions/2063/why-does-the-bitcoin-protocol-use-the-little-endian-notation]]
   * @return
   */
  def txIdBE: DoubleSha256Digest = txId.flip

  /** The version number for this transaction */
  def version: Int32

  /** The inputs for this transaction */
  def inputs: Seq[TransactionInput]

  /** The outputs for this transaction */
  def outputs: Seq[TransactionOutput]

  /** The locktime for this transaction */
  def lockTime: UInt32

  /** Determines if this transaction is a coinbase transaction. */
  def isCoinbase: Boolean = inputs.size match {
    case 1 => inputs.head match {
      case _: CoinbaseInput => true
      case _: TransactionInput => false
    }
    case _: Int => false
  }
}

sealed abstract class BaseTransaction extends Transaction {
  override def bytes = RawBaseTransactionParser.write(this)
}

case object EmptyTransaction extends BaseTransaction {
  override def txId = CryptoUtil.emptyDoubleSha256Hash
  override def version = TransactionConstants.version
  override def inputs = Nil
  override def outputs = Nil
  override def lockTime = TransactionConstants.lockTime
}

object Transaction extends Factory[Transaction] {

  def fromBytes(bytes: ByteVector): Transaction = RawBaseTransactionParser.read(bytes)
}

object BaseTransaction extends Factory[BaseTransaction] {
  private case class BaseTransactionImpl(version: Int32, inputs: Seq[TransactionInput],
    outputs: Seq[TransactionOutput], lockTime: UInt32) extends BaseTransaction

  override def fromBytes(bytes: ByteVector): BaseTransaction = RawBaseTransactionParser.read(bytes)

  def apply(version: Int32, inputs: Seq[TransactionInput],
    outputs: Seq[TransactionOutput], lockTime: UInt32): BaseTransaction = BaseTransactionImpl(version, inputs, outputs, lockTime)
}

