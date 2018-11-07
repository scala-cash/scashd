package org.scash.core.consensus
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.currency.{ CurrencyUnit, Satoshis }
import org.scash.core.number.Int64

/**
 * Consensus constants and helpers for scash
 */
object Consensus {

  /** 1mb */
  val oneMB = 1000000

  /**
   * The maximum allowed size for a transaction, in bytes
   * MAX_TX_SIZE
   */
  val maxTxSize = oneMB

  /**
   * The maximum allowed size for a transaction, in bytes
   * MIN_TX_SIZE
   */
  val minTxSize = 100

  /**
   * The maximum allowed size for a block, before the UAHF
   * LEGACY_MAX_BLOCK_SIZE
   */
  val legacyMaxBlockSize = oneMB

  /**
   * The maximum allowed size default value for a block
   * DEFAULT_MAX_BLOCK_SIZE
   */
  val maxBlockSize = 32 * oneMB

  /**
   * BIP141 changes this from 20,000 -> 80,000, to see how sigops are counted please see BIP 141
   * allowed number of signature check operations per transaction.
   * MAX_BLOCK_SIGOPS_PER_MB
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/uahf-technical-spec.md]]
   */
  val maxBlockSigOpsPerMB = 20000

  /**
   * allowed number of signature check operations per transaction.
   * MAX_TX_SIGOPS_COUNT
   */
  val maxTxSigOpsCount = 20000

  val coin = Satoshis(Int64(100000000L))
  /**
   * Maximum amount of money in satoshis
   * 21million * 1btc (consensus).
   */
  val maxMoney: CurrencyUnit = Satoshis(Int64(2100000000000000L))

  /**
   * A integer representing the maximum number of public keys you can have in a
   * OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY operation
   * https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L903
   * MAX_PUBKEYS_PER_MULTISIG
   */
  val maxPublicKeysPerMultiSig = 20

  /**
   * Max number of bytes pushable to the stack
   * MAX_SCRIPT_ELEMENT_SIZE
   */
  val maxScriptElementSize = 520

  /**
   * Currently bitcoin cash limits the maximum number of non-push operations per script
   * to 201
   * MAX_OPS_PER_SCRIPT
   */
  val maxScriptOps = 201

  /**
   * Max script length in bytes
   * MAX_SCRIPT_SIZE
   */
  val maxScriptSize = 10000
  /**
   * Compute the maximum number of sigops operation that can contained in a block
   * given the block size as parameter. It is computed by multiplying
   * MAX_BLOCK_SIGOPS_PER_MB by the size of the block in MB rounded up to the
   * closest integer.
   */
  def getMaxBlockSizeOpsCount(blockSize: BigInt) = {
    val nMbRoundedUp = 1 + ((blockSize - 1) / oneMB)
    nMbRoundedUp * maxBlockSigOpsPerMB
  }
}
