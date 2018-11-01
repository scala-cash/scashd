package org.scash.core.consensus

import org.scash.core.currency.{ CurrencyUnit, Satoshis }
import org.scash.core.number.Int64

/**
 * Created by chris on 5/13/16.
 */
sealed abstract class Consensus {

  def maxBlockSize: Long = 1000000

  /**
   * BIP141 changes this from 20,000 -> 80,000, to see how sigops are counted please see BIP 141
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/uahf-technical-spec.md]]
   */
  def maxSigOps = 20000

  def maxMoney: CurrencyUnit = Satoshis(Int64(2100000000000000L))

  /**
   * A integer representing the maximum number of public keys you can have in a
   * OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY operation
   * https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L903
   * @return
   */
  def maxPublicKeysPerMultiSig = 20
}

object Consensus extends Consensus
