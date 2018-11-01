package org.scash.core.protocol.transaction

import org.scash.core.gen.TransactionGenerators
import org.scash.core.util.BitcoinSLogger
import org.scalacheck.{ Prop, Properties }

/**
 * Created by chris on 6/24/16.
 */
class TransactionInputSpec extends Properties("TranactionInputSpec") {
  private val logger = BitcoinSLogger.logger
  property("Serialization symmetry") = {
    Prop.forAllNoShrink(TransactionGenerators.input) { input =>
      val result = TransactionInput(input.hex) == input
      result
    }
  }
}

