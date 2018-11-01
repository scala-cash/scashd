package org.scash.core.protocol.transaction

import org.scash.core.gen.TransactionGenerators
import org.scash.core.util.{ BitcoinSLogger, CryptoUtil }
import org.scalacheck.{ Prop, Properties }

/**
 * Created by chris on 6/24/16.
 */
class TransactionSpec extends Properties("TransactionSpec") {
  private val logger = BitcoinSLogger.logger

  property("Serialization symmetry") =
    Prop.forAll(TransactionGenerators.transaction) { tx =>
      val result = Transaction(tx.hex) == tx
      if (!result) {
        logger.error(s"tx: $tx")
        logger.error("Incorrect tx hex: " + tx.hex)
      }
      result
    }

  property("txid of a base transaction must be SHA256(SHA256(hex)) of a btx") =
    Prop.forAll(TransactionGenerators.baseTransaction) { btx: BaseTransaction =>
      btx.txId == CryptoUtil.doubleSHA256(btx.hex)
    }

}
