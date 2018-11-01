package org.scash.core.protocol.blockchain

import org.scash.core.gen.BlockchainElementsGenerator
import org.scash.core.util.BitcoinSLogger
import org.scalacheck.{ Prop, Properties }

/**
 * Created by tom on 7/6/16.
 */
class BlockSpec extends Properties("BlockSpec") {
  private val logger = BitcoinSLogger.logger

  property("Serialization symmetry") =
    Prop.forAll(BlockchainElementsGenerator.block) { block =>
      val result = Block(block.hex) == block
      if (!result) logger.warn("block.hex: " + block.hex)
      result
    }
}
