package org.scash.core.protocol.blockchain

import org.scash.core.gen.BlockchainElementsGenerator
import org.scalacheck.{ Prop, Properties }

/**
 * Created by tom on 7/6/16.
 */
class BlockHeaderSpec extends Properties("BlockHeaderSpec") {
  property("serialization symmetry") =
    Prop.forAll(BlockchainElementsGenerator.blockHeader) { header =>
      BlockHeader(header.hex) == header
    }
}
