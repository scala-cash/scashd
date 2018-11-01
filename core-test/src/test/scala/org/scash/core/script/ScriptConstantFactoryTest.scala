package org.scash.core.script

import org.scash.core.script.constant.ScriptConstant
import org.scash.core.util.BitcoinSUtil
import org.scalatest.{ MustMatchers, FlatSpec }

/**
 * Created by chris on 4/1/16.
 */
class ScriptConstantFactoryTest extends FlatSpec with MustMatchers {

  "ScriptConstantFactory" must "create a constant from bytes" in {
    val bytes = BitcoinSUtil.decodeHex("abc123")
    ScriptConstant(bytes).bytes must be(bytes)
  }

}
