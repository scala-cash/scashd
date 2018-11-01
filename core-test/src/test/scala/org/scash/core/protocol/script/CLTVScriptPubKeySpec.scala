package org.scash.core.protocol.script

import org.scash.core.gen.ScriptGenerators
import org.scalacheck.{ Properties, Prop }

/**
 * Created by tom on 8/23/16.
 */
class CLTVScriptPubKeySpec extends Properties("CLTVScriptPubKeySpec") {
  property("Serialization symmetry") =
    Prop.forAll(ScriptGenerators.cltvScriptPubKey) {
      case (cltvScriptPubKey, _) =>
        CLTVScriptPubKey(cltvScriptPubKey.hex) == cltvScriptPubKey
    }
}
