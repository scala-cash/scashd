package org.scash.core.protocol.script

import org.scalacheck.{Prop, Properties}
import org.scash.testkit.gen.ScriptGenerators

/**
 * Created by chris on 6/22/16.
 */
class P2PKScriptPubKeySpec extends Properties("P2PKScriptPubKeySpec") {

  property("Serialization symmetry") =
    Prop.forAll(ScriptGenerators.p2pkScriptPubKey) {
      case (p2pkScriptPubKey, _) =>
        P2PKScriptPubKey(p2pkScriptPubKey.hex) == p2pkScriptPubKey

    }
}
