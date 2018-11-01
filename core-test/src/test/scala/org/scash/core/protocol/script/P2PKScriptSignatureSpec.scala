package org.scash.core.protocol.script

import org.scash.core.gen.ScriptGenerators
import org.scash.core.util.BitcoinSLogger
import org.scalacheck.{ Prop, Properties }

/**
 * Created by chris on 6/22/16.
 */
class P2PKScriptSignatureSpec extends Properties("P2PKSpec") {
  private def logger = BitcoinSLogger.logger

  property("Serialization symmetry") =
    Prop.forAll(ScriptGenerators.p2pkScriptSignature) { p2pkScriptSig =>
      P2PKScriptSignature(p2pkScriptSig.hex) == p2pkScriptSig
    }
}
