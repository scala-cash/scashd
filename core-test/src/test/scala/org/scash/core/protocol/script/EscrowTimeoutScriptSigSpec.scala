package org.scash.core.protocol.script

import org.scash.core.gen.ScriptGenerators
import org.scalacheck.{ Prop, Properties }

/**
 * Created by chris on 3/28/17.
 */
class EscrowTimeoutScriptSigSpec extends Properties("EscrowWithTimeoutScriptSigSpec") {

  property("serialization symmetry") =
    Prop.forAll(ScriptGenerators.escrowTimeoutScriptSig) { scriptSig =>
      EscrowTimeoutScriptSignature(scriptSig.hex) == scriptSig &&
        EscrowTimeoutScriptSignature.fromAsm(scriptSig.asm) == scriptSig
    }
}
