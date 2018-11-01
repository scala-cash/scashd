package org.scash.core.protocol.script

import org.scash.core.gen.ScriptGenerators
import org.scalacheck.{ Prop, Properties }

class ScriptSpec extends Properties("ScriptSpec") {

  property("serialization symmetry for ScriptFactory.fromAsmBytes") = {
    Prop.forAllNoShrink(ScriptGenerators.scriptPubKey) {
      case (spk, _) =>
        ScriptPubKey.fromAsmBytes(spk.asmBytes) == spk
    }
  }

  property("serialization symmetry for ScriptFactory.fromAsmBytes") = {
    Prop.forAllNoShrink(ScriptGenerators.scriptSignature) {
      case ss =>
        ScriptSignature.fromAsmBytes(ss.asmBytes) == ss
    }
  }
}
