package org.scash.core.script.crypto

import org.scash.core.gen.NumberGenerator
import org.scalacheck.{ Prop, Properties }

class SigHashTypeSpec extends Properties("SigHashTypeSpec") {

  property("serialization symmetry") = {
    Prop.forAll(NumberGenerator.int32s) { i32 =>
      val hashType = SigHashType.from4Bytes(i32.bytes)
      hashType.serialize.head == i32.bytes.last &&
        i32.bytes.last == hashType.byte &&
        SigHashType(hashType.byte).byte == hashType.byte

    }
  }
}
