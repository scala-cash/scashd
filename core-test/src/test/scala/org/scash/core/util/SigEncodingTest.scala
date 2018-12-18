package org.scash.core.util

import org.scalatest.{ FlatSpec, MustMatchers }
import org.scash.core.crypto.{ ECPublicKey, SigEncoding }

class SigEncodingTest extends FlatSpec with MustMatchers {
  it must "check a public key's encoding" in {
    //pubkeys must be compressed or uncompressed or else that are not validly encoded
    val key = ECPublicKey("00")
    val program = TestUtil.testProgram
    SigEncoding.checkPubKeyEncoding(key, program.flags).isLeft must be(true)
  }
}
