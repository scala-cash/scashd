package org.scash.core.protocol.script

import org.scash.core.crypto.ECDigitalSignature
import org.scash.core.script.crypto.{ BaseHashType, SigHashType }
import org.scash.core.util.TestUtil
import org.scalatest.{ FlatSpec, MustMatchers }

/**
 * Created by chris on 4/1/16.
 */
class P2PKHScriptSignatureTest extends FlatSpec with MustMatchers {

  "P2PKHScriptSignature" must "be able to identify it's own hash type" in {
    val p2pkhScriptSig = TestUtil.p2pkhScriptSig match {
      case s: P2PKHScriptSignature => s
      case _ => throw new RuntimeException("Must be p2pkh scriptSig")
    }
    SigHashType(p2pkhScriptSig.signatures.head.bytes.last) must be(SigHashType(BaseHashType.ALL))
  }

  it must "be able to identify the signature in a p2pkh scriptSig" in {
    val p2pkhScriptSig = TestUtil.p2pkhScriptSig match {
      case s: P2PKHScriptSignature => s
      case _ => throw new RuntimeException("Must be p2pkh scriptSig")
    }
    p2pkhScriptSig.signature must be(ECDigitalSignature("3044022016ffdbb7c57634903c5e018fcfc48d59f4e37dc4bc3bbc9ba4e6ee39150bca030220119c2241a931819bc1a75d3596e4029d803d1cd6de123bf8a1a1a2c3665e1fac01"))
  }

}
