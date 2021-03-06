package org.scash.core.protocol.script

import org.scalatest.{FlatSpec, MustMatchers}
import org.scash.testkit.gen.CryptoGenerators

/**
 * Created by chris on 9/22/16.
 */
class P2PKHScriptPubKeyTest extends FlatSpec with MustMatchers {

  "P2PKHScriptPubKey" must "return the pubkeyhash" in {
    val hash = CryptoGenerators.sha256Hash160Digest.sample.get
    val p2pkhScriptPubKey = P2PKHScriptPubKey(hash)
    p2pkhScriptPubKey.pubKeyHash must be(hash)
  }
}
