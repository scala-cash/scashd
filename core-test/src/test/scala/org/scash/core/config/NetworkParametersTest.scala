package org.scash.core.config

import org.scash.core.util.BitcoinSUtil
import org.scalatest.{ FlatSpec, MustMatchers }

/**
 * Created by chris on 6/10/16.
 */
class NetworkParametersTest extends FlatSpec with MustMatchers {

  //test case answers are from this link
  //https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
  "NetworkParameters" must "create the correct magic network bytes for mainnet" in {
    MainNet.magicBytes.toHex must be("e3e1f3e8")
  }

  it must "create the correct magic network bytes for testnet" in {
    TestNet3.magicBytes.toHex must be("f4e5f3f4".toLowerCase)
  }

  it must "create the correct magic network bytes for regtest" in {
    RegTest.magicBytes.toHex must be("dab5bffa")
  }
}
