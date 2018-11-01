package org.scash.core.protocol.script

import org.scash.core.script.bitwise.OP_EQUALVERIFY
import org.scash.core.script.constant._
import org.scash.core.script.crypto.{ OP_CHECKSIG, OP_HASH160 }
import org.scash.core.script.stack.OP_DUP
import org.scash.core.util.TestUtil
import org.scalatest.{ FlatSpec, MustMatchers }

/**
 * Created by chris on 1/14/16.
 */
class ScriptPubKeyTest extends FlatSpec with MustMatchers {
  val expectedAsm: Seq[ScriptToken] =
    List(OP_DUP, OP_HASH160, BytesToPushOntoStack(20), ScriptConstant("31a420903c05a0a7de2de40c9f02ebedbacdc172"), OP_EQUALVERIFY, OP_CHECKSIG)
  //from b30d3148927f620f5b1228ba941c211fdabdae75d0ba0b688a58accbf018f3cc
  val rawScriptPubKey = TestUtil.rawP2PKHScriptPubKey
  val scriptPubKey = ScriptPubKey(rawScriptPubKey)

  "ScriptPubKey" must "give the expected asm from creating a scriptPubKey from hex" in {
    scriptPubKey.asm must be(expectedAsm)
  }
}

