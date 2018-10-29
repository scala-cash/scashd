package org.scash.core.protocol.script.testprotocol

import org.scash.core.crypto.DoubleSha256Digest
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.script.crypto.HashType
import org.scash.core.serializers.script.ScriptParser
import spray.json._

/**
 * Created by tom on 7/21/16.
 */
object SignatureHashTestCaseProtocol extends DefaultJsonProtocol {
  implicit object SignatureTestCaseProtocol extends RootJsonFormat[SignatureHashTestCase] {
    override def read(value: JsValue): SignatureHashTestCase = {
      val jsArray: JsArray = value match {
        case array: JsArray => array
        case _: JsValue => throw new RuntimeException("Script signature hash test case must be in jsarray format")
      }
      val elements: Vector[JsValue] = jsArray.elements
      val transaction: Transaction = Transaction(elements.head.convertTo[String])
      val asm = ScriptParser.fromHex(elements.apply(1).convertTo[String])
      val script: ScriptPubKey = ScriptPubKey(asm)
      val inputIndex: UInt32 = UInt32(elements(2).convertTo[Int])
      val hashTypeNum: Int32 = Int32(elements(3).convertTo[Int])
      val hashType: HashType = HashType(hashTypeNum)
      val regularSigHash = DoubleSha256Digest(elements(4).convertTo[String])
      val noForkKidSigHash = DoubleSha256Digest(elements(5).convertTo[String])
      val replayProtectedSigHash = DoubleSha256Digest(elements(6).convertTo[String])

      SignatureHashTestCaseImpl(
        transaction,
        script,
        inputIndex,
        hashTypeNum,
        hashType,
        regularSigHash,
        noForkKidSigHash,
        replayProtectedSigHash)
    }

    override def write(testCase: SignatureHashTestCase): JsValue = ???
  }
}
