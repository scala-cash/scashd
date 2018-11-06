package org.scash.core.script.interpreter.testprotocol

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.protocol.CompactSizeUInt
import org.scash.core.serializers.script.ScriptParser
import org.scash.core.protocol.script._
import org.scash.core.script.result.ScriptResult
import org.scash.core.util.{ BitcoinSLogger, BitcoinScriptUtil }

import scodec.bits.ByteVector
import spray.json._

object ABCTestCaseProtocol extends DefaultJsonProtocol {

  private def logger = BitcoinSLogger.logger

  implicit object ABCTestCaseFormatter extends RootJsonFormat[Option[ScripTestCase]] {

    override def read(value: JsValue): Option[ScripTestCase] = {
      logger.debug("Test case: " + value)
      val jsArray: JsArray = value match {
        case array: JsArray => array
        case _ => throw new RuntimeException("ABC test case must be in the format of js array")
      }
      val elements = jsArray.elements
      if (elements.size < 3) {
        //means that the line is probably a separator between different types of test cases i.e.
        //["Equivalency of different numeric encodings"]
        None
      } else if (elements.size <= 5) {
        val scriptSignature = ScriptSignature(parseScriptSignature(elements(0)))
        val scriptPubKey = ScriptPubKey(parseScriptPubKey(elements(1)))
        val flags = elements(2).convertTo[String]
        val expectedResult = ScriptResult(elements(3).convertTo[String])
        val comments = if (elements.size == 4) "" else elements(4).convertTo[String] //check for comments

        if (expectedResult.isEmpty)
          new Throwable(s"Script Result: $expectedResult is not known")
        else
          logger.info("Script Result: " + elements(3).convertTo[String])

        expectedResult.map(r => ScripTestCase(scriptSignature, scriptPubKey, flags, r, comments, elements.toString))

      } else None
    }

    /**
     * Parses the script signature asm, it can come in multiple formats
     * such as byte strings i.e. 0x02 0x01 0x00
     * and numbers   1  2
     * look at script_valid.json file for example formats
     *
     * @param element
     * @return
     */
    private def parseScriptSignature(element: JsValue): ByteVector = {
      val asm = ScriptParser.fromString(element.convertTo[String])
      val bytes = BitcoinScriptUtil.asmToBytes(asm)
      val compactSizeUInt = CompactSizeUInt.calculateCompactSizeUInt(bytes)
      compactSizeUInt.bytes ++ bytes
    }

    /**
     * Parses a script pubkey asm from the bitcoin ABC test cases,
     * example formats:
     * "2 EQUALVERIFY 1 EQUAL"
     * "'Az' EQUAL"
     * look at script_valid.json file for more example formats
     * @param element
     * @return
     */
    private def parseScriptPubKey(element: JsValue): ByteVector = {
      val asm = ScriptParser.fromString(element.convertTo[String])
      val bytes = BitcoinScriptUtil.asmToBytes(asm)
      val compactSizeUInt = CompactSizeUInt.calculateCompactSizeUInt(bytes)
      compactSizeUInt.bytes ++ bytes
    }

    override def write(testCase: Option[ScripTestCase]): JsValue = ???
  }

}
