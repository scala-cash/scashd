package org.scash.core.script.interpreter

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.crypto.TxSigComponent
import org.scash.core.currency.CurrencyUnits
import org.scash.core.protocol.script._
import org.scash.core.protocol.transaction.{ Transaction, TransactionOutput }
import org.scash.core.script.{ PreExecutionScriptProgram, ScriptProgram }
import org.scash.core.script.flag.ScriptFlagFactory
import org.scash.core.script.interpreter.testprotocol.ScripTestCase
import org.scash.core.script.interpreter.testprotocol.CoreTestCaseProtocol._
import org.scash.core.util._
import org.scalatest.{ FlatSpec, MustMatchers }
import spray.json._

import scala.io.Source

class ScriptInterpreterTest extends FlatSpec with MustMatchers {
  private def logger = BitcoinSLogger.logger

  "ScriptInterpreter" must "evaluate all the scripts from the bitcoin core script_tests.json" in {

    val source = Source.fromURL(getClass.getResource("/script_tests.json"))

    //use this to represent a single test case from script_valid.json
    /*    val lines =
      """
          | [["", "DEPTH 0 EQUAL", "P2SH,STRICTENC", "OK", "Test the test: we should have an empty stack after scriptSig evaluation"]]
   """.stripMargin*/
    val lines = try source.getLines.filterNot(_.isEmpty).map(_.trim) mkString "\n" finally source.close()
    val json = lines.parseJson
    val testCasesOpt: Seq[Option[ScripTestCase]] = json.convertTo[Seq[Option[ScripTestCase]]]
    val testCases: Seq[ScripTestCase] = testCasesOpt.flatten
    for {
      testCase <- testCases
      (creditingTx, outputIndex) = TransactionTestUtil.buildCreditingTransaction(testCase.scriptPubKey)
      (tx, inputIndex) = TransactionTestUtil.buildSpendingTransaction(creditingTx, testCase.scriptSig, outputIndex)
    } yield {
      val scriptPubKey = ScriptPubKey.fromAsm(testCase.scriptPubKey.asm)
      val flags = ScriptFlagFactory.fromList(testCase.flags)
      val output = TransactionOutput(CurrencyUnits.zero, scriptPubKey)
      val txSigComponent = TxSigComponent(
        transaction = tx,
        inputIndex = inputIndex,
        output = output,
        flags = flags)
      val program = PreExecutionScriptProgram(txSigComponent)
      withClue(testCase.raw) {
        ScriptInterpreter.run(program) must equal(testCase.expectedResult)
      }
    }
  }

}
