package org.scash.core.script.bitwise
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptErrorInvalidOperandSize, ScriptErrorInvalidStackOperation }
import org.scash.core.util.TestUtil
import org.scalatest.FlatSpec
import org.scash.core.TestHelpers
import org.scash.core.consensus.Consensus
import scodec.bits.ByteVector

import scala.io.Source
import BitWiseJsonProtocol._
import spray.json._

class BitwiseInterpreterTest extends FlatSpec with TestHelpers {
  val input = Source.fromURL(getClass.getResource("/bitwise.json"))
    .mkString
    .parseJson
    .convertTo[BitWiseCase]

  private val pubKeyHash = ScriptConstant("5238C71458E464D9FF90299ABCA4A1D7B9CB76AB".toLowerCase)
  val BI = BitwiseInterpreter
  "BitwiseInterpreter" must "evaluate OP_EQUAL" in {
    val stack = List(pubKeyHash, pubKeyHash)
    val script = List(OP_EQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = BI.opEqual(program)
    newProgram.stack.head must be(OP_TRUE)
  }

  it must "evaluate OP_1 and OP_TRUE to equal" in {
    val stack = List(OP_1, OP_TRUE)
    val script = List(OP_EQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = BI.opEqual(program)
    newProgram.stack.head must be(OP_TRUE)
  }

  it must "throw an exception for OP_EQUAL when we don't have enough items on the stack" in {
    intercept[IllegalArgumentException] {
      BI.opEqual(ScriptProgram(TestUtil.testProgram, List(), List()))
    }
  }

  it must "throw an exception for OP_EQUAL when we don't have enough items on the script stack" in {
    intercept[IllegalArgumentException] {
      BI.opEqual(ScriptProgram(TestUtil.testProgram, List(), List()))
    }
  }

  it must "evaulate OP_EQUALVERIFY must not evaluate a transaction to invalid with two of the same pubkeys" in {
    val stack = List(pubKeyHash, pubKeyHash)
    val script = List(OP_EQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val result = BI.opEqualVerify(program)
    //if verification fails it will transform the script to a ExecutedProgram with an error set
    result.isInstanceOf[ExecutedScriptProgram] must be(false)
  }

  it must "evaluate OP_EQUALVERIFY to false given two different pub keys" in {
    val uniquePubKey = ScriptConstant(pubKeyHash.hex + "00")
    val stack = List(pubKeyHash, uniquePubKey)
    val script = List(OP_EQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val result = BI.opEqualVerify(program)
    result.stackTopIsTrue must be(false)
  }

  it must "evaluate a ScriptNumber & ScriptConstant to true if they are the same" in {
    val stack = List(ScriptNumber(2), ScriptConstant("02"))
    val script = List(OP_EQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    BI.opEqual(program).stack.head must be(OP_TRUE)

    val stack1 = List(ScriptConstant("02"), ScriptNumber(2))
    val script1 = List(OP_EQUAL)
    val program1 = ScriptProgram(TestUtil.testProgram, stack1, script1)
    BI.opEqual(program1).stack.head must be(OP_TRUE)
  }

  it must "evaluate an OP_0 and ScriptNumberImpl(0) to equal" in {
    val stack = List(OP_0, ScriptNumber.zero)
    val script = List(OP_EQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    BI.opEqual(program).stack.head must be(OP_TRUE)
  }

  it must "mark the script as invalid of OP_EQUALVERIFY is run without two stack elements" in {
    val stack = List(OP_0)
    val script = List(OP_EQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = BI.opEqualVerify(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorInvalidStackOperation))
  }

  def bitwiseOperations(op: ScriptOperation, ex: ScriptToken)(interpreter: ScriptProgram => ScriptProgram) = {
    val empty = ScriptConstant.empty
    val zeroes = ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(0))
    val ones = ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(0xff))
    val a = input.a.foldLeft(ByteVector.empty)((r, s) => r ++ ByteVector.fromValidHex(s))
    val b = input.b.foldLeft(ByteVector.empty)((r, s) => r ++ ByteVector.fromValidHex(s))

    checkBinaryOp(empty, empty, op, List(empty))(interpreter)
    checkBinaryOp(zeroes, zeroes, op, List(zeroes))(interpreter)
    checkBinaryOp(ones, ones, op, List(ones))(interpreter)
    checkBinaryOp(ScriptConstant(a), ScriptConstant(b), op, List(ex))(interpreter)
  }

  it must "evaluate all OP_AND tests" in {
    bitwiseOperations(OP_AND, ScriptConstant(input.and.foldLeft(ByteVector.empty)((r, s) => r ++ ByteVector.fromValidHex(s))))(BI.opAnd)
  }
  it must "evaluate all OP_OR tests" in {
    bitwiseOperations(OP_OR, ScriptConstant(input.or.foldLeft(ByteVector.empty)((r, s) => r ++ ByteVector.fromValidHex(s))))(BI.opOr)
  }

  it must "check error conditions" in {
    List((OP_AND, BI.opAnd _), (OP_OR, BI.opOr _)).map {
      case (op, interpreter) =>
        checkOpError(List(ScriptConstant.empty), op, ScriptErrorInvalidStackOperation)(interpreter)
        checkOpError(List(ScriptNumber.zero), op, ScriptErrorInvalidStackOperation)(interpreter)
        checkOpError(List(ScriptNumber(0xabcdef)), op, ScriptErrorInvalidStackOperation)(interpreter)

        checkOpError(List(ScriptConstant.empty, ScriptNumber(0xcd)), op, ScriptErrorInvalidOperandSize)(interpreter)
        checkOpError(List(ScriptNumber(0xcd), ScriptConstant.empty), op, ScriptErrorInvalidOperandSize)(interpreter)
        checkOpError(List(ScriptNumber(0xabcdef), ScriptNumber(0xcd)), op, ScriptErrorInvalidOperandSize)(interpreter)
        checkOpError(List(ScriptNumber(0xcd), ScriptNumber(0xabcdef)), op, ScriptErrorInvalidOperandSize)(interpreter)
    }
  }
}
