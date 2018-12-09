package org.scash.core.script.arithmetic
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018-2019 The SCash developers (MIT License)
 */
import org.scash.core.script.result._
import org.scash.core.script.flag.ScriptFlag
import org.scash.core.script.{ ExecutedScriptProgram, ExecutionInProgressScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.util.{ ScriptProgramTestUtil, TestUtil }
import org.scalatest.FlatSpec
import org.scash.core.TestHelpers
import org.scash.core.policy.Policy
import org.scash.core.script.ScriptProgram.Stack
import scodec.bits.ByteVector
import scodec.bits._

class ArithmeticInterpreterTest extends FlatSpec with TestHelpers {

  val AI = ArithmeticInterpreter

  "ArithmeticInterpreter" must "perform an OP_ADD correctly" in {
    val stack = List(ScriptNumber.one, ScriptNumber(2))
    val script = List(OP_ADD)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opAdd(program)
    newProgram.stack.head must be(ScriptNumber(3))
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_1ADD correctly" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_1ADD)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.op1Add(program)

    newProgram.stack.head must be(ScriptNumber.one)
    newProgram.script.isEmpty must be(true)
  }

  it must "mark the script as invalid if we have an OP_1ADD with nothing on the stack" in {

    val stack = List()
    val script = List(OP_1ADD)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(AI.op1Add(program))
    newProgram.error must be(Some(ScriptErrorInvalidStackOperation))

  }

  it must "perform an OP_1SUB corectly" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_1SUB)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.op1Sub(program)

    newProgram.stack.head must be(ScriptNumber(-1))
    newProgram.script.isEmpty must be(true)
  }

  it must "mark a script as invalid if we have an OP_1SUB with nothing on the stack" in {

    val stack = List()
    val script = List(OP_1SUB)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(AI.op1Sub(program))
    newProgram.error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "perform an OP_SUB corectly" in {
    val stack = List(ScriptNumber.one, ScriptNumber.zero)
    val script = List(OP_SUB)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opSub(program)

    newProgram.stack.head must be(ScriptNumber(-1))
    newProgram.script.isEmpty must be(true)
  }

  it must "mark a script as invalid if we have an OP_SUB with nothing on the stack" in {
    val stack = List()
    val script = List(OP_SUB)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(AI.opSub(program))
    newProgram.error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "perform an OP_ABS on a negative number corectly" in {
    val stack = List(ScriptNumber(-1))
    val script = List(OP_ABS)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opAbs(program)

    newProgram.stack.head must be(ScriptNumber.one)
    newProgram.script.isEmpty must be(true)
  }

  it must "perform OP_ABS on zero correctly" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_ABS)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opAbs(program)

    newProgram.stack.head must be(ScriptNumber.zero)
    newProgram.script.isEmpty must be(true)
  }
  it must "mark a script as invalid if we have an OP_ABS with nothing on the stack" in {
    val stack = List()
    val script = List(OP_ABS)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(AI.opAbs(program))
    newProgram.error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "perform an OP_NEGATE on a zero correctly" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_NEGATE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNegate(program)

    newProgram.stack.head must be(ScriptNumber.zero)
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_NEGATE on a positive number correctly" in {
    val stack = List(ScriptNumber.one)
    val script = List(OP_NEGATE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNegate(program)

    newProgram.stack.head must be(ScriptNumber(-1))
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_NEGATE on a negative number correctly" in {
    val stack = List(ScriptNumber(-1))
    val script = List(OP_NEGATE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNegate(program)

    newProgram.stack.head must be(ScriptNumber.one)
    newProgram.script.isEmpty must be(true)
  }
  it must "mark a script as invalid if we have an OP_NEGATE with nothing on the stack" in {

    val stack = List()
    val script = List(OP_NEGATE)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(AI.opNegate(program))
    newProgram.error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "perform an OP_NOT correctly where 0 is the stack top" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_NOT)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNot(program)

    newProgram.stackTopIsTrue must be(true)
    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_NOT correctly where 1 is the stack top" in {
    val stack = List(ScriptNumber.one)
    val script = List(OP_NOT)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNot(program)

    newProgram.stackTopIsFalse must be(true)
    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_0NOTEQUAL correctly where 0 is the stack top" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_0NOTEQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.op0NotEqual(program)

    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)
  }

  it must "perform an OP_0NOTEQUAL correctly where 1 is the stack top" in {
    val stack = List(ScriptNumber.one)
    val script = List(OP_0NOTEQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.op0NotEqual(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "have an OP_BOOLAND correctly for two 0s" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.zero)
    val script = List(OP_BOOLAND)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opBoolAnd(program)

    newProgram.stackTopIsFalse must be(true)
    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)

    val stack1 = List(OP_0, OP_0)
    val script1 = List(OP_BOOLAND)
    val program1 = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram1 = AI.opBoolAnd(program)

    newProgram.stackTopIsFalse must be(true)
    newProgram1.stack.head must be(OP_FALSE)
    newProgram1.script.isEmpty must be(true)
  }

  it must "have an OP_BOOLAND correctly for one 0" in {
    val stack = List(ScriptNumber.zero, OP_1)
    val script = List(OP_BOOLAND)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opBoolAnd(program)

    newProgram.stackTopIsTrue must be(false)
    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)
  }

  it must "have an OP_BOOLOR correctly for two 1s" in {
    val stack = List(ScriptNumber.one, ScriptNumber.one)
    val script = List(OP_BOOLOR)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opBoolOr(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "have an OP_BOOLOR correctly for two 0s" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.zero)
    val script = List(OP_BOOLOR)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opBoolOr(program)

    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)
  }

  it must "have an OP_BOOLOR correctly for one OP_0" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_BOOLOR)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opBoolOr(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "evaulate an OP_NUMEQUAL for two zeros" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.zero)
    val script = List(OP_NUMEQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNumEqual(program)

    newProgram.stackTopIsTrue must be(true)
    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_NUMEQUALVERIFY for two zeros" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.zero)
    val script = List(OP_NUMEQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opNumEqualVerify(program)
    newProgram.isInstanceOf[ExecutionInProgressScriptProgram] must be(true)
    newProgram.stack.isEmpty must be(true)
  }

  it must "evaluate an OP_NUMEQUALVERIFY for two different numbers" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_NUMEQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opNumEqualVerify(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorVerify))
  }

  it must "mark the script as invalid for OP_NUMEQAULVERIFY without two stack elements" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_NUMEQUALVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opNumEqualVerify(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "evaluate an OP_NUMNOTEQUAL for two numbers that are the same" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.zero)
    val script = List(OP_NUMNOTEQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNumNotEqual(program)

    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_NUMNOTEQUAL for two numbers that are not the same" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_NUMNOTEQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opNumNotEqual(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_LESSTHAN correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_LESSTHAN)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opLessThan(program)

    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)

    val stack1 = List(ScriptNumber.zero, ScriptNumber.zero)
    val script1 = List(OP_LESSTHAN)
    ScriptProgram(TestUtil.testProgram, stack, script)
    val program1 = ScriptProgram(TestUtil.testProgram, stack1, script1)
    val newProgram1 = AI.opLessThan(program1)

    newProgram1.stack.head must be(OP_FALSE)
    newProgram1.script.isEmpty must be(true)

    val stack2 = List(ScriptNumber.one, ScriptNumber.zero)
    val script2 = List(OP_LESSTHAN)
    val program2 = ScriptProgram(TestUtil.testProgram, stack2, script2)
    val newProgram2 = AI.opLessThan(program2)

    newProgram2.stack.head must be(OP_TRUE)
    newProgram2.script.isEmpty must be(true)
  }

  it must "evaluate an OP_LESSTHANOREQUAL correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_LESSTHANOREQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opLessThanOrEqual(program)

    newProgram.stack.head must be(OP_FALSE)
    newProgram.script.isEmpty must be(true)

    val stack1 = List(ScriptNumber.zero, ScriptNumber.zero)
    val script1 = List(OP_LESSTHANOREQUAL)
    ScriptProgram(TestUtil.testProgram, stack, script)
    val program1 = ScriptProgram(TestUtil.testProgram, stack1, script1)
    val newProgram1 = AI.opLessThanOrEqual(program1)

    newProgram1.stack.head must be(OP_TRUE)
    newProgram1.script.isEmpty must be(true)

    val stack2 = List(ScriptNumber.one, ScriptNumber.zero)
    val script2 = List(OP_LESSTHANOREQUAL)
    val program2 = ScriptProgram(TestUtil.testProgram, stack2, script2)
    val newProgram2 = AI.opLessThanOrEqual(program2)

    newProgram2.stack.head must be(OP_TRUE)
    newProgram2.script.isEmpty must be(true)
  }

  it must "evaluate an OP_GREATERTHAN correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_GREATERTHAN)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opGreaterThan(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)

    val stack1 = List(ScriptNumber.zero, ScriptNumber.zero)
    val script1 = List(OP_GREATERTHAN)
    val program1 = ScriptProgram(TestUtil.testProgram, stack1, script1)
    val newProgram1 = AI.opGreaterThan(program1)

    newProgram1.stack.head must be(OP_FALSE)
    newProgram1.script.isEmpty must be(true)

    val stack2 = List(ScriptNumber.one, ScriptNumber.zero)
    val script2 = List(OP_GREATERTHAN)
    val program2 = ScriptProgram(TestUtil.testProgram, stack2, script2)
    val newProgram2 = AI.opGreaterThan(program2)

    newProgram2.stack.head must be(OP_FALSE)
    newProgram2.script.isEmpty must be(true)
  }

  it must "evaluate an OP_GREATERTHANOREQUAL correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_GREATERTHANOREQUAL)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opGreaterThanOrEqual(program)

    newProgram.stack.head must be(OP_TRUE)
    newProgram.script.isEmpty must be(true)

    val stack1 = List(ScriptNumber.zero, ScriptNumber.zero)
    val script1 = List(OP_GREATERTHANOREQUAL)
    val program1 = ScriptProgram(TestUtil.testProgram, stack1, script1)
    val newProgram1 = AI.opGreaterThanOrEqual(program1)

    newProgram1.stack.head must be(OP_TRUE)
    newProgram1.script.isEmpty must be(true)

    val stack2 = List(ScriptNumber.one, ScriptNumber.zero)
    val script2 = List(OP_GREATERTHANOREQUAL)
    val program2 = ScriptProgram(TestUtil.testProgram, stack2, script2)
    val newProgram2 = AI.opGreaterThanOrEqual(program2)

    newProgram2.stack.head must be(OP_FALSE)
    newProgram2.script.isEmpty must be(true)
  }

  it must "evaluate an OP_MIN correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_MIN)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opMin(program)

    newProgram.stack must be(List(ScriptNumber.zero))
  }

  it must "mark a script invalid for OP_MIN if there isn't two elements on the stack" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_MIN)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opMin(program)

    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "evaluate an OP_MAX correctly" in {
    val stack = List(ScriptNumber.zero, ScriptNumber.one)
    val script = List(OP_MAX)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opMax(program)

    newProgram.stack must be(List(ScriptNumber.one))
  }

  it must "mark a script invalid for OP_MAX if there isn't two elements on the stack" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_MAX)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opMax(program)

    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "evaluate an OP_WITHIN correctly" in {
    val stack = List(ScriptNumber(2), ScriptNumber.one, ScriptNumber.zero)
    val script = List(OP_WITHIN)
    val program = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script), Seq[ScriptFlag]())
    val newProgram = AI.opWithin(program)
    newProgram.stack must be(List(OP_FALSE))
    newProgram.script.isEmpty must be(true)

    val stack1 = List(ScriptNumber.one, OP_0, ScriptNumber.zero)
    val script1 = List(OP_WITHIN)
    val program1 = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack1, script1), Seq[ScriptFlag]())
    val newProgram1 = AI.opWithin(program1)
    newProgram1.stack must be(List(OP_TRUE))
    newProgram1.script.isEmpty must be(true)
  }

  it must "mark the script as invalid if one of the numbers within OP_WITHIN is not encoded the smallest way possible" in {
    val stack = List(ScriptNumber("00"), ScriptNumber.one, ScriptNumber.one)
    val script = List(OP_WITHIN)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = AI.opWithin(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorUnknownError))
  }

  it must "mark the script as invalid for OP_WITHIN if one of the numbers is larger than 4 bytes" in {
    val stack = List(ScriptNumber("0000000000000000"), ScriptNumber.one, ScriptNumber.one)
    val script = List(OP_WITHIN)
    val program = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script), Seq[ScriptFlag]())
    val newProgram = AI.opWithin(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorUnknownError))
  }

  it must "mark the script as invalid for OP_WITHIN if we do not have 3 stack elements" in {
    val stack = List(ScriptNumber("0000000000000000"), ScriptNumber.one)
    val script = List(OP_WITHIN)
    val program = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script), Seq[ScriptFlag]())
    val newProgram = AI.opWithin(program)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be(true)
    newProgram.asInstanceOf[ExecutedScriptProgram].error must be(Some(ScriptErrorInvalidStackOperation))
  }

  it must "interpret two script constants as numbers and then add them" in {
    val scriptConstant1 = ScriptConstant("ffffffff")
    val scriptConstant2 = ScriptConstant("ffffff7f")
    val stack = List(scriptConstant1, scriptConstant2)
    val script = List(OP_ADD)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = AI.opAdd(program)
    newProgram.stack must be(List(ScriptNumber.zero))
    newProgram.script.isEmpty must be(true)
  }

  //a, b, div expected, mod expected
  val inputDivMod = List(
    (hex"0xaf775318", hex"0x011bf485", hex"0x84", hex"0xab0b8300"),
    (hex"0xaf775318", hex"0x011b", hex"0x9de600", hex"0x1202"),
    (hex"0x0f", hex"0x04", hex"0x03", hex"0x03"),
    (hex"0x983a", hex"0x04", hex"0xa60e", hex""),
    (hex"0x983a", hex"0xa00f", hex"0x03", hex"0xb80b"),
    (hex"0xc0e1e400", hex"0xa00f", hex"0xa60e", hex""),
    (hex"0xc0e1e400", hex"0x04", hex"0x703839", hex""),
    (hex"0xbbf05d03", hex"0x4101", hex"0x67af02", hex"0x9400"),
    (hex"0xbbf05d03", hex"0x03", hex"0x3e501f01", hex"0x01"),
    (hex"0xbbf05d03", hex"0x4e67ab21", hex"", hex"0xbbf05d03")).map(n => (ScriptNumber(n._1), ScriptNumber(n._2), ScriptNumber(n._3), ScriptNumber(n._4)))

  def negNum(n: ScriptNumber) =
    n.bytes.lastOption
      .map(l => ScriptNumber((ByteVector(l ^ 0x80) ++ n.bytes.reverse.drop(1)).reverse))
      .getOrElse(n)

  it must "evaluate OP_DIV successfully " in inputDivMod.map {
    case (n1, n2, ex, _) =>
      val f = checkBinaryOp(OP_DIV, AI.opDiv) _

      //Negative values
      f(n1, n2, ex)
      f(n1, negNum(n2), negNum(ex))
      f(negNum(n1), n2, negNum(ex))
      f(negNum(n1), negNum(n2), ex)

      //Division identities
      f(n1, ScriptNumber(hex"0x01"), n1)
      f(n1, ScriptNumber(hex"0x81"), negNum(n1))
      f(n1, n1, ScriptNumber(hex"0x01"))
      f(n1, negNum(n1), ScriptNumber(hex"0x81"))
      f(negNum(n1), n1, ScriptNumber(hex"0x81"))
      f(n2, ScriptNumber(hex"0x01"), n2)
      f(n2, ScriptNumber(hex"0x81"), negNum(n2))
      f(n2, n2, ScriptNumber(hex"0x01"))
      f(n2, negNum(n2), ScriptNumber(hex"0x81"))
      f(negNum(n2), n2, ScriptNumber(hex"0x81"))
  }

  val flagSet = Policy.standardScriptVerifyFlags

  it must "throw errors for OP_DIV" in inputDivMod.map {
    case (n1, n2, _, _) =>
      val f = checkOpError(OP_DIV, AI.opDiv) _
      f(List(n1, ScriptNumber.zero), ScriptErrorDivByZero)
      f(List(n2, ScriptNumber.zero), ScriptErrorDivByZero)
  }

  it must "evaluate OP_MOD successfully " in inputDivMod.map {
    case (n1, n2, _, ex) =>
      val f = checkBinaryOp(OP_MOD, AI.opMod) _

      //Negative values
      f(n1, n2, ex)
      f(n1, negNum(n2), ex)
      f(negNum(n1), n2, negNum(ex))
      f(negNum(n1), negNum(n2), negNum(ex))

      // Modulo identities
      // n2 % n1 % n1 = n2 % n1
      val p = ScriptProgram(
        TestUtil.testProgramExecutionInProgress,
        List(n1, n2).reverse,
        List(OP_MOD, OP_MOD))

      val p1 = AI.opMod(p)
      val r = AI.opMod(ScriptProgram(p1, n2 +: p1.stack, p1.script))
      r.stack.head must be(ex)
      r.script.isEmpty must be(true)
  }
}
