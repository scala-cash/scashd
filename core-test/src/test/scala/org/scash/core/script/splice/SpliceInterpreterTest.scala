package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation, ScriptErrorPushSize }
import org.scash.core.util.{ BitcoinSUtil, TestUtil }
import org.scalatest.{ FlatSpec, MustMatchers }
import org.scash.core.consensus.Consensus
import scodec.bits.ByteVector

class SpliceInterpreterTest extends FlatSpec with MustMatchers {
  val SI = SpliceInterpreter

  "SpliceInterpreter" must "evaluate an OP_SIZE on OP_0 correctly" in {
    val stack = List(OP_0)
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = SI.opSize(program)
    newProgram.stack must be(List(OP_0, OP_0))
    newProgram.script.isEmpty must be(true)

  }

  it must "determine the size of script number 0 correctly" in {
    val stack = List(ScriptNumber.zero)
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = SI.opSize(program)
    newProgram.stack must be(List(ScriptNumber.zero, ScriptNumber.zero))
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_SIZE correctly with 0x7f" in {
    val stack = List(ScriptConstant("7f"))
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = SI.opSize(program)
    newProgram.stack must be(List(ScriptNumber(1), ScriptConstant("7f")))
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_SIZE correctly with 0x8000" in {
    //0x8000 == 128 in bitcoin
    val stack = List(ScriptNumber(128))
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = SI.opSize(program)
    newProgram.stack must be(List(ScriptNumber(2), ScriptNumber(128)))
    newProgram.script.isEmpty must be(true)
  }

  it must "evaluate an OP_SIZE correctly with a negative number" in {
    val stack = List(ScriptNumber(-1))
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgram, stack, script)
    val newProgram = SI.opSize(program)
    newProgram.stack must be(List(ScriptNumber.one, ScriptNumber(-1)))
    newProgram.script.isEmpty must be(true)
  }

  it must "mark the script as invalid if OP_SIZE has nothing on the stack" in {
    val stack = List()
    val script = List(OP_SIZE)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
    val newProgram = SI.opSize(program)
    (newProgram match {
      case e: ExecutedScriptProgram => {
        e.error must be(Some(ScriptErrorInvalidStackOperation))
        true
      }
      case _ => false
    }) must be(true)
  }

  def str2ByteVector(str: String) =
    BitcoinSUtil.decodeHex(BitcoinSUtil.flipEndianness(ByteVector(str.getBytes)))

  it must "evaluate an OP_CAT with empty elements correctly" in {
    val r = str2ByteVector("myString")

    val stack = List(ScriptConstant(r), ScriptConstant.empty)
    val stack2 = List(ScriptConstant.empty, ScriptConstant(r))
    val script = List(OP_CAT)

    List(stack, stack2)
      .map(ScriptProgram(TestUtil.testProgramExecutionInProgress, _, script))
      .map(SI.opCat).map(_.stack.head.bytes must be(r))
  }

  def checkOpError(
    stack: List[ScriptToken],
    op: ScriptOperation,
    ex: ScriptError)(
    interpreter: ScriptProgram => ScriptProgram) = {
    val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, List(op))
    interpreter(p) match {
      case e: ExecutedScriptProgram => e.error must be(Some(ex))
      case _ => assert(false)
    }
  }

  it must "evaluate an OP_CAT that is bigger than `maxScriptElementSize` and fail with ScriptErrorPushSize" in {
    val stack = List(
      ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(1)),
      ScriptConstant("0xaf"))

    checkOpError(stack, OP_CAT, ScriptErrorPushSize)(SI.opCat)
    checkOpError(stack.reverse, OP_CAT, ScriptErrorPushSize)(SI.opCat)
  }
}
