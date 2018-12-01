package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptErrorInvalidStackOperation, ScriptErrorPushSize }
import org.scash.core.util.{ BitcoinSUtil, TestUtil }
import org.scalatest.FlatSpec
import org.scash.core.TestHelpers
import org.scash.core.consensus.Consensus

import scodec.bits.ByteVector

class SpliceInterpreterTest extends FlatSpec with TestHelpers {
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

  it must "evaluate an OP_CAT that is bigger than `maxScriptElementSize` and fail with ScriptErrorPushSize" in {
    val stack = List(
      ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(1)),
      ScriptConstant("0xaf"))

    checkOpError(stack, OP_CAT, ScriptErrorPushSize)(SI.opCat)
    checkOpError(stack.reverse, OP_CAT, ScriptErrorPushSize)(SI.opCat)
  }

  val inputs = List(
    (ScriptConstant.empty, ScriptConstant.empty),
    (ScriptConstant.zero, ScriptConstant.zero),
    (ScriptConstant("0xab"), ScriptConstant("0xcd")),
    (ScriptConstant("0xabcdef"), ScriptConstant("0x12345678")))

  it must "evaluate all OP_CAT successfully" in {
    inputs.map {
      case (a, b) =>
        checkBinaryOp(a, b, OP_CAT, List(ScriptConstant(a.bytes ++ b.bytes)))(SI.opCat)

        //Check empty concats
        checkBinaryOp(a, ScriptConstant.empty, OP_CAT, List(a))(SI.opCat)
        checkBinaryOp(b, ScriptConstant.empty, OP_CAT, List(b))(SI.opCat)
        checkBinaryOp(ScriptConstant.empty, a, OP_CAT, List(a))(SI.opCat)
        checkBinaryOp(ScriptConstant.empty, b, OP_CAT, List(b))(SI.opCat)
    }
  }

  it must "evaluate all OP_SPLIT successfully" in {
    inputs.map {
      case (a, b) =>
        SI.opSplit(
          ScriptProgram(
            TestUtil.testProgramExecutionInProgress,
            List(ScriptNumber(a.size), ScriptConstant(a.bytes ++ b.bytes)),
            List(OP_SPLIT)))
          .stack must be(List(a, b).reverse)
    }
  }

  it must "split and cat successfully" in {
    inputs.map {
      case (a, b) =>
        val p = ScriptProgram(
          TestUtil.testProgramExecutionInProgress,
          List(ScriptNumber(a.size), ScriptConstant(a.bytes ++ b.bytes)),
          List(OP_SPLIT, OP_CAT))
        (SI.opSplit _ andThen SI.opCat)(p).stack must be(List(ScriptConstant(a.bytes ++ b.bytes)))
    }
  }

  it must "cat and split successfully" in {
    inputs.map {
      case (a, b) =>
        val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, List(b, a, ScriptNumber(a.size)), List(OP_CAT, OP_SPLIT))
        val ss = SI.opCat(p)
        val pn = ScriptProgram(TestUtil.testProgramExecutionInProgress, ss.stack.reverse, ss.script)
        val sq = SI.opSplit(pn)
        sq.stack must be(List(a, b).reverse)
    }
  }
}
