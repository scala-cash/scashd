package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptErrorInvalidSplitRange, ScriptErrorInvalidStackOperation, ScriptErrorPushSize }
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

    val f = checkOpError(OP_CAT, SI.opCat) _
    f(stack, ScriptErrorPushSize)
    f(stack.reverse, ScriptErrorPushSize)
  }

  val spliceInputs = List(
    (ScriptConstant.empty, ScriptConstant.empty),
    (ScriptConstant.zero, ScriptConstant.zero),
    (ScriptConstant("0xab"), ScriptConstant("0xcd")),
    (ScriptConstant("0xabcdef"), ScriptConstant("0x12345678")))

  it must "evaluate all OP_CAT successfully" in {
    spliceInputs.map {
      case (a, b) =>
        val f = checkBinaryOp(OP_CAT, SI.opCat) _
        f(a, b, ScriptConstant(a.bytes ++ b.bytes))

        //Check empty concats
        f(a, ScriptConstant.empty, a)
        f(b, ScriptConstant.empty, b)
        f(ScriptConstant.empty, a, a)
        f(ScriptConstant.empty, b, b)
    }
  }

  it must "evaluate all OP_SPLIT successfully" in {
    spliceInputs.map {
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
    spliceInputs.map {
      case (a, b) =>
        val p = ScriptProgram(
          TestUtil.testProgramExecutionInProgress,
          List(ScriptNumber(a.size), ScriptConstant(a.bytes ++ b.bytes)),
          List(OP_SPLIT, OP_CAT))
        (SI.opSplit _ andThen SI.opCat)(p).stack must be(List(ScriptConstant(a.bytes ++ b.bytes)))
    }
  }

  it must "split and fail due to invalid range" in {
    spliceInputs.map {
      case (a, b) =>
        val f = checkOpError(OP_SPLIT, SI.opSplit) _

        f(List(a, ScriptNumber(a.size + 1)), ScriptErrorInvalidSplitRange)
        f(List(b, ScriptNumber(b.size + 1)), ScriptErrorInvalidSplitRange)
        f(List(ScriptConstant(a.bytes ++ b.bytes), ScriptNumber(ScriptConstant(a.bytes ++ b.bytes).size + 1)), ScriptErrorInvalidSplitRange)
        f(List(a, ScriptNumber(-1)), ScriptErrorInvalidSplitRange)

    }
  }

  it must "call OP_NUM2BIN correctly" in {
    val p = ScriptProgram(
      TestUtil.testProgramExecutionInProgress,
      List(ScriptNumber.zero, ScriptConstant.empty).reverse,
      List(OP_NUM2BIN))
    println(p.stack)
    val p1 = SI.opNum2Bin(p)
    println(p1.stack)
    p1.stack.head must be(ScriptNumber.zero)

    10.to(Consensus.maxScriptElementSize).map { s =>
      val paddedZeroes = ByteVector.fill(s)(0x00)
      val p = ScriptProgram(
        TestUtil.testProgramExecutionInProgress,
        List(ScriptNumber(paddedZeroes.size), ScriptConstant.empty).reverse,
        List(OP_NUM2BIN))
      println(p.stack)
      val p1 = SI.opNum2Bin(p)
      println(p1.stack)
      p1.stack.head must be(ScriptConstant.empty)
    }
  }
}
