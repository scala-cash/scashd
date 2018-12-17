package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant._
import org.scash.core.script.result._
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
    val f = compare(OP_NUM2BIN, SI.opNum2Bin) _
    val zero = ScriptNumber.zero
    val empty = ScriptConstant.empty

    // Merge leading byte when sign bit isn't used.
    val k = 0x7F.toByte
    val negK = 0xFF.toByte

    //empty ones
    f(List(zero, empty), empty)
    f(List(zero, empty), empty)

    0.to(Consensus.maxScriptElementSize - 1).map { s =>

      val paddedZeroes = ByteVector.fill(s)(0x00)
      val paddedNegZeroes = paddedZeroes :+ 0x80.toByte

      val paddedK = k +: ByteVector.fill(s)(0x00)
      val paddedNegK =
        if (s == 0)
          ByteVector(negK)
        else
          ByteVector(negK & k) ++ ByteVector.fill(s - 1)(0x80 & k) :+ 0x80.toByte

      f(List(ScriptNumber(paddedZeroes.size), empty), ScriptConstant(paddedZeroes))
      f(List(ScriptNumber(paddedNegZeroes.size), empty), ScriptConstant(paddedNegZeroes))
      f(List(ScriptNumber(paddedNegK.size), ScriptConstant(ByteVector(negK))), ScriptConstant(paddedNegK))
      f(List(ScriptNumber(paddedK.size), ScriptNumber(ByteVector(k))), ScriptConstant(paddedK))
    }

    val bin1 = ByteVector.fromValidHex("abcdef00")
    val bin2 = ScriptConstant(ByteVector.fromValidHex("abcd7f00"))

    // Some known values
    f(List(ScriptNumber(4), ScriptNumber(bin1)), ScriptConstant(bin1))
    f(List(ScriptNumber(4), ScriptNumber(ByteVector.fromValidHex("abcd7f"))), bin2)

    val bin3 = ScriptConstant(ByteVector.fromValidHex("0xabcdef4280"))
    val bin4 = ScriptConstant(ByteVector.fromValidHex("0xabcd7f4200"))

    //Reductions
    f(List(ScriptNumber(5), ScriptNumber(ByteVector.fromValidHex("0xabcdefc2"))), bin3)
    f(List(ScriptNumber(5), ScriptNumber(ByteVector.fromValidHex("0xabcd7f42"))), bin4)

    // NUM2BIN must not generate oversized push.
    f(List(ScriptNumber(Consensus.maxScriptElementSize), ScriptNumber(ByteVector.empty)), ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(0x00)))
  }

  it must "NUM2BIN errors" in {
    val f = checkOpError(OP_NUM2BIN, SI.opNum2Bin) _
    //Empty Stack error
    f(Nil, ScriptErrorInvalidStackOperation)

    //NUM2BIn require 2 elements on the stack
    f(List(ScriptNumber.zero), ScriptErrorInvalidStackOperation)

    f(List(ScriptNumber(ByteVector.empty), ScriptNumber(ByteVector.fromValidHex("0x0902"))), ScriptErrorPushSize)

    //Impossible encoding
    f(List(ScriptNumber(ByteVector.fromValidHex("0xabcdef80")), ScriptNumber(0x03)), ScriptErrorImpossibleEncoding)
  }

  it must "BIN2NUM errors" in {
    val f = checkOpError(OP_BIN2NUM, SI.opBin2Num) _
    //Empty Stack error
    f(Nil, ScriptErrorInvalidStackOperation)

    //Values that do not fit in 4 bytes are considered out of range for bin2num
    f(List(ScriptConstant(ByteVector.fromValidHex("0xabcdefc280"))), ScriptErrorInvalidNumberRange)
    f(List(ScriptConstant(ByteVector.fromValidHex("0x0000008080"))), ScriptErrorInvalidNumberRange)
  }
}

