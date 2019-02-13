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

        f(List(ScriptNumber(a.size + 1), a), ScriptErrorInvalidSplitRange)
        f(List(ScriptNumber(b.size + 1), b), ScriptErrorInvalidSplitRange)
        f(List(ScriptNumber(ScriptConstant(a.bytes ++ b.bytes).size + 1), ScriptConstant(a.bytes ++ b.bytes)), ScriptErrorInvalidSplitRange)
        f(List(ScriptNumber(-1), a), ScriptErrorInvalidSplitRange)

    }
  }

  // Merge leading byte when sign bit isn't used.
  val k = 0x7F.toByte
  val negK = 0xFF.toByte
  val zero = ScriptNumber.zero

  val inputsConversion = List(
    (ByteVector.empty, ByteVector.empty),
    (ByteVector.fromValidHex("abcdef00"), ByteVector.fromValidHex("abcdef00")),
    (ByteVector.fromValidHex("abcd7f00"), ByteVector.fromValidHex("abcd7f")),
    (ByteVector.fromValidHex("0xabcdef4280"), ByteVector.fromValidHex("0xabcdefc2")), //known values
    (ByteVector.fromValidHex("0xabcd7f4200"), ByteVector.fromValidHex("0xabcd7f42")) //Reductions
  )

  it must "call OP_NUM2BIN correctly" in {
    val f = compare(OP_NUM2BIN, SI.opNum2Bin) _

    val empty = ScriptConstant.empty

    //empty ones
    f(List(zero, empty), empty)

    // NUM2BIN must not generate oversized push.
    f(List(ScriptNumber(Consensus.maxScriptElementSize), ScriptNumber(ByteVector.empty)), ScriptConstant(ByteVector.fill(Consensus.maxScriptElementSize)(0x00)))

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

    inputsConversion.map {
      case (a, b) =>
        f(List(ScriptNumber(a.size), ScriptNumber(b)), ScriptConstant(a))
    }
  }

  it must "call OP_BIN2NUM correctly" in {
    val f = compare(OP_BIN2NUM, SI.opBin2Num) _
    val empty = ScriptConstant.empty
    //empty ones
    f(List(empty), zero)

    0.to(Consensus.maxScriptElementSize - 1).map { s =>
      val paddedZeroes = ByteVector.fill(s)(0x00)
      val paddedNegZeroes = paddedZeroes :+ 0x80.toByte

      val paddedK = k +: ByteVector.fill(s)(0x00)
      val paddedNegK =
        if (s == 0)
          ByteVector(negK)
        else
          ByteVector(negK & k) ++ ByteVector.fill(s - 1)(0x80 & k) :+ 0x80.toByte

      f(List(ScriptConstant(paddedZeroes)), zero)
      f(List(ScriptConstant(paddedNegZeroes)), zero)
      f(List(ScriptConstant(paddedNegK)), ScriptNumber(ByteVector(negK)))
      f(List(ScriptConstant(paddedK)), ScriptNumber(ByteVector(k)))

    }

    inputsConversion.map {
      case (a, b) =>
        f(List(ScriptConstant(a)), ScriptNumber(b))
    }
  }

  it must "demonstrate that BIN2NUM is indempotent" in {
    inputsConversion.map {
      case (a, b) =>
        val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, List(ScriptConstant(a)), List(OP_BIN2NUM, OP_BIN2NUM))
        val p1 = SI.opBin2Num(p)
        val p2 = SI.opBin2Num(p1)
        p2.stack.head must be(ScriptNumber(b))
    }
  }

  it must "do a round trip for BIN2NUM -> NUM2BIN" in {
    inputsConversion.map {
      case (a, b) =>
        val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, List(ScriptConstant(a)), List(OP_BIN2NUM, OP_NUM2BIN))
        val p1 = SI.opBin2Num(p)
        val p2 = ScriptProgram(TestUtil.testProgramExecutionInProgress, ScriptNumber(a.size) +: p1.stack, p1.script)
        val p3 = SI.opNum2Bin(p2)
        p1.stack.head must be(ScriptNumber(b)) //BIN2NUM
        p3.stack.head must be(ScriptConstant(a)) //Back to BIN
    }
  }

  it must "do a round trip for NUM2BIN -> BIN2NUM" in {
    inputsConversion.map {
      case (a, b) =>
        val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, List(ScriptNumber(a.size), ScriptNumber(b)), List(OP_NUM2BIN, OP_BIN2NUM))
        val p1 = SI.opNum2Bin(p)
        val p2 = SI.opBin2Num(p1)
        p1.stack.head must be(ScriptConstant(a)) //NUM2BIN
        p2.stack.head must be(ScriptNumber(b)) //BIN2NUM
    }
  }

  it must "NUM2BIN errors" in {
    val f = checkOpError(OP_NUM2BIN, SI.opNum2Bin) _
    //Empty Stack error
    f(Nil, ScriptErrorInvalidStackOperation)

    //NUM2BIn require 2 elements on the stack
    f(List(ScriptNumber.zero), ScriptErrorInvalidStackOperation)

    f(List(ScriptNumber(ByteVector.fromValidHex("0x0902")), ScriptNumber(ByteVector.empty)), ScriptErrorPushSize)

    //Impossible encoding
    f(List(ScriptNumber(0x03), ScriptNumber(ByteVector.fromValidHex("0xabcdef80"))), ScriptErrorImpossibleEncoding)
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

