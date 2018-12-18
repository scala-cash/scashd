package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.consensus.Consensus
import org.scash.core.script
import org.scash.core.script.constant.{ ScriptNumber, _ }
import org.scash.core.script.result._
import org.scash.core.script.ScriptProgram
import org.scash.core.util.{ BitcoinSLogger, BitcoinScriptUtil }
import scalaz.{ -\/, \/- }
import scodec.bits.ByteVector

sealed abstract class SpliceInterpreter {

  private def logger = BitcoinSLogger.logger

  /**
   * Concatenates two strings
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_cat]]
   */
  def opCat(program: ScriptProgram): ScriptProgram = (for {
    p <- script.checkBinary(program)
    v1 = p.stack(1)
    v2 = p.stack(0)
    np <- scriptPushSize(p)(v1.size + v2.size)
    n <- (v1, v2) match {
      case (s1: ScriptConstant, s2: ScriptConstant) => \/-(s1 ++ s2)
      case _ => -\/(ScriptProgram(p, ScriptErrorUnknownError))
    }
  } yield ScriptProgram(np, n :: p.stack.tail.tail, p.script.tail)).merge

  /**
   * Split the operand at the given position. This operation is the exact inverse of OP_CAT
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_split]]
   */
  def opSplit(program: ScriptProgram): ScriptProgram = (for {
    p <- script.checkBinary(program)
    n <- ScriptNumber(p, p.stack.head.bytes)
    pos = n.toLong
    data = p.stack(1).bytes
    s <- if (pos >= 0 && pos.toLong <= data.size) {
      \/-(data.splitAt(pos))
    } else {
      -\/(ScriptProgram(p, ScriptErrorInvalidSplitRange))
    }
  } yield ScriptProgram(p, List(ScriptConstant(s._2), ScriptConstant(s._1)) ::: p.stack.tail.tail, p.script.tail)).merge

  /**
   * Convert the numeric value into a byte sequence of a certain size, taking account of the sign bit.
   * The byte sequence produced uses the little-endian encoding.
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_num2bin]]
   * (in size --> out)
   */
  def opNum2Bin(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NUM2BIN), "Script top must be OP_NUM2BIN")
    (for {
      p <- script.checkBinary(program)
      size <- ScriptNumber(p, p.stack.head.bytes)
      np <- scriptPushSize(p)(size.toLong)
    } yield {

      val bin = BitcoinScriptUtil.toMinimalEncoding(np.stack(1).bytes)

      if (bin.size > size.toLong) {
        ScriptProgram(p, ScriptErrorImpossibleEncoding)
      } else if (bin.size == size.toLong) {
        ScriptProgram(p, ScriptConstant(bin.bytes) +: p.stack.tail.tail, p.script.tail)
      } else {
        val r = if (bin.size == 0) {
          ScriptConstant(ByteVector.fill(size.toLong)(0x00))
        } else {
          val signBit = (bin.bytes.last & 0x80).toByte
          val bit = (bin.bytes.last & 0x7f).toByte
          val padding = ByteVector.fill((size.toLong - 1) - bin.size)(0x00)
          val nNum = bin.bytes.update(bin.size - 1, bit) ++ padding :+ signBit
          ScriptConstant(nNum)
        }
        ScriptProgram(np, r +: np.stack.tail.tail, np.script.tail)
      }
    })
      .merge
  }

  /**
   * Convert the byte sequence into a numeric value, including minimal encoding.
   * The byte sequence must encode the value in little-endian encoding.
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_bin2num]]
   */
  def opBin2Num(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_BIN2NUM), "Script top must be OP_BIN2NUM")
    if (p.stack.isEmpty) {
      ScriptProgram(p, ScriptErrorInvalidStackOperation)
    } else {
      val num = BitcoinScriptUtil.toMinimalEncoding(p.stack.head.bytes)
      if (!BitcoinScriptUtil.isMinimalEncoding(num) || (num.size > 4)) {
        ScriptProgram(p, ScriptErrorInvalidNumberRange)
      } else {
        ScriptProgram(p, ScriptNumber(num.bytes) +: p.stack.tail, p.script.tail)
      }
    }
  }

  /** Pushes the string length of the top element of the stack (without popping it). */
  def opSize(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_SIZE), "Script top must be OP_SIZE")
    if (program.stack.nonEmpty) {
      if (program.stack.head == OP_0) {
        ScriptProgram(program, OP_0 :: program.stack, program.script.tail)
      } else {
        val scriptNumber = program.stack.head match {
          case ScriptNumber.zero => ScriptNumber.zero
          case x: ScriptToken => ScriptNumber(x.bytes.size)
        }
        ScriptProgram(program, scriptNumber :: program.stack, program.script.tail)
      }
    } else {
      logger.error("Must have at least 1 element on the stack for OP_SIZE")
      ScriptProgram(program, ScriptErrorInvalidStackOperation)
    }
  }

  def scriptPushSize(p: => ScriptProgram)(b: Long) =
    if (b < 0 || b > Consensus.maxScriptElementSize)
      -\/(ScriptProgram(p, ScriptErrorPushSize))
    else
      \/-(p)
}

object SpliceInterpreter extends SpliceInterpreter