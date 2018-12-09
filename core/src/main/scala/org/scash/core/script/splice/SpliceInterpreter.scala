package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.consensus.Consensus
import org.scash.core.script
import org.scash.core.script.constant.{ScriptNumber, _}
import org.scash.core.script.result.{ScriptErrorInvalidSplitRange, ScriptErrorInvalidStackOperation, ScriptErrorPushSize, ScriptErrorUnknownError}
import org.scash.core.script.ScriptProgram
import org.scash.core.script.flag.ScriptFlagUtil
import org.scash.core.util.BitcoinSLogger
import scalaz.{-\/, \/-}
import scodec.bits.ByteVector

import scala.util.{Failure, Success}

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
  } yield ScriptProgram(np, n :: p.stack.tail.tail, p.script.tail)
  ).merge

  /**
   * Split the operand at the given position. This operation is the exact inverse of OP_CAT
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_split]]
   */
  def opSplit(program: ScriptProgram): ScriptProgram = (for {
    p <- script.checkBinary(program)
    n <- ScriptNumber(p, ScriptFlagUtil.requireMinimalData(p.flags))
    pos = n.toLong
    data = p.stack(1).bytes
    s <-
      if (pos >= 0 && pos.toLong <= data.size) {
        \/-(data.splitAt(pos))
      } else {
        -\/(ScriptProgram(p, ScriptErrorInvalidSplitRange))
      }
  } yield ScriptProgram(p, List(ScriptConstant(s._2), ScriptConstant(s._1)) ::: p.stack.tail.tail, p.script.tail)
  ).merge


  /**
    * Convert the numeric value into a byte sequence of a certain size, taking account of the sign bit.
    * The byte sequence produced uses the little-endian encoding.
    * Spec info
    * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_num2bin]]
    */
  def opNum2Bin(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NUM2BIN), "Script top must be OP_NUM2BIN")
    for {
      p <- script.checkBinary(program)
      size <- ScriptNumber(p, ScriptFlagUtil.requireMinimalData(p.flags))
      np <- scriptPushSize(p)(size.toLong)
      num <- ScriptNumber.fromBytes(np.stack(1).bytes)
    } yield ()
  }

  /**
    * Convert the byte sequence into a numeric value, including minimal encoding.
    * The byte sequence must encode the value in little-endian encoding.
    * Spec info
    * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_bin2num]]
    */
  def opBin2Num(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NUM2BIN), "Script top must be OP_NUM2BIN")

    program
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
    if(b > Consensus.maxScriptElementSize)
      -\/(ScriptProgram(p, ScriptErrorPushSize))
    else
      \/-(p)
}

object SpliceInterpreter extends SpliceInterpreter