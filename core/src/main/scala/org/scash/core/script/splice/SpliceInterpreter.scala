package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.consensus.Consensus
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptErrorInvalidSplitRange, ScriptErrorInvalidStackOperation, ScriptErrorPushSize, ScriptErrorUnknownError }
import org.scash.core.script.ScriptProgram
import org.scash.core.script.flag.ScriptFlagUtil
import org.scash.core.util.BitcoinSLogger

import scala.util.{ Failure, Success }

sealed abstract class SpliceInterpreter {

  private def logger = BitcoinSLogger.logger

  private def isInvalid(p: ScriptProgram): Option[ScriptProgram] =
    if (p.stack.size < 2) {
      logger.error("Must have at least 2 elements on the stack")
      Some(ScriptProgram(p, ScriptErrorInvalidStackOperation))
    } else None

  /**
   * Concatenates two strings
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_cat]]
   */
  def opCat(p: ScriptProgram): ScriptProgram =
    isInvalid(p).getOrElse {
      val v1 = p.stack(1)
      val v2 = p.stack(0)
      if (v1.bytes.size + v2.bytes.size > Consensus.maxScriptElementSize) {
        ScriptProgram(p, ScriptErrorPushSize)
      } else {
        ((v1, v2) match {
          case (s1: ScriptConstant, s2: ScriptConstant) => Some(s1 ++ s2)
          case _ => None
        }) match {
          case Some(n) => ScriptProgram(p, n :: p.stack.tail.tail, p.script.tail)
          case None => ScriptProgram(p, ScriptErrorUnknownError)
        }
      }
    }

  /**
   * Split the operand at the given position. This operation is the exact inverse of OP_CAT
   * Spec info
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-reenabled-opcodes.md#op_split]]
   */
  def opSplit(p: ScriptProgram): ScriptProgram =
    isInvalid(p).getOrElse {
      //Split point is congruent
      ScriptNumber(p.stack(0).bytes, ScriptFlagUtil.requireMinimalData(p.flags)) match {
        case Success(l) =>
          val pos = l.toLong
          val data = p.stack(1).bytes
          if (pos >= 0 && pos.toLong <= data.size) {
            val (n1, n2) = data.splitAt(pos)
            ScriptProgram(p, List(ScriptConstant(n2), ScriptConstant(n1)), p.script.tail)
          } else ScriptProgram(p, ScriptErrorInvalidSplitRange)
        case Failure(_) => ScriptProgram(p, ScriptErrorUnknownError)
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
}

object SpliceInterpreter extends SpliceInterpreter