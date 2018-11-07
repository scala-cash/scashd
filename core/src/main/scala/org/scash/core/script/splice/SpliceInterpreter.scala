package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.consensus.Consensus
import org.scash.core.script.constant._
import org.scash.core.script.result.{ ScriptErrorInvalidStackOperation, ScriptErrorPushSize, ScriptErrorUnknownError }
import org.scash.core.script.ScriptProgram
import org.scash.core.util.{ BitcoinSLogger, BitcoinSUtil }

sealed abstract class SpliceInterpreter {

  private def logger = BitcoinSLogger.logger

  def opCat(program: ScriptProgram): ScriptProgram = {
    if (program.stack.size < 2) {
      logger.error("Must have at least 2 elements on the stack for OP_CAT")
      ScriptProgram(program, ScriptErrorInvalidStackOperation)
    } else {
      val v1 = program.stack(1)
      val v2 = program.stack(0)

      if (v1.bytes.size + v2.bytes.size > Consensus.maxScriptElementSize) {
        ScriptProgram(program, ScriptErrorPushSize)
      } else {
        ((v1, v2) match {
          case (s1: ScriptConstant, s2: ScriptConstant) => Some(s1 ++ s2)
          case _ => None
        }) match {
          case Some(n) => ScriptProgram(program, n :: program.stack.tail.tail, program.script.tail)
          case None => ScriptProgram(program, ScriptErrorUnknownError)
        }
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
}

object SpliceInterpreter extends SpliceInterpreter