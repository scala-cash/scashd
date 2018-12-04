package org.scash.core
/**
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script.result.{ ScriptErrorInvalidOperandSize, ScriptErrorInvalidStackOperation }
import org.scash.core.util.BitcoinSLogger

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram): Option[ScriptProgram] =
    if (p.stack.size < 2) {
      logger.error("Must have at least 2 elements on the stack")
      Some(ScriptProgram(p, ScriptErrorInvalidStackOperation))
    } else None

  def checkSameSize(p: => ScriptProgram): Option[ScriptProgram] =
    if (p.stack(0).size != p.stack(1).size) {
      logger.error("Inputs must be the same size")
      Some(ScriptProgram(p, ScriptErrorInvalidOperandSize))
    } else None

}
