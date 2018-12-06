package org.scash.core
/**
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script.result.ScriptErrorInvalidStackOperation
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram): ScriptProgram \/ ScriptProgram =
    if (p.stack.size < 2) {
      logger.error("Must have at least 2 elements on the stack")
      -\/(ScriptProgram(p, ScriptErrorInvalidStackOperation))
    } else \/-(p)
}
