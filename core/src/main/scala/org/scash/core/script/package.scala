package org.scash.core
/**
 *   Copyright (c) 2018-2019 The Scash Developers (MIT License)
 */
import org.scash.core.script.result.ScriptErrorInvalidStackOperation
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram) = checkNum(p, 2)

  def checkTriary(p: => ScriptProgram) = checkNum(p, 3)

  private def checkNum(p: => ScriptProgram, n: Int): ScriptProgram \/ ScriptProgram =
    if (p.stack.size < n) {
      logger.error(s"Must have at least $n elements on the stack for ${p.script.headOption}")
      -\/(ScriptProgram(p, ScriptErrorInvalidStackOperation))
    } else \/-(p)
}
