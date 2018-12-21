package org.scash.core
/**
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation }
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram): ScriptProgram \/ ScriptProgram =
    checkNum(p, 2).leftMap(ScriptProgram(p, _))

  def checkTriary(p: => ScriptProgram): ScriptError \/ ScriptProgram = checkNum(p, 3)

  def checkNum(p: => ScriptProgram, n: Int): ScriptError \/ ScriptProgram =
    to(p)(ScriptErrorInvalidStackOperation, p.stack.size < n)

  def to[A](a: => A)(err: ScriptError, cond: Boolean): ScriptError \/ A = {
    if (cond) {
      logger.error(s"Script failed with $err")
      -\/(err)
    } else \/-(a)
  }
}
