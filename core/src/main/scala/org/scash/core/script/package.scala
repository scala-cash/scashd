package org.scash.core
/**
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.script.constant.{ ScriptOperation, ScriptToken }
import org.scash.core.script.flag.ScriptFlag
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation }
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram): ScriptProgram \/ ScriptProgram =
    checkNum(p, 2).leftMap(ScriptProgram(p, _))

  def getThree(p: => List[ScriptToken]): ScriptError \/ (ScriptToken, ScriptToken, ScriptToken) =
    p match {
      case a :: b :: c :: _ => \/-(a, b, c)
      case _ => -\/(ScriptErrorInvalidStackOperation)
    }

  def checkNum(p: => ScriptProgram, n: Int): ScriptError \/ ScriptProgram =
    to(p)(ScriptErrorInvalidStackOperation, p.stack.size < n)

  def to[A](a: => A)(err: ScriptError, cond: Boolean): ScriptError \/ A = {
    if (cond) {
      logger.error(s"Script failed with $err")
      -\/(err)
    } else \/-(a)
  }

  def checkFlag(flags: Seq[ScriptFlag])(flag: ScriptFlag, err: ScriptError, f: => Boolean = false): ScriptError \/ Seq[ScriptFlag] =
    to(flags)(err, flags.contains(flag) && f)

  def checkFlags(flags: Seq[ScriptFlag])(reqs: Seq[ScriptFlag], err: ScriptError, f: => Boolean = false): ScriptError \/ Seq[ScriptFlag] =
    to(flags)(err, flags.find(reqs.contains).isDefined && f)

}
