package org.scash.core
/**
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.script.constant.ScriptToken
import org.scash.core.script.flag.ScriptFlag
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation }
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

package object script {
  def logger = BitcoinSLogger.logger

  def checkBinary(p: => ScriptProgram): ScriptProgram \/ ScriptProgram =
    checkSize(p.stack, 2).bimap(ScriptProgram(p, _), _ => p)

  def getTop(p: => List[ScriptToken]): ScriptError \/ ScriptToken = p match {
    case h :: _ => \/-(h)
    case Nil => -\/(ScriptErrorInvalidStackOperation)
  }

  def getTwo(p: => List[ScriptToken]): ScriptError \/ (ScriptToken, ScriptToken) =
    p match {
      case a :: b :: _ => \/-(a, b)
      case _ => -\/(ScriptErrorInvalidStackOperation)
    }

  def getThree(p: => List[ScriptToken]): ScriptError \/ (ScriptToken, ScriptToken, ScriptToken) =
    p match {
      case a :: b :: c :: _ => \/-(a, b, c)
      case _ => -\/(ScriptErrorInvalidStackOperation)
    }

  def checkSize(p: => List[ScriptToken], n: Int): ScriptError \/ Unit =
    failIf(p.size < n, ScriptErrorInvalidStackOperation)

  def failIf(cond: Boolean, err: ScriptError): ScriptError \/ Unit =
    to(())(err, cond)

  def to[A](a: => A)(err: ScriptError, cond: Boolean): ScriptError \/ A = {
    if (cond) {
      logger.error(s"Script failed with $err")
      -\/(err)
    } else \/-(a)
  }

  def checkFlag(flags: Seq[ScriptFlag])(flag: ScriptFlag, err: ScriptError, f: => Boolean = true): ScriptError \/ Seq[ScriptFlag] =
    to(flags)(err, flags.contains(flag) && f)

  def checkFlags(flags: Seq[ScriptFlag])(reqs: Seq[ScriptFlag], err: ScriptError, f: => Boolean = true): ScriptError \/ Seq[ScriptFlag] =
    to(flags)(err, flags.find(reqs.contains).isDefined && f)

}
