package org.scash.core

import org.scalatest.MustMatchers
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant.{ ScriptOperation, ScriptToken }
import org.scash.core.script.result.ScriptError
import org.scash.core.util.TestUtil

trait TestHelpers extends MustMatchers {

  def checkBinaryOp(
    a: ScriptToken,
    b: ScriptToken,
    op: ScriptOperation,
    ex: List[ScriptToken])(
    interpreter: ScriptProgram => ScriptProgram) = {
    val p = interpreter(ScriptProgram(TestUtil.testProgramExecutionInProgress, List(a, b).reverse, List(op)))

    p.stack must be(ex)
    p.script.isEmpty must be(true)
  }

  def checkOpError(
    stack: List[ScriptToken],
    op: ScriptOperation,
    ex: ScriptError)(
    interpreter: ScriptProgram => ScriptProgram) =
    interpreter(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, List(op))) match {
      case e: ExecutedScriptProgram => e.error must be(Some(ex))
      case _ => assert(false)
    }
}

