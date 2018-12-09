package org.scash.core

import org.scalatest.MustMatchers
import org.scash.core.script.{ ExecutedScriptProgram, ScriptProgram }
import org.scash.core.script.constant.{ ScriptOperation, ScriptToken }
import org.scash.core.script.result.ScriptError
import org.scash.core.util.TestUtil

trait TestHelpers extends MustMatchers {

  def checkBinaryOp(
    op: ScriptOperation,
    interpreter: ScriptProgram => ScriptProgram)(
    a: ScriptToken,
    b: ScriptToken,
    ex: ScriptToken) = {
    val p = interpreter(ScriptProgram(TestUtil.testProgramExecutionInProgress, List(a, b).reverse, List(op)))
    p.stack.head must be(ex)
    p.script.isEmpty must be(true)
  }

  def checkOpError(
    op: ScriptOperation,
    interpreter: ScriptProgram => ScriptProgram)(
    stack: List[ScriptToken],
    ex: ScriptError) =
    interpreter(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack.reverse, List(op))) match {
      case e: ExecutedScriptProgram => e.error must be(Some(ex))
      case _ => assert(false)
    }
}

