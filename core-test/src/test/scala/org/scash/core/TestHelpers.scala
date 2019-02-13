package org.scash.core

import org.scalatest.MustMatchers
import org.scash.core.policy.Policy
import org.scash.core.script.{ExecutedScriptProgram, ScriptProgram}
import org.scash.core.script.constant.{ScriptConstant, ScriptOperation, ScriptToken}
import org.scash.core.script.flag.ScriptFlag
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

  def checkPass(
    op: ScriptOperation,
    interpreter: ScriptProgram => ScriptProgram
  )(
    stack: List[ScriptToken],
    ex: Option[ScriptToken],
    flags: Seq[ScriptFlag] = Policy.standardFlags
  ) = {
    val p = interpreter(ScriptProgram(ScriptProgram(TestUtil.noflagTestProgram, flags), stack, List(op)))
    p.stack.headOption must be(ex)
    p.script.isEmpty must be(true)
  }

  def checkOpError(
    op: ScriptOperation,
    interpreter: ScriptProgram => ScriptProgram,
    flags: Seq[ScriptFlag] = Policy.standardFlags)(
    stack: List[ScriptToken],
    ex: ScriptError) =
    interpreter(ScriptProgram(ScriptProgram(TestUtil.noflagTestProgram, flags), stack, List(op))) match {
      case e: ExecutedScriptProgram => e.error must be(Some(ex))
      case _ => assert(false)
    }

  def compare(
    op: ScriptOperation,
    interpreter: ScriptProgram => ScriptProgram)(
    s: List[ScriptToken],
    ex: ScriptToken) = {
    val rebuiltEx = s.tail.headOption.map { n =>
      if (n.bytes.isEmpty && ex.size > 0) {
        ScriptConstant(ex.bytes.update(ex.bytes.size - 1, (ex.bytes.last & 0x7F).toByte))
      } else ex
    }.getOrElse(ex)

    val p = ScriptProgram(TestUtil.testProgramExecutionInProgress, s, List(op))
    interpreter(p).stack.head must be(rebuiltEx)
  }
}

