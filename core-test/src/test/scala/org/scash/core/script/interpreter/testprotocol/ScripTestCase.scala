package org.scash.core.script.interpreter.testprotocol

import org.scash.core.protocol.script.{ ScriptPubKey, ScriptSignature }
import org.scash.core.script.result.ScriptResult

/**
 * Created by chris on 1/18/16.
 * This represents a core test case for valid and invalid scripts
 * the scripts can be seen in the script_tests.json file
 * files.
 */
trait ScripTestCase {
  def scriptSig: ScriptSignature
  def scriptPubKey: ScriptPubKey
  def flags: String
  def expectedResult: ScriptResult
  def comments: String
  def raw: String
}

case class ScriptTestCaseImpl(
  scriptSig: ScriptSignature,
  scriptPubKey: ScriptPubKey, flags: String, expectedResult: ScriptResult,
  comments: String, raw: String) extends ScripTestCase
