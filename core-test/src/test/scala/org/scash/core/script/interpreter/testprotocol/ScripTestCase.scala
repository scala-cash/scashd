package org.scash.core.script.interpreter.testprotocol

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.protocol.script.{ ScriptPubKey, ScriptSignature }
import org.scash.core.script.result.ScriptResult

/**
 * This represents a test case for valid and invalid scripts
 * the scripts can be seen in the script_tests.json file
 * files.
 */
case class ScripTestCase(
  scriptSig: ScriptSignature,
  scriptPubKey: ScriptPubKey,
  flags: String,
  expectedResult: ScriptResult,
  comments: String,
  raw: String)
