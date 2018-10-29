package org.scash.core.protocol.script.testprotocol

import org.scash.core.crypto.DoubleSha256Digest
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.script.constant.{ ScriptToken, ScriptConstant }
import org.scash.core.script.crypto.HashType

/**
 * Created by tom on 7/21/16.
 */
trait SignatureHashTestCase {
  def transaction: Transaction
  def script: ScriptPubKey
  def inputIndex: UInt32
  def hashTypeNum: Int32
  def hashType: HashType
  def regularSigHash: DoubleSha256Digest
  def noForkKidSigHash: DoubleSha256Digest
  def replayProtectedSigHash: DoubleSha256Digest
}

case class SignatureHashTestCaseImpl(
  transaction: Transaction,
  script: ScriptPubKey,
  inputIndex: UInt32,
  hashTypeNum: Int32,
  hashType: HashType,
  regularSigHash: DoubleSha256Digest,
  noForkKidSigHash: DoubleSha256Digest,
  replayProtectedSigHash: DoubleSha256Digest) extends SignatureHashTestCase