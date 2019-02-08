package org.scash.core.protocol.script.testprotocol

import org.scash.core.crypto.DoubleSha256Digest
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.script.crypto.SigHashType

case class LegacySignatureHashTestCase(
  transaction: Transaction,
  script: ScriptPubKey,
  inputIndex: UInt32,
  hashType: SigHashType,
  regularSigHash: DoubleSha256Digest)

case class SignatureHashTestCase(
  transaction: Transaction,
  script: ScriptPubKey,
  inputIndex: UInt32,
  hashType: SigHashType,
  regularSigHash: DoubleSha256Digest,
  noForkKidSigHash: DoubleSha256Digest,
  replayProtectedSigHash: DoubleSha256Digest)