package org.scash.core.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018-2019 The SCash Developers (MIT License)
 */
import org.scash.core.script.flag.{ ScriptFlag, ScriptFlagUtil }
import org.scash.core.script.result.{ ScriptError, ScriptErrorNonCompressedPubkey, ScriptErrorPubKeyType }
import org.scash.core.util.BitcoinSLogger
import scalaz.{ -\/, \/, \/- }

object SigEncoding {
  def logger = BitcoinSLogger.logger
  /**
   * Determines if the given pubkey is valid in accordance to the given [[ScriptFlag]].
   * Mimics this function inside of Bitcoin ABC
   * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/058a6c027b5d4749b4fa23a0ac918e5fc04320e8/src/script/sigencoding.cpp#L245]]
   */
  def checkPubKeyEncoding(
    pubKey: => ECPublicKey,
    flags: Seq[ScriptFlag]): ScriptError \/ ECPublicKey = {
    if (ScriptFlagUtil.requireStrictEncoding(flags) && !isCompressedOrUncompressedPubKey(pubKey)) {
      logger.error(s"invalid pubkey encoding for $pubKey")
      -\/(ScriptErrorPubKeyType)
    } else if (ScriptFlagUtil.requireCompressedPubKey(flags) && !isCompressedPubKey(pubKey)) {
      logger.error(s"COMPRESSED_PUBKEY enabled. Pubkey is not compressed $pubKey")
      -\/(ScriptErrorNonCompressedPubkey)
    } else
      \/-(pubKey)
  }

  /**
   * Returns true if the key is compressed or uncompressed, false otherwise
   * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/058a6c027b5d4749b4fa23a0ac918e5fc04320e8/src/script/sigencoding.cpp#L217]]
   * @param key the public key that is being checked
   * @return true if the key is compressed/uncompressed otherwise false
   */
  def isCompressedOrUncompressedPubKey(key: => ECPublicKey): Boolean = key.bytes.size match {
    case 33 =>
      // Compressed public key: must start with 0x02 or 0x03.
      key.bytes.get(0) == 0x02 || key.bytes.get(0) == 0x03
    case 65 =>
      //Non-compressed public key must start with 0x04
      key.bytes.get(0) == 0x04
    case _ =>
      // Non canonical public keys are invalid
      false
  }

  /** Checks if the given public key is a compressed public key */
  def isCompressedPubKey(key: => ECPublicKey): Boolean = {
    (key.bytes.size == 33) && (key.bytes.head == 0x02 || key.bytes.head == 0x03)
  }
}
