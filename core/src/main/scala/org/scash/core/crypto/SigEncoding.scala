package org.scash.core.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018-2019 The SCash Developers (MIT License)
 */

import org.scash.core.script
import org.scash.core.script.crypto.{ SigHashType, HashType }
import org.scash.core.script.flag._
import org.scash.core.script.result._
import org.scash.core.util.BitcoinSLogger
import scalaz.{ \/, \/- }
import scodec.bits.ByteVector

object SigEncoding {

  def logger = BitcoinSLogger.logger

  /**
   * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len
   * S> <S> <hashtype>, where R and S are not negative (their first byte has its
   * highest bit not set), and not excessively padded (do not start with a 0 byte,
   * unless an otherwise negative number follows, in which case a single 0 byte is
   * necessary and even required).
   *
   * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
   *
   * This function is consensus-critical since BIP66.
   */
  def isValidSignatureEncoding(sig: ByteVector): Boolean = {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.

    // Minimum and maximum size constraints.
    if (sig.size < 8 || sig.size > 72) return false

    // A signature is of type 0x30 (compound)
    if (sig.head != 0x30) return false

    // Make sure the length covers the entire sig
    // Remove:
    // * 1 byte for the compound type.
    // * 1 byte for the length of the signature.
    if (sig(1) != sig.size - 2) return false

    //
    // Check that R is an positive integer of sensible size.
    //
    if (sig(2) != 0x02) return false

    //Extract the length of the R element
    val rLength = sig(3)

    // Zero-length integers are not allowed for R.
    if (rLength == 0) return false

    //Negative numbers not allowed for R
    if ((sig(4) & 0x80) != 0) return false

    // Make sure the length of the R element is consistent with the signature
    // size.
    // Remove:
    // * 1 byte for the compound type.
    // * 1 byte for the length of the signature.
    // * 2 bytes for the integer type of R and S.
    // * 2 bytes for the size of R and S.
    // * 1 byte for S itself
    // Extract the length of the S element.
    if (rLength > (sig.size - 7)) return false

    // Null bytes at the start of R are not allowed, unless R would otherwise be
    // interpreted as a negative number.
    //
    // /!\ This check can only be performed after we checked that rLength is
    // consistent with the size of the signature or we risk to access out of
    // bound elements.
    if (rLength > 1 && (sig(4) == 0x00) && !((sig(5) & 0x80) != 0)) return false

    //
    // Check that S is an positive integer of sensible size.
    //

    // S's definition starts after R's definition:
    // * 1 byte for the compound type.
    // * 1 byte for the length of the signature.
    // * 1 byte for the size of R.
    // * rLength bytes for R itself.
    // * 1 byte to get to S.
    val sStart = rLength + 4

    //Check wether the S element is an Integer
    if (sig(sStart) != 0x02) return false

    //Extract the length of the S element
    val sLength = sig(sStart + 1)

    // Zero-length integers are not allowed for S.
    if (sLength == 0) return false

    // Negative numbers are not allowed for S.
    if ((sig(sStart + 2) & 0x80) != 0) return false

    // Verify that the length of S is consistent with the size of the signature
    // including metadatas:
    // * 1 byte for the integer type of S.
    // * 1 byte for the size of S.
    if ((sStart + sLength + 2) != sig.size) return false

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    //
    // /!\ This check can only be performed after we checked that lenR and lenS
    // are consistent with the size of the signature or we risk to access
    // out of bound elements.
    if (sLength > 1 && (sig(sStart + 2) == 0x00) && !((sig(sStart + 3) & 0x80) != 0)) return false

    true
  }

  /**
   * Test whether the tx element is a valid signature based
   * on the encoding, S value, and sighash type. Requires
   * [[ScriptVerifyDerSig]] | [[ScriptVerifyLowS]] | [[ScriptVerifyStrictEnc]],
   * [[ScriptVerifyLowS]] &&  [[ScriptVerifyStrictEnc]]
   * to be enabled respectively. Note that this will allow zero-length signatures.
   */
  def checkRawSigEncoding(
    sig: => ByteVector,
    flags: Seq[ScriptFlag]): ScriptError \/ ECDigitalSignature =
    for {
      _ <- script.checkFlags(flags)(
        List(ScriptVerifyDerSig, ScriptVerifyLowS, ScriptVerifyStrictEnc),
        ScriptErrorSigDer,
        !isValidSignatureEncoding(sig))
      _ <- script.checkFlag(flags)(ScriptVerifyLowS, ScriptErrorSigHighS, !DERSignatureUtil.isLowS(sig))
    } yield ECDigitalSignature(sig)

  def checkTxSigEncoding(
    sig: => ECDigitalSignature,
    flags: Seq[ScriptFlag]): ScriptError \/ ECDigitalSignature =
    //allow empty sigs
    if (sig.isEmpty)
      \/-(sig)
    else for {
      _ <- checkRawSigEncoding(sig.bytes.init, flags)
      ec <- if (ScriptFlagUtil.requireStrictEncoding(flags)) {
        val f = script.to(sig) _
        for {
          _ <- f(ScriptErrorSigHashType, !(SigHashType.isDefined(sig)))
          useForkId = SigHashType.fromByte(sig.bytes.last).has(HashType.FORKID)
          forkIdEnabled = ScriptFlagUtil.sighashForkIdEnabled(flags)
          _ <- f(ScriptErrorIllegalForkId, !forkIdEnabled && useForkId)
          _ <- f(ScriptErrorMustUseForkId, forkIdEnabled && !useForkId)
        } yield sig
      } else \/-(sig)
    } yield ec

  def checkDataSigEncoding(
    sig: => ECDigitalSignature,
    flags: Seq[ScriptFlag]): ScriptError \/ ECDigitalSignature = {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (sig.isEmpty)
      \/-(sig)
    else checkRawSigEncoding(sig.bytes, flags)
  }
  /**
   * Determines if the given pubkey is valid in accordance to the given [[ScriptFlag]].
   * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/058a6c027b5d4749b4fa23a0ac918e5fc04320e8/src/script/sigencoding.cpp#L245]]
   */
  def checkPubKeyEncoding(
    pubKey: => ECPublicKey,
    flags: Seq[ScriptFlag]): ScriptError \/ ECPublicKey = {
    val f = script.checkFlag(flags) _
    for {
      _ <- f(ScriptVerifyStrictEnc, ScriptErrorPubKeyType, !isKeyEncoding(pubKey))
      _ <- f(ScriptVerifyCompressedPubkeytype, ScriptErrorNonCompressedPubkey, !isCompressedPubKey(pubKey))
    } yield pubKey
  }

  /**
   * Returns true if the key is compressed or uncompressed, false otherwise
   * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/058a6c027b5d4749b4fa23a0ac918e5fc04320e8/src/script/sigencoding.cpp#L217]]
   */
  def isKeyEncoding(key: => ECPublicKey): Boolean = key.bytes.size match {
    case 33 =>
      // Compressed public key: must start with 0x02 or 0x03.
      key.bytes.head == 0x02 || key.bytes.head == 0x03
    case 65 =>
      //Non-compressed public key must start with 0x04
      key.bytes.head == 0x04
    case _ =>
      // Non canonical public keys are invalid
      false
  }

  /** Checks if the given public key is a compressed public key */
  def isCompressedPubKey(key: => ECPublicKey): Boolean =
    (key.bytes.size == 33) && (key.bytes.head == 0x02 || key.bytes.head == 0x03)

}
