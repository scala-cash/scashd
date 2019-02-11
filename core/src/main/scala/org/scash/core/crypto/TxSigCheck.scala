package org.scash.core.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018-2019 The SCash Developers (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.script.constant.ScriptToken
import org.scash.core.script.crypto._
import org.scash.core.script.flag.{ ScriptFlag, ScriptVerifyNullFail }
import org.scash.core.util.{ BitcoinSLogger, BitcoinScriptUtil }
import org.scash.core.script
import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.TransactionOutput
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation, ScriptErrorSigNullFail }
import scalaz.{ -\/, \/, \/- }
import scalaz.std.list._
import scalaz.syntax.applicative._

import scala.annotation.tailrec

/**
 * Responsible for checking digital signatures on inputs against their respective
 * public keys
 */
trait TxSigCheck extends BitcoinSLogger {

  /**
   * Checks the signature of a scriptSig in the spending transaction against the
   * given scriptPubKey & explicitly given public key
   * This is useful for instances of non standard scriptSigs
   *
   * @param txSig the relevant transaction information for signature checking
   * @param nonSepScript Script with no separators
   * @param pubKey the public key the signature is being checked against
   * @param sig the signature which is being checked against the transaction & the public key
   * @param flags the script flags used to check validity of the signature
   * @return a boolean indicating if the signature is valid or not
   */
  def checkSig(
    txSig: TxSigComponent,
    nonSepScript: Seq[ScriptToken],
    pubKey: ECPublicKey,
    sig: ECDigitalSignature,
    flags: Seq[ScriptFlag]): ScriptError \/ Boolean = {
    val sigsRemovedScript = BitcoinScriptUtil.calculateScriptForChecking(txSig, sig, nonSepScript)
    val hashTypeByte = sig.bytes.lastOption.getOrElse(0x00.toByte)
    val hashType = SigHashType.fromByte(hashTypeByte)
    val spk = ScriptPubKey.fromAsm(sigsRemovedScript)
    val txSComp = TxSigComponent(txSig.transaction, txSig.inputIndex, TransactionOutput(txSig.output.value, spk), txSig.flags)
    val hashForSignature = TransactionSignatureSerializer.hashForSignature(txSComp, hashType)
    val stripHashByte = ECDigitalSignature(sig.bytes.init)
    val success = pubKey.verify(hashForSignature, stripHashByte)

    nullFailCheck(sig.point[List], flags, success)
  }

  /**
   * This is a helper function to check digital signatures against public keys
   * if the signature does not match this public key, check it against the next
   * public key in the sequence
   * @param txSig the tx signature component that contains all relevant transaction information
   * @param nonSepScript Script with no separators
   * @param sigs the signatures that are being checked for validity
   * @param pubKeys the public keys which are needed to verify that the signatures are correct
   * @param flags the script verify flags which are rules to verify the signatures
   */
  def multiSigCheck(
    txSig: TxSigComponent,
    nonSepScript: Seq[ScriptToken],
    sigs: List[ECDigitalSignature],
    pubKeys: List[ECPublicKey],
    flags: Seq[ScriptFlag],
    requiredSigs: Long): ScriptError \/ Boolean = {
    @tailrec
    def go(ss: List[ECDigitalSignature], pks: List[ECPublicKey], reqSigs: Long): ScriptError \/ Boolean = (ss, pks) match {
      case (s, p) if (s.length > p.length) =>
        logger.info("We have more sigs than we have public keys remaining")
        nullFailCheck(sigs, flags, false)
      case (s, _) if (reqSigs > s.length) =>
        logger.info("We do not have enough sigs to meet the threshold of requireSigs in the multiSignatureScriptPubKey")
        val err = nullFailCheck(ss, flags, false)
        if (err.isRight) -\/(ScriptErrorInvalidStackOperation) else err
      case (sig :: sigsT, pubKey :: pubKeysT) =>
        (for {
          _ <- SigEncoding.checkTxSigEncoding(sig, flags)
          _ <- SigEncoding.checkPubKeyEncoding(pubKey, flags)
          b <- checkSig(txSig, nonSepScript, pubKey, sig, flags)
        } yield b) match {
          case \/-(true) => go(sigsT, pubKeysT, reqSigs - 1)
          //checkSig may return a negative result, but we need to continue evaluating the signatures
          //in the multisig script, we don't check for nullfail until evaluation the OP_CHECKMULTSIG is completely done
          case \/-(false) | -\/(ScriptErrorSigNullFail) => go(ss, pubKeysT, reqSigs)
          case s => s
        }
      //means that we have checked all of the sigs against the pubkeys
      case (Nil, _) => \/-(true)
      case _ => nullFailCheck(sigs, flags, false)
    }
    go(sigs, pubKeys, requiredSigs)
  }

  /**
   * If the NULLFAIL flag is set as defined in BIP146, it checks to make sure all failed signatures were an empty byte vector
   * [[https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#NULLFAIL]]
   */
  private def nullFailCheck(sigs: List[ECDigitalSignature], flags: Seq[ScriptFlag], isValid: Boolean): ScriptError \/ Boolean =
    script.checkFlag(flags)(ScriptVerifyNullFail, ScriptErrorSigNullFail, !isValid && sigs.exists(_.bytes.nonEmpty))
      .map(_ => isValid)
}

object TxSigCheck extends TxSigCheck

