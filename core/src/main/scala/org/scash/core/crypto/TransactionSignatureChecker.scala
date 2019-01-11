package org.scash.core.crypto

import org.scash.core.script.constant.ScriptToken
import org.scash.core.script.crypto._
import org.scash.core.script.flag.{ ScriptFlag, ScriptFlagUtil }
import org.scash.core.util.{ BitcoinSLogger, BitcoinSUtil, BitcoinScriptUtil }
import org.scash.core.crypto
import org.scash.core.protocol.script.ScriptPubKey
import org.scash.core.protocol.transaction.TransactionOutput
import org.scash.core.script.result.{ ScriptError, ScriptErrorInvalidStackOperation, ScriptErrorSigNullFail }

import scalaz.{ -\/, \/, \/- }
import scalaz.std.list._
import scalaz.syntax.applicative._

import scodec.bits.ByteVector
import scala.annotation.tailrec

/**
 * Created by chris on 2/16/16.
 * Responsible for checking digital signatures on inputs against their respective
 * public keys
 */
trait TransactionSignatureChecker extends BitcoinSLogger {

  /**
   * Checks the signature of a scriptSig in the spending transaction against the
   * given scriptPubKey & explicitly given public key
   * This is useful for instances of non standard scriptSigs
   *
   * @param txSignatureComponent the relevant transaction information for signature checking
   * @param script the current script state inside the interpreter - this is needed in the case of OP_CODESEPARATORS
   * @param pubKey the public key the signature is being checked against
   * @param signature the signature which is being checked against the transaction & the public key
   * @param flags the script flags used to check validity of the signature
   * @return a boolean indicating if the signature is valid or not
   */
  def checkSignature(txSignatureComponent: TxSigComponent, script: Seq[ScriptToken],
    pubKey: ECPublicKey, signature: ECDigitalSignature, flags: Seq[ScriptFlag]): TransactionSignatureCheckerResult = {
    val pubKeyEncodedCorrectly = BitcoinScriptUtil.isValidPubKeyEncoding(pubKey, flags)
    if (ScriptFlagUtil.requiresStrictDerEncoding(flags) && !DERSignatureUtil.isValidSignatureEncoding(signature)) {
      logger.error("Signature was not strictly encoded der: " + signature.hex)
      SignatureValidationErrorNotStrictDerEncoding
    } else if (ScriptFlagUtil.requireLowSValue(flags) && !DERSignatureUtil.isLowS(signature)) {
      logger.error("Signature did not have a low s value")
      SignatureValidationErrorHighSValue
    } else if (ScriptFlagUtil.requireStrictEncoding(flags) && signature.bytes.nonEmpty &&
      !HashType.isDefinedHashtypeSignature(signature)) {
      logger.error("signature: " + signature.hex)
      logger.error("Hash type was not defined on the signature, got: " + signature.bytes.last)
      SignatureValidationErrorHashType
    } else if (pubKeyEncodedCorrectly.isDefined) {
      val result = SignatureValidationErrorPubKeyEncoding
      logger.error("The public key given for signature checking was not encoded correctly, err: " + result)
      result
    } else {
      val sigsRemovedScript = BitcoinScriptUtil.calculateScriptForChecking(txSignatureComponent, signature, script)
      val hashTypeByte = if (signature.bytes.nonEmpty) signature.bytes.last else 0x00.toByte
      val hashType = HashType(ByteVector(0.toByte, 0.toByte, 0.toByte, hashTypeByte))
      val spk = ScriptPubKey.fromAsm(sigsRemovedScript)
      val hashForSignature = TransactionSignatureSerializer.hashForSignature(
        TxSigComponent(
          txSignatureComponent.transaction,
          txSignatureComponent.inputIndex,
          TransactionOutput(txSignatureComponent.output.value, spk),
          txSignatureComponent.flags),
        hashType)
      logger.trace("Hash for signature: " + BitcoinSUtil.encodeHex(hashForSignature.bytes))
      val isValid = pubKey.verify(hashForSignature, stripHashType(signature))
      if (isValid) SignatureValidationSuccess
      else nullFailCheck(Seq(signature), SignatureValidationErrorIncorrectSignatures, flags)
    }
  }

  def checkSig(
    txSig: TxSigComponent,
    scrpt: Seq[ScriptToken],
    pubKey: ECPublicKey,
    sig: ECDigitalSignature,
    flags: Seq[ScriptFlag]): ScriptError \/ Boolean = {
    val sigsRemovedScript = BitcoinScriptUtil.calculateScriptForChecking(txSig, sig, scrpt)
    val hashTypeByte = sig.bytes.lastOption.getOrElse(0x00.toByte)
    val hashType = HashType(ByteVector(0.toByte, 0.toByte, 0.toByte, hashTypeByte))
    val spk = ScriptPubKey.fromAsm(sigsRemovedScript)
    val txSComp = TxSigComponent(txSig.transaction, txSig.inputIndex, TransactionOutput(txSig.output.value, spk), txSig.flags)
    val hashForSignature = TransactionSignatureSerializer.hashForSignature(txSComp, hashType)

    val success = pubKey.verify(hashForSignature, stripHashType(sig))

    nullFailCheck(sig.point[List], flags, success)
  }

  /**
   * This is a helper function to check digital signatures against public keys
   * if the signature does not match this public key, check it against the next
   * public key in the sequence
   * @param txSignatureComponent the tx signature component that contains all relevant transaction information
   * @param script the script state this is needed in case there is an OP_CODESEPARATOR inside the script
   * @param sigs the signatures that are being checked for validity
   * @param pubKeys the public keys which are needed to verify that the signatures are correct
   * @param flags the script verify flags which are rules to verify the signatures
   * @return a boolean indicating if all of the signatures are valid against the given public keys
   */
  @tailrec
  final def multiSignatureEvaluator(txSignatureComponent: TxSigComponent, script: Seq[ScriptToken],
    sigs: List[ECDigitalSignature], pubKeys: List[ECPublicKey], flags: Seq[ScriptFlag],
    requiredSigs: Long): TransactionSignatureCheckerResult = {
    logger.trace("Signatures inside of helper: " + sigs)
    logger.trace("Public keys inside of helper: " + pubKeys)
    if (sigs.size > pubKeys.size) {
      //this is how bitcoin core treats this. If there are ever any more
      //signatures than public keys remaining we immediately return
      //false https://github.com/bitcoin/bitcoin/blob/8c1dbc5e9ddbafb77e60e8c4e6eb275a3a76ac12/src/script/interpreter.cpp#L943-L945
      logger.info("We have more sigs than we have public keys remaining")
      nullFailCheck(sigs, SignatureValidationErrorIncorrectSignatures, flags)
    } else if (requiredSigs > sigs.size) {
      //for the case when we do not have enough sigs left to check to meet the required signature threshold
      //https://github.com/bitcoin/bitcoin/blob/8c1dbc5e9ddbafb77e60e8c4e6eb275a3a76ac12/src/script/interpreter.cpp#L990-L991
      logger.info("We do not have enough sigs to meet the threshold of requireSigs in the multiSignatureScriptPubKey")
      nullFailCheck(sigs, SignatureValidationErrorSignatureCount, flags)
    } else if (sigs.nonEmpty && pubKeys.nonEmpty) {
      val sig = sigs.head
      val pubKey = pubKeys.head
      val result = checkSignature(txSignatureComponent, script, pubKey, sig, flags)
      result match {
        case SignatureValidationSuccess =>
          multiSignatureEvaluator(txSignatureComponent, script, sigs.tail, pubKeys.tail, flags, requiredSigs - 1)
        case SignatureValidationErrorIncorrectSignatures | SignatureValidationErrorNullFail =>
          //notice we pattern match on 'SignatureValidationErrorNullFail' here, this is because
          //'checkSignature' may return that result, but we need to continue evaluating the signatures
          //in the multisig script, we don't check for nullfail until evaluation the OP_CHECKMULTSIG is completely done
          multiSignatureEvaluator(txSignatureComponent, script, sigs, pubKeys.tail, flags, requiredSigs)
        case x @ (SignatureValidationErrorNotStrictDerEncoding | SignatureValidationErrorSignatureCount |
          SignatureValidationErrorPubKeyEncoding | SignatureValidationErrorHighSValue |
          SignatureValidationErrorHashType) =>
          nullFailCheck(sigs, x, flags)
      }
    } else if (sigs.isEmpty) {
      //means that we have checked all of the sigs against the public keys
      //validation succeeds
      SignatureValidationSuccess
    } else nullFailCheck(sigs, SignatureValidationErrorIncorrectSignatures, flags)

  }

  def multiSigCheck(
    txSig: TxSigComponent,
    nonSepScript: Seq[ScriptToken],
    sigs: List[ECDigitalSignature],
    pubKeys: List[ECPublicKey],
    flags: Seq[ScriptFlag],
    requiredSigs: Long): ScriptError \/ Boolean = {
    logger.error("Signatures inside of helper: " + sigs.size)
    logger.error("Public keys inside of helper: " + pubKeys.size)
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
  private def nullFailCheck(sigs: Seq[ECDigitalSignature], result: TransactionSignatureCheckerResult, flags: Seq[ScriptFlag]): TransactionSignatureCheckerResult = {
    val nullFailEnabled = ScriptFlagUtil.requireScriptVerifyNullFail(flags)
    if (nullFailEnabled && !result.isValid && sigs.exists(_.bytes.nonEmpty)) {
      //we need to check that all signatures were empty byte vectors, else this fails because of BIP146 and nullfail
      SignatureValidationErrorNullFail
    } else result
  }

  private def nullFailCheck(sigs: List[ECDigitalSignature], flags: Seq[ScriptFlag], isValid: Boolean): ScriptError \/ Boolean =
    if (!isValid && ScriptFlagUtil.requireScriptVerifyNullFail(flags) && sigs.exists(_.bytes.nonEmpty)) {
      //we need to check that all signatures were empty byte vectors, else this fails because of BIP146 and nullfail
      -\/(ScriptErrorSigNullFail)
    } else \/-(isValid)

  /** Removes the hash type from the [[crypto.ECDigitalSignature]] */
  private def stripHashType(sig: ECDigitalSignature) = ECDigitalSignature(sig.bytes.init)
}

object TransactionSignatureChecker extends TransactionSignatureChecker

