package org.scash.core.wallet.signer

import org.scash.core.crypto._
import org.scash.core.protocol.script._
import org.scash.core.protocol.transaction._
import org.scash.core.script.crypto.HashType
import org.scash.core.wallet.builder.TxBuilderError
import org.scash.core.crypto._
import org.scash.core.number.UInt32
import org.scash.core.policy.Policy
import org.scash.core.util.BitcoinSLogger
import scodec.bits.ByteVector

import scala.concurrent.{ ExecutionContext, Future }

/** The class used to represent a signing process for a specific [[org.scash.core.protocol.script.ScriptPubKey]] type */
sealed abstract class Signer {

  /**
   * The method used to sign a bitcoin unspent transaction output
   * @param signers the [[Signer]] needed to sign the utxo
   * @param output the utxo we are spending
   * @param unsignedTx the unsigned transaction which is spending the utxo
   * @param inputIndex the input index inside of the unsigned transaction which spends the utxo
   * @param hashType the signature hashing algorithm we should use to sign the utxo
   * @param isDummySignature - do not sign the tx for real, just use a dummy signature this is useful for fee estimation
   * @return
   */
  def sign(signers: Seq[Sign], output: TransactionOutput, unsignedTx: Transaction,
    inputIndex: UInt32, hashType: HashType, isDummySignature: Boolean)(implicit ec: ExecutionContext): Future[TxSigComponent]

  def doSign(sigComponent: TxSigComponent, sign: ByteVector => Future[ECDigitalSignature], hashType: HashType,
    isDummySignature: Boolean)(implicit ec: ExecutionContext): Future[ECDigitalSignature] = {
    if (isDummySignature) {
      Future.successful(DummyECDigitalSignature)
    } else {
      TransactionSignatureCreator.createSig(sigComponent, sign, hashType)
    }
  }
}

/** Represents all signers for the bitcoin protocol, we could add another network later like litecoin */
sealed abstract class BitcoinSigner extends Signer

/** Used to sign a [[org.scash.core.protocol.script.P2PKScriptPubKey]] */
sealed abstract class P2PKSigner extends BitcoinSigner {

  override def sign(signers: Seq[Sign], output: TransactionOutput, unsignedTx: Transaction,
    inputIndex: UInt32, hashType: HashType, isDummySignature: Boolean)(implicit ec: ExecutionContext): Future[TxSigComponent] = {
    val spk = output.scriptPubKey
    if (signers.size != 1) {
      Future.fromTry(TxBuilderError.TooManySigners)
    } else {
      val sign: ByteVector => Future[ECDigitalSignature] = signers.head.signFunction
      val unsignedInput = unsignedTx.inputs(inputIndex.toInt)
      val flags = Policy.standardFlags
      val signed: Future[TxSigComponent] = spk match {
        case _: P2PKScriptPubKey =>
          val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
          val signature = doSign(sigComponent, sign, hashType, isDummySignature)
          signature.map { sig =>
            val p2pkScriptSig = P2PKScriptSignature(sig)
            val signedInput = TransactionInput(unsignedInput.previousOutput, p2pkScriptSig, unsignedInput.sequence)
            val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
            val signedTx = BaseTransaction(
              unsignedTx.version,
              signedInputs,
              unsignedTx.outputs,
              unsignedTx.lockTime)
            TxSigComponent(signedTx, inputIndex, output, flags)
          }
        case lock: LockTimeScriptPubKey =>
          lock.nestedScriptPubKey match {
            case _: P2PKScriptPubKey =>
              val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
              val signature = doSign(sigComponent, sign, hashType, isDummySignature)
              signature.map { sig =>
                val p2pkScriptSig = P2PKScriptSignature(sig)
                val signedInput = TransactionInput(unsignedInput.previousOutput, p2pkScriptSig, unsignedInput.sequence)
                val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
                val signedTx = BaseTransaction(
                  unsignedTx.version,
                  signedInputs,
                  unsignedTx.outputs,
                  unsignedTx.lockTime)

                TxSigComponent(signedTx, inputIndex, output, flags)
              }

            case _: P2PKHScriptPubKey | _: MultiSignatureScriptPubKey | _: P2SHScriptPubKey
              | _: NonStandardScriptPubKey
              | _: CLTVScriptPubKey | _: CSVScriptPubKey | EmptyScriptPubKey
              | _: EscrowTimeoutScriptPubKey => Future.fromTry(TxBuilderError.WrongSigner)
          }
        case _: P2PKHScriptPubKey | _: MultiSignatureScriptPubKey | _: P2SHScriptPubKey
          | _: NonStandardScriptPubKey | EmptyScriptPubKey
          | _: EscrowTimeoutScriptPubKey => Future.fromTry(TxBuilderError.WrongSigner)
      }
      signed
    }
  }
}

object P2PKSigner extends P2PKSigner

/** Used to sign a [[org.scash.core.protocol.script.P2PKHScriptPubKey]] */
sealed abstract class P2PKHSigner extends BitcoinSigner {

  override def sign(signers: Seq[Sign], output: TransactionOutput, unsignedTx: Transaction,
    inputIndex: UInt32, hashType: HashType, isDummySignature: Boolean)(implicit ec: ExecutionContext): Future[TxSigComponent] = {
    val spk = output.scriptPubKey
    if (signers.size != 1) {
      Future.fromTry(TxBuilderError.TooManySigners)
    } else {
      val sign = signers.head.signFunction
      val pubKey = signers.head.publicKey
      val unsignedInput = unsignedTx.inputs(inputIndex.toInt)
      val flags = Policy.standardFlags
      val amount = output.value
      val signed: Future[TxSigComponent] = spk match {
        case p2pkh: P2PKHScriptPubKey =>
          if (p2pkh != P2PKHScriptPubKey(pubKey)) {
            Future.fromTry(TxBuilderError.WrongPublicKey)
          } else {
            val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
            val signature = doSign(sigComponent, sign, hashType, isDummySignature)
            signature.map { sig =>
              val p2pkhScriptSig = P2PKHScriptSignature(sig, pubKey)
              val signedInput = TransactionInput(unsignedInput.previousOutput, p2pkhScriptSig, unsignedInput.sequence)
              val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
              val signedTx = BaseTransaction(
                unsignedTx.version,
                signedInputs,
                unsignedTx.outputs,
                unsignedTx.lockTime)

              TxSigComponent(signedTx, inputIndex, output, flags)
            }
          }
        case lock: LockTimeScriptPubKey =>
          lock.nestedScriptPubKey match {
            case p2pkh: P2PKHScriptPubKey =>
              if (p2pkh != P2PKHScriptPubKey(pubKey)) {
                Future.fromTry(TxBuilderError.WrongPublicKey)
              } else {
                val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
                val signature = doSign(sigComponent, sign, hashType, isDummySignature)
                signature.map { sig =>
                  val p2pkhScriptSig = P2PKHScriptSignature(sig, pubKey)
                  val signedInput = TransactionInput(unsignedInput.previousOutput, p2pkhScriptSig, unsignedInput.sequence)
                  val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
                  val signedTx = BaseTransaction(
                    unsignedTx.version,
                    signedInputs,
                    unsignedTx.outputs,
                    unsignedTx.lockTime)

                  TxSigComponent(signedTx, inputIndex, output, flags)
                }
              }
            case _: P2PKScriptPubKey | _: MultiSignatureScriptPubKey | _: P2SHScriptPubKey
              | _: NonStandardScriptPubKey
              | _: CLTVScriptPubKey | _: CSVScriptPubKey | EmptyScriptPubKey
              | _: EscrowTimeoutScriptPubKey => Future.fromTry(TxBuilderError.WrongSigner)
          }
        case _: P2PKScriptPubKey | _: MultiSignatureScriptPubKey | _: P2SHScriptPubKey
          | _: NonStandardScriptPubKey
          | _: EscrowTimeoutScriptPubKey | EmptyScriptPubKey => Future.fromTry(TxBuilderError.WrongSigner)
      }
      signed
    }
  }
}

object P2PKHSigner extends P2PKHSigner

sealed abstract class MultiSigSigner extends BitcoinSigner {
  private val logger = BitcoinSLogger.logger

  override def sign(signersWithPubKeys: Seq[Sign], output: TransactionOutput, unsignedTx: Transaction,
    inputIndex: UInt32, hashType: HashType, isDummySignature: Boolean)(implicit ec: ExecutionContext): Future[TxSigComponent] = {
    val spk = output.scriptPubKey
    val signers = signersWithPubKeys.map(_.signFunction)
    val unsignedInput = unsignedTx.inputs(inputIndex.toInt)
    val flags = Policy.standardFlags
    val amount = output.value
    val signed: Future[TxSigComponent] = spk match {
      case multiSigSPK: MultiSignatureScriptPubKey =>
        val requiredSigs = multiSigSPK.requiredSigs
        if (signers.size < requiredSigs) {
          Future.fromTry(TxBuilderError.WrongSigner)
        } else {
          val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
          val signaturesNested = 0.until(requiredSigs).map(i => doSign(sigComponent, signers(i), hashType, isDummySignature))
          val signatures = Future.sequence(signaturesNested)
          signatures.map { sigs =>
            val multiSigScriptSig = MultiSignatureScriptSignature(sigs)
            val signedInput = TransactionInput(unsignedInput.previousOutput, multiSigScriptSig, unsignedInput.sequence)
            val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
            val signedTx = BaseTransaction(
              unsignedTx.version,
              signedInputs,
              unsignedTx.outputs,
              unsignedTx.lockTime)

            TxSigComponent(signedTx, inputIndex, output, Policy.standardFlags)
          }
        }
      case lock: LockTimeScriptPubKey =>
        val nested = lock.nestedScriptPubKey
        val multiSigSPK = nested match {
          case m: MultiSignatureScriptPubKey => Future.successful(m)
          case _: P2PKScriptPubKey | _: P2PKHScriptPubKey | _: MultiSignatureScriptPubKey | _: P2SHScriptPubKey
            | _: CLTVScriptPubKey | _: CSVScriptPubKey
            | _: NonStandardScriptPubKey
            | _: EscrowTimeoutScriptPubKey | EmptyScriptPubKey => Future.fromTry(TxBuilderError.WrongSigner)
        }
        multiSigSPK.flatMap { mSPK =>
          val requiredSigs = mSPK.requiredSigs
          val sigComponent = TxSigComponent(unsignedTx, inputIndex, output, flags)
          val signatures: Future[Seq[ECDigitalSignature]] = if (signers.size < requiredSigs) {
            Future.fromTry(TxBuilderError.WrongSigner)
          } else {
            val sigs = 0.until(requiredSigs).map { i =>
              doSign(sigComponent, signers(i), hashType, isDummySignature)
            }
            Future.sequence(sigs)
          }
          val signedTxSigComp = signatures.map { sigs =>
            val multiSigScriptSig = MultiSignatureScriptSignature(sigs)
            val signedInput = TransactionInput(unsignedInput.previousOutput, multiSigScriptSig, unsignedInput.sequence)
            val signedInputs = unsignedTx.inputs.updated(inputIndex.toInt, signedInput)
            val signedTx = BaseTransaction(
              unsignedTx.version,
              signedInputs,
              unsignedTx.outputs,
              unsignedTx.lockTime)

            TxSigComponent(signedTx, inputIndex, output, flags)
          }
          signedTxSigComp
        }
      case _: P2PKScriptPubKey | _: P2PKHScriptPubKey | _: P2SHScriptPubKey
        | _: NonStandardScriptPubKey
        | _: EscrowTimeoutScriptPubKey | EmptyScriptPubKey =>
        Future.fromTry(TxBuilderError.WrongSigner)
    }
    signed
  }
}

object MultiSigSigner extends MultiSigSigner
