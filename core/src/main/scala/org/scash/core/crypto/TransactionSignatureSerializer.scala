package org.scash.core.crypto

import org.scash.core.protocol.transaction._
import org.scash.core.script.constant.ScriptToken
import org.scash.core.script.crypto._
import org.scash.core.util.{ BitcoinSLogger, BitcoinSUtil, BitcoinScriptUtil, CryptoUtil }
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.protocol.CompactSizeUInt
import org.scash.core.protocol.script.{ NonStandardScriptSignature, ScriptSignature }
import org.scash.core.script.crypto.SigHashType
import org.scash.core.script.flag.{ ScriptEnableReplayProtection, ScriptFlagUtil }
import org.scash.core.serializers.transaction.RawTransactionOutputParser

import scalaz.{ -\/, \/- }
import scodec.bits.ByteVector

/**
 * Created by chris on 2/16/16.
 * Wrapper that serializes like Transaction, but with the modifications
 * required for the signature hash done
 * [[https://github.com/bitcoin/bitcoin/blob/93c85d458ac3e2c496c1a053e1f5925f55e29100/src/script/interpreter.cpp#L1016-L1105]]
 */
sealed abstract class TransactionSignatureSerializer {

  private val logger = BitcoinSLogger.logger

  /**
   * SIGNATURE_HASH_ERROR represents the special value of 1 that is used by the legacy SignatureHash
   * function to signal errors in calculating the signature hash. This export is ONLY meant to check for the
   * consensus-critical oddities of the legacy signature validation code and SHOULD NOT be used to signal
   * problems during signature hash calculations for any current BCH signature hash functions!
   */
  private lazy val errorHash: DoubleSha256Digest = DoubleSha256Digest(BitcoinSUtil.decodeHex("0100000000000000000000000000000000000000000000000000000000000000"))

  private lazy val forkIdXor = ByteVector.fromInt(0xdead)
  private lazy val mask = ByteVector.fromInt(0xff0000)
  private lazy val ff = ByteVector.fromInt(0xff)

  /**
   * Implements the signature serialization algorithm that Satoshi Nakamoto originally created
   * and the new signature serialization algorithm as specified by UAHF
   * [[https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md]]
   */
  def serializeLegacy(txSigComponent: TxSigComponent, hashType: SigHashType): ByteVector = {
    val spendingTransaction = txSigComponent.transaction
    val inputIndex = txSigComponent.inputIndex
    val output = txSigComponent.output
    val script = BitcoinScriptUtil.calculateScriptForSigning(txSigComponent, output.scriptPubKey.asm)
    logger.trace(s"scriptForSigning: $script")
    logger.trace("Serializing for signature")
    logger.trace("Script: " + script)
    // Clear input scripts in preparation for signing. If we're signing a fresh
    // CScript's inside the Bitcoin Core codebase retain their compactSizeUInt
    // while clearing out all of the actual asm operations in the CScript
    val inputSigsRemoved = for {
      input <- spendingTransaction.inputs
      s = input.scriptSignature
    } yield TransactionInput(input.previousOutput, NonStandardScriptSignature(s.compactSizeUInt.hex), input.sequence)

    //make sure all scriptSigs have empty asm
    inputSigsRemoved.map(input =>
      require(input.scriptSignature.asm.isEmpty, "Input asm was not empty " + input.scriptSignature.asm))

    val scriptWithOpCodeSeparatorsRemoved: Seq[ScriptToken] = removeOpCodeSeparators(script)
    val inputToSign = inputSigsRemoved(inputIndex.toInt)

    // Set the input to the script of its output. Bitcoin Core does this but the step has no obvious purpose as
    // the signature covers the hash of the prevout transaction which obviously includes the output script
    // already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
    val scriptSig = ScriptSignature.fromAsm(scriptWithOpCodeSeparatorsRemoved)
    val inputWithConnectedScript = TransactionInput(inputToSign.previousOutput, scriptSig, inputToSign.sequence)

    //update the input at index i with inputWithConnectScript
    val updatedInputs = inputSigsRemoved.zipWithIndex.map {
      case (input, idx) =>
        if (UInt32(idx) == inputIndex) inputWithConnectedScript else input
    }

    val txWithInputSigsRemoved = BaseTransaction(spendingTransaction.version, updatedInputs, spendingTransaction.outputs, spendingTransaction.lockTime)

    /**
     * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/5e02f75dc9233dacbc073a7e8e78c240de8d7de9/src/script/interpreter.cpp#L1385]]
     */
    val sigHashBytes = hashType.sighash.bytes.reverse

    val sigHashTx = hashType.baseType match {
      case BaseHashType.NONE => \/-(sigHashNone(txWithInputSigsRemoved, inputIndex))
      case BaseHashType.SINGLE =>
        if (inputIndex >= UInt32(spendingTransaction.outputs.size)) -\/(errorHash.bytes)
        else \/-(sigHashSingle(txWithInputSigsRemoved, inputIndex))
      case _ => \/-(txWithInputSigsRemoved)
    }

    sigHashTx.map(shtx =>
      (hashType.anyoneCanPay match {
        case HashType.ANYONE_CANPAY => sigHashAnyoneCanPay(shtx, inputWithConnectedScript)
        case _ => shtx
      }).bytes ++ sigHashBytes).merge
  }

  def serializeReplayProtected(txSigComponent: TxSigComponent, hashType: SigHashType): ByteVector = {
    val spendingTransaction = txSigComponent.transaction
    val inputIndex = txSigComponent.inputIndex
    val output = txSigComponent.output
    val script = BitcoinScriptUtil.calculateScriptForSigning(txSigComponent, output.scriptPubKey.asm)
    val amount = txSigComponent.amount
    val isNotAnyoneCanPay = !hashType.has(HashType.ANYONE_CANPAY)
    val isNotSigHashSingle = !hashType.has(BaseHashType.SINGLE)
    val isNotSigHashNone = !hashType.has(BaseHashType.NONE)
    val inputIndexInt = inputIndex.toInt
    val emptyHash = CryptoUtil.emptyDoubleSha256Hash

    val outPointHash: ByteVector = if (isNotAnyoneCanPay) {
      val prevOuts = spendingTransaction.inputs.map(_.previousOutput)
      val bytes: ByteVector = BitcoinSUtil.toByteVector(prevOuts)
      CryptoUtil.doubleSHA256(bytes).bytes
    } else emptyHash.bytes

    val sequenceHash: ByteVector = if (isNotAnyoneCanPay && isNotSigHashNone && isNotSigHashSingle) {
      val sequences = spendingTransaction.inputs.map(_.sequence)
      val littleEndianSeq = sequences.foldLeft(ByteVector.empty)(_ ++ _.bytes.reverse)
      CryptoUtil.doubleSHA256(littleEndianSeq).bytes
    } else emptyHash.bytes

    val outputHash: ByteVector = if (isNotSigHashSingle && isNotSigHashNone) {
      val outputs = spendingTransaction.outputs
      val bytes = BitcoinSUtil.toByteVector(outputs)
      CryptoUtil.doubleSHA256(bytes).bytes
    } else if (hashType.has(BaseHashType.SINGLE) &&
      inputIndex < UInt32(spendingTransaction.outputs.size)) {
      val output = spendingTransaction.outputs(inputIndexInt)
      val bytes = CryptoUtil.doubleSHA256(RawTransactionOutputParser.write(output)).bytes
      bytes
    } else emptyHash.bytes

    val scriptBytes = BitcoinSUtil.toByteVector(script)

    val i = spendingTransaction.inputs(inputIndexInt)
    val serializationForSig =
      spendingTransaction.version.bytes.reverse ++
        outPointHash ++
        sequenceHash ++
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        i.previousOutput.bytes ++
        CompactSizeUInt.calc(scriptBytes).bytes ++
        scriptBytes ++
        amount.bytes ++
        i.sequence.bytes.reverse ++
        // Outputs (none/one/all, depending on flags)
        outputHash ++
        spendingTransaction.lockTime.bytes.reverse ++
        hashType.serialize
    logger.debug("Serialization for signature: " + BitcoinSUtil.encodeHex(serializationForSig))
    serializationForSig
  }

  /**
   * Hashes a [[TxSigComponent]] to give the value that needs to be signed by a [[Sign]] to
   * produce a valid [[ECDigitalSignature]] for a transaction
   */
  def hashForSignature(txSigComponent: TxSigComponent, hashType: SigHashType): DoubleSha256Digest = {
    val spendingTransaction = txSigComponent.transaction
    val inputIndex = txSigComponent.inputIndex
    if (inputIndex >= UInt32(spendingTransaction.inputs.size)) {
      logger.warn("Our inputIndex is out of the range of the inputs in the spending transaction")
      errorHash
    } else if (hashType.has(BaseHashType.SINGLE) && inputIndex >= UInt32(spendingTransaction.outputs.size)) {
      logger.warn("When we have a SIGHASH_SINGLE we cannot have more inputs than outputs")
      errorHash
    } else {
      val sigHash = txSigComponent.flags
        .find(_ == ScriptEnableReplayProtection)
        .fold(hashType) { _ =>
          val newForkValue = (mask | ((hashType.sighash.bytes >>> 8) ^ forkIdXor))
          val newFork = SigHashType.from4Bytes(((newForkValue << 8) | (hashType.sighash.bytes) & ff))
          logger.trace(s"new fork value: $newFork")
          newFork
        }

      val ssTxSig =
        if (sigHash.has(HashType.FORKID) &&
          ScriptFlagUtil.sighashForkIdEnabled(txSigComponent.flags)) serializeReplayProtected(txSigComponent, sigHash)
        else serializeLegacy(txSigComponent, sigHash)

      CryptoUtil.doubleSHA256(ssTxSig)
    }
  }

  /** Sets the input's sequence number to zero EXCEPT for the input at inputIndex. */
  private def setSequenceNumbersZero(inputs: Seq[TransactionInput], inputIndex: UInt32): Seq[TransactionInput] =
    inputs.zipWithIndex.map {
      case (input, idx) =>
        if (UInt32(idx) == inputIndex)
          input
        else
          TransactionInput(input.previousOutput, input.scriptSignature, UInt32.zero)
    }

  /** Executes the [[BaseHashType.NONE]] procedure on a spending transaction for the input specified by inputIndex. */
  private def sigHashNone(spendingTransaction: Transaction, inputIndex: UInt32): Transaction = {
    //means that no outputs are signed at all
    //set the sequence number of all inputs to 0 EXCEPT the input at inputIndex
    val updatedInputs = setSequenceNumbersZero(spendingTransaction.inputs, inputIndex)
    BaseTransaction(spendingTransaction.version, updatedInputs, Nil, spendingTransaction.lockTime)
  }

  /** Executes the [[BaseHashType.SINGLE]] procedure on a spending transaction for the input specified by inputIndex */
  private def sigHashSingle(spendingTransaction: Transaction, inputIndex: UInt32): Transaction = {
    // In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
    // that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
    val updatedOutputs = spendingTransaction.outputs
      .zipWithIndex
      .map {
        case (output, idx) =>
          if (UInt32(idx) < inputIndex)
            Some(EmptyTransactionOutput)
          else if (UInt32(idx) == inputIndex)
            Some(output)
          else
            None
      }
      .flatten

    //create blank inputs with sequence numbers set to zero EXCEPT the input at the inputIndex
    val updatedInputs = setSequenceNumbersZero(spendingTransaction.inputs, inputIndex)
    BaseTransaction(spendingTransaction.version, updatedInputs, updatedOutputs, spendingTransaction.lockTime)
  }

  /** Executes the [[HashType.ANYONE_CANPAY]] procedure on a spending transaction at inputIndex. */
  private def sigHashAnyoneCanPay(spendingTransaction: Transaction, input: TransactionInput): Transaction =
    BaseTransaction(spendingTransaction.version, Seq(input), spendingTransaction.outputs, spendingTransaction.lockTime)

  /** Removes [[OP_CODESEPARATOR]] operations then returns the script. */
  def removeOpCodeSeparators(script: Seq[ScriptToken]): Seq[ScriptToken] = {
    if (script.contains(OP_CODESEPARATOR)) {
      script.filterNot(_ == OP_CODESEPARATOR)
    } else script
  }
}

object TransactionSignatureSerializer extends TransactionSignatureSerializer
