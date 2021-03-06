package org.scash.core.util

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.consensus.Consensus
import org.scash.core.crypto.{ ECDigitalSignature, ECPublicKey, TxSigComponent }
import org.scash.core.number.UInt32
import org.scash.core.protocol.script._
import org.scash.core.script.constant._
import org.scash.core.script.crypto._
import org.scash.core.script.flag.{ ScriptFlag, ScriptFlagUtil }
import org.scash.core.script.result.{ ScriptError, ScriptErrorPubKeyType }
import org.scash.core.script.{ ExecutionInProgressScriptProgram, ScriptProgram }
import scodec.bits.ByteVector

import scala.annotation.tailrec

trait BitcoinScriptUtil extends BitcoinSLogger {

  /** Takes in a sequence of script tokens and converts them to their hexadecimal value */
  def asmToHex(asm: Seq[ScriptToken]): String = {
    val hex = asm.map(_.hex).mkString
    hex
  }

  /** Converts a sequence of script tokens to them to their byte values */
  def asmToBytes(asm: Seq[ScriptToken]): ByteVector = BitcoinSUtil.decodeHex(asmToHex(asm))

  /**
   * Filters out push operations in our sequence of script tokens
   * this removes OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 and all ByteToPushOntoStack tokens
   */
  def filterPushOps(asm: Seq[ScriptToken]): Seq[ScriptToken] =
    //TODO: This does not remove the following script number after a OP_PUSHDATA
    asm.filterNot(op =>
      op.isInstanceOf[BytesToPushOntoStack]
        || op == OP_PUSHDATA1
        || op == OP_PUSHDATA2
        || op == OP_PUSHDATA4
    )

  /**
   * Returns true if the given script token counts towards our max script operations in a script
   * See https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L269-L271
   * which is how bitcoin core handles this
   */
  def countsTowardsScriptOpLimit(token: ScriptToken): Boolean = token match {
    case scriptOp: ScriptOperation => scriptOp.opCode > OP_16.opCode
    case _                         => false
  }

  /**
   * Counts the amount of sigops in a script
   * https://github.com/bitcoin/bitcoin/blob/master/src/script/script.cpp#L156-L202
   * @param script the script whose sigops are being counted
   * @return the number of signature operations in the script
   */
  def countSigOps(script: Seq[ScriptToken]): Long = {
    val sigCount = script.count(token =>
      token == OP_CHECKSIG ||
        token == OP_CHECKSIGVERIFY ||
        token == OP_CHECKDATASIG ||
        token == OP_CHECKDATASIGVERIFY
    )

    val multiSigOps = Seq(OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY)
    val multiSigCount: Long = script.zipWithIndex.map {
      case (token, index) =>
        if (multiSigOps.contains(token) && index != 0) {
          script(index - 1) match {
            case scriptNum: ScriptNumber        => scriptNum.toLong
            case scriptConstant: ScriptConstant => ScriptNumberUtil.toLong(scriptConstant.hex)
            case _: ScriptToken                 => Consensus.maxPublicKeysPerMultiSig
          }
        } else 0
    }.sum
    sigCount + multiSigCount
  }

  /**
   * Parses the number of signatures on the stack
   * This can only be called when an OP_CHECKMULTISIG operation is about to be executed
   * on the stack
   * For instance if this was a 2/3 multisignature script, it would return the number 3
   */
  def numPossibleSignaturesOnStack(program: ScriptProgram): ScriptNumber = {
    require(
      program.script.headOption == Some(OP_CHECKMULTISIG) || program.script.headOption == Some(OP_CHECKMULTISIGVERIFY),
      "We can only parse the nubmer of signatures the stack when we are executing a OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY op"
    )
    val nPossibleSignatures: ScriptNumber = program.stack.head match {
      case s: ScriptNumber   => s
      case s: ScriptConstant => ScriptNumber(s.bytes)
      case _: ScriptToken =>
        throw new RuntimeException("n must be a script number or script constant for OP_CHECKMULTISIG")
    }
    nPossibleSignatures
  }

  /**
   * Returns the number of required signatures on the stack, for instance if this was a
   * 2/3 multisignature script, it would return the number 2
   */
  def numRequiredSignaturesOnStack(program: ScriptProgram): ScriptNumber = {
    require(
      program.script.headOption == Some(OP_CHECKMULTISIG) || program.script.headOption == Some(OP_CHECKMULTISIGVERIFY),
      "We can only parse the nubmer of signatures the stack when we are executing a OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY op"
    )
    val nPossibleSignatures = numPossibleSignaturesOnStack(program)
    val stackWithoutPubKeys = program.stack.tail.slice(nPossibleSignatures.toInt, program.stack.tail.size)
    val mRequiredSignatures: ScriptNumber = stackWithoutPubKeys.head match {
      case s: ScriptNumber   => s
      case s: ScriptConstant => ScriptNumber(s.bytes)
      case _: ScriptToken =>
        throw new RuntimeException("m must be a script number or script constant for OP_CHECKMULTISIG")
    }
    mRequiredSignatures
  }

  /**
   * Determines if a script contains only script operations
   * This is equivalent to isPushOnly in ABC the implementation
   */
  def isPushOnly(script: Seq[ScriptToken]): Boolean = {
    @tailrec
    def loop(tokens: Seq[ScriptToken]): Boolean = tokens match {
      case h :: t =>
        h match {
          case op: ScriptOperation =>
            if (op.opCode > OP_16.opCode) false
            else loop(t)
          case _ => loop(t)
        }
      case Nil => true
    }
    loop(script)
  }

  /**
   * Determines if the token being pushed onto the stack is being pushed by the SMALLEST push operation possible
   * This is equivalent to
   * [[https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L209]]
   * @param pushOp the operation that is pushing the data onto the stack
   * @param token the token that is being pushed onto the stack by the pushOp
   * @return
   */
  def isMinimalPush(pushOp: ScriptToken, token: ScriptToken): Boolean = token match {
    case scriptNumOp: ScriptNumberOperation =>
      scriptNumOp == pushOp
    case ScriptConstant.zero | ScriptConstant.negativeZero =>
      //weird case where OP_0 pushes an empty byte vector on the stack, NOT "00" or "81"
      //so we can push the constant "00" or "81" onto the stack with a BytesToPushOntoStack pushop
      pushOp == BytesToPushOntoStack(1)
    case _: ScriptToken if (token.bytes.size == 1 && ScriptNumberOperation.fromNumber(token.toLong.toInt).isDefined) =>
      //could have used the ScriptNumberOperation to push the number onto the stack
      false
    case token: ScriptToken =>
      token.bytes.size match {
        case size if (size == 0) => pushOp == OP_0
        case size if (size == 1 && token.bytes.head == OP_1NEGATE.opCode) =>
          pushOp == OP_1NEGATE
        case size if (size <= 75)    => token.bytes.size == pushOp.toLong
        case size if (size <= 255)   => pushOp == OP_PUSHDATA1
        case size if (size <= 65535) => pushOp == OP_PUSHDATA2
        case _                       =>
          //default case is true because we have to use the largest push op as possible which is OP_PUSHDATA4
          true
      }
  }

  /** Calculates the push operation for the given [[ScriptToken]] */
  def calculatePushOp(scriptToken: ScriptToken): Seq[ScriptToken] = {
    //push ops following an OP_PUSHDATA operation are interpreted as unsigned numbers
    val scriptTokenSize = UInt32(scriptToken.bytes.size)
    val bytes           = scriptTokenSize.bytes
    if (scriptToken.isInstanceOf[ScriptNumberOperation]) Nil
    else if (scriptTokenSize <= UInt32(75)) Seq(BytesToPushOntoStack(scriptToken.bytes.size))
    else if (scriptTokenSize <= UInt32(OP_PUSHDATA1.max)) {
      //we need the push op to be only 1 byte in size
      val pushConstant = ScriptConstant(BitcoinSUtil.flipEndianness(bytes.slice(bytes.length - 1, bytes.length)))
      Seq(OP_PUSHDATA1, pushConstant)
    } else if (scriptTokenSize <= UInt32(OP_PUSHDATA2.max)) {
      //we need the push op to be only 2 bytes in size
      val pushConstant = ScriptConstant(BitcoinSUtil.flipEndianness(bytes.slice(bytes.length - 2, bytes.length)))
      Seq(OP_PUSHDATA2, pushConstant)
    } else if (scriptTokenSize <= UInt32(OP_PUSHDATA4.max)) {
      val pushConstant = ScriptConstant(BitcoinSUtil.flipEndianness(bytes))
      Seq(OP_PUSHDATA4, pushConstant)
    } else throw new IllegalArgumentException("ScriptToken is to large for pushops, size: " + scriptTokenSize)
  }

  def calculatePushOp(bytes: ByteVector): Seq[ScriptToken] = calculatePushOp(ScriptConstant(bytes))

  def toMinimalEncoding(n: ByteVector): ScriptConstant =
    if (BitcoinScriptUtil.isMinimalEncoding(n)) {
      ScriptConstant(n)
    } else {
      val last = n.last

      @tailrec
      def go(i: Long): ByteVector =
        if (i == 0)
          ByteVector.empty
        else {
          val b = n(i - 1)
          if (b != 0x00) {
            if ((b & 0x80) >= 1) {
              // We found a byte with it sign bit set so we need one more byte.
              n.update(i, last).slice(0, i + 1)
            } else {
              // the sign bit is clear, we can use it.
              n.update(i - 1, (b | last).toByte).slice(0, i)
            }
          } else go(i - 1)
        }
      ScriptConstant(go(n.size - 1))
    }

  /**
   * Whenever a [[ScriptConstant]] is interpreted to a number BIP62 could enforce that number to be encoded
   * in the smallest encoding possible
   */
  def isMinimalEncoding(constant: ScriptConstant): Boolean = isMinimalEncoding(constant.bytes)

  // If the most-significant-byte - excluding the sign bit - is zero
  // then we're not minimal. Note how this test also rejects the
  // negative-zero encoding, 0x80.
  // One exception: if there's more than one byte and the most
  // significant bit of the second-most-significant-byte is set
  // it would conflict with the sign bit. An example of this case
  // is +-255, which encode to 0xff00 and 0xff80 respectively.
  // (big-endian).
  def isMinimalEncoding(bytes: ByteVector): Boolean =
    if ((bytes.nonEmpty && (bytes.last & 0x7f) == 0) && (bytes.size <= 1 || (bytes(bytes.size - 2) & 0x80) == 0)) false
    else true

  /**
   * Whenever a script constant is interpreted to a number BIP62 should enforce that number to be encoded
   * in the smallest encoding possible
   * https://github.com/bitcoin/bitcoin/blob/a6a860796a44a2805a58391a009ba22752f64e32/src/script/script.h#L220-L237
   */
  def isMinimalEncoding(hex: String): Boolean = isMinimalEncoding(BitcoinSUtil.decodeHex(hex))

  /**
   * Checks the [[ECPublicKey]] encoding according to bitcoin core's function:
   * [[https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L202]].
   */
  def checkPubKeyEncoding(key: ECPublicKey, program: ScriptProgram): Boolean = checkPubKeyEncoding(key, program.flags)

  def checkPubKeyEncoding(key: ECPublicKey, flags: Seq[ScriptFlag]): Boolean =
    if (ScriptFlagUtil.requireStrictEncoding(flags) &&
        !isCompressedOrUncompressedPubKey(key)) false
    else true

  /**
   * Returns true if the key is compressed or uncompressed, false otherwise
   * [[https://github.com/Bitcoin-ABC/bitcoin-abc/blob/058a6c027b5d4749b4fa23a0ac918e5fc04320e8/src/script/sigencoding.cpp#L217]]
   * @param key the public key that is being checked
   * @return true if the key is compressed/uncompressed otherwise false
   */
  def isCompressedOrUncompressedPubKey(key: ECPublicKey): Boolean = key.bytes.size match {
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
  def isCompressedPubKey(key: ECPublicKey): Boolean =
    (key.bytes.size == 33) && (key.bytes.head == 0x02 || key.bytes.head == 0x03)

  def minimalScriptNumberRepresentation(num: ScriptNumber): ScriptNumber = {
    val op = ScriptNumberOperation.fromNumber(num.toLong)
    if (op.isDefined) op.get else num
  }

  /**
   * Determines if the given pubkey is valid in accordance to the given [[ScriptFlag]].
   * Mimics this function inside of Bitcoin Core
   * [[https://github.com/bitcoin/bitcoin/blob/528472111b4965b1a99c4bcf08ac5ec93d87f10f/src/script/interpreter.cpp#L214-L223]]
   */
  def isValidPubKeyEncoding(pubKey: ECPublicKey, flags: Seq[ScriptFlag]): Option[ScriptError] =
    if (ScriptFlagUtil.requireStrictEncoding(flags) &&
        !BitcoinScriptUtil.isCompressedOrUncompressedPubKey(pubKey)) {
      Some(ScriptErrorPubKeyType)
    } else None

  /**
   * Prepares the script we spending to be serialized for our transaction signature serialization algorithm
   * We need to check if the scriptSignature has a redeemScript
   * In that case, we need to pass the redeemScript to the TransactionSignatureChecker
   *
   */
  def calculateScriptForChecking(
    txSignatureComponent: TxSigComponent,
    signature: ByteVector,
    script: Seq[ScriptToken]
  ): Seq[ScriptToken] = {
    val scriptForChecking = calculateScriptForSigning(txSignatureComponent, script)
    logger.debug("sig for removal: " + signature)
    logger.debug("script: " + script)
    logger.debug("scriptWithSigRemoved: " + scriptForChecking)
    removeSignatureFromScript(signature, scriptForChecking)
  }

  def calculateScriptForSigning(txSignatureComponent: TxSigComponent, script: Seq[ScriptToken]): Seq[ScriptToken] =
    txSignatureComponent.scriptPubKey match {
      case _: P2SHScriptPubKey =>
        val p2shScriptSig = P2SHScriptSignature(txSignatureComponent.scriptSignature.bytes)
        removeSignaturesFromScript(p2shScriptSig.signatures, p2shScriptSig.redeemScript.asm)
      case _: P2PKHScriptPubKey | _: P2PKScriptPubKey | _: MultiSignatureScriptPubKey | _: NonStandardScriptPubKey |
          _: CLTVScriptPubKey | _: CSVScriptPubKey | _: EscrowTimeoutScriptPubKey | EmptyScriptPubKey =>
        script
    }

  /** Removes the given [[ECDigitalSignature]] from the list of [[ScriptToken]] if it exists. */
  def removeSignatureFromScript(signature: ByteVector, script: Seq[ScriptToken]): Seq[ScriptToken] =
    if (script.contains(ScriptConstant(signature.toHex))) {
      //replicates this line in bitcoin core
      //https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L872
      val sigIndex = script.indexOf(ScriptConstant(signature.toHex))
      logger.debug("SigIndex: " + sigIndex)
      //remove sig and it's corresponding BytesToPushOntoStack
      val sigRemoved = script.slice(0, sigIndex - 1) ++ script.slice(sigIndex + 1, script.size)
      logger.debug("sigRemoved: " + sigRemoved)
      sigRemoved
    } else script

  /** Removes the list of [[ECDigitalSignature]] from the list of [[ScriptToken]] */
  def removeSignaturesFromScript(sigs: Seq[ECDigitalSignature], script: Seq[ScriptToken]): Seq[ScriptToken] = {
    @tailrec
    def loop(remainingSigs: Seq[ECDigitalSignature], scriptTokens: Seq[ScriptToken]): Seq[ScriptToken] =
      remainingSigs match {
        case Nil => scriptTokens
        case h :: t =>
          val newScriptTokens = removeSignatureFromScript(h.bytes, scriptTokens)
          loop(t, newScriptTokens)
      }
    loop(sigs, script)
  }

  /**
   * Removes the [[org.scash.core.script.crypto.OP_CODESEPARATOR]] in the original script according to
   * the last code separator index in the script.
   */
  def removeOpCodeSeparator(p: ExecutionInProgressScriptProgram): Seq[ScriptToken] = {
    logger.debug("Program before removing OP_CODESEPARATOR: " + p.originalScript)
    val r = p.lastCodeSeparator
      .map(last => p.originalScript.slice(last + 1, p.originalScript.size))
      .getOrElse(p.originalScript)
    logger.debug("Program after removing OP_CODESEPARATOR: " + r)
    r
  }

  /**
   * Casts the given script token to a boolean value
   * Mimics this function inside of Bitcoin Core
   * [[https://github.com/bitcoin/bitcoin/blob/8c1dbc5e9ddbafb77e60e8c4e6eb275a3a76ac12/src/script/interpreter.cpp#L38]]
   * All bytes in the byte vector must be zero, unless it is the last byte, which can be 0 or 0x80 (negative zero)
   */
  def castToBool(token: ScriptToken): Boolean =
    token.bytes.toArray.zipWithIndex.exists {
      case (b, index) =>
        val byteNotZero             = b.toByte != 0
        val lastByteNotNegativeZero = !(index == token.bytes.size - 1 && b.toByte == 0x80.toByte)
        byteNotZero && lastByteNotNegativeZero
    }

  /** Since witnesses are not run through the interpreter, replace OP_0/OP_1 with ScriptNumber.zero/ScriptNumber.one */
  def minimalIfOp(asm: Seq[ScriptToken]): Seq[ScriptToken] =
    if (asm == Nil) asm
    else if (asm.last == OP_0) {
      asm.dropRight(1) ++ Seq(ScriptNumber.zero)
    } else if (asm.last == OP_1) {
      asm.dropRight(1) ++ Seq(ScriptNumber.one)
    } else asm

  /** Replaces the OP_0 dummy for OP_CHECKMULTISIG with ScriptNumber.zero */
  def minimalDummy(asm: Seq[ScriptToken]): Seq[ScriptToken] =
    if (asm.headOption == Some(OP_0)) ScriptNumber.zero +: asm.tail
    else asm

  /**
   * Checks that all the [[ECPublicKey]] in this script
   * is compressed public keys, this is required for BIP143
   * @param spk
   * @return
   */
  def isOnlyCompressedPubKey(spk: ScriptPubKey): Boolean =
    spk match {
      case p2pk: P2PKScriptPubKey => p2pk.publicKey.isCompressed
      case m: MultiSignatureScriptPubKey =>
        !m.publicKeys.exists(k => !k.isCompressed)
      case l: LockTimeScriptPubKey =>
        isOnlyCompressedPubKey(l.nestedScriptPubKey)
      case e: EscrowTimeoutScriptPubKey =>
        isOnlyCompressedPubKey(e.escrow) && isOnlyCompressedPubKey(e.timeout)
      case _: P2PKHScriptPubKey | _: P2SHScriptPubKey | _: NonStandardScriptPubKey | EmptyScriptPubKey =>
        true

    }

}

object BitcoinScriptUtil extends BitcoinScriptUtil
