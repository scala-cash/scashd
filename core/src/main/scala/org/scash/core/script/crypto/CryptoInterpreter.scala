package org.scash.core.script.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018-2019 The SCash Developers (MIT License)
 *   https://github.com/scala-cash/scash
 */
import org.scash.core.consensus.Consensus
import org.scash.core.crypto._
import org.scash.core.script
import org.scash.core.script.constant._
import org.scash.core.script.flag.{ScriptEnableCheckDataSig, ScriptVerifyNullDummy, ScriptVerifyNullFail}
import org.scash.core.script.result._
import org.scash.core.script._
import org.scash.core.util.{BitcoinScriptUtil, CryptoUtil}

import scalaz.{-\/, \/, \/-}
import scalaz.syntax.std.option._

import scodec.bits.ByteVector

import scala.annotation.tailrec

sealed abstract class CryptoInterpreter {

  /** The input is hashed twice: first with SHA-256 and then with RIPEMD-160. */
  def opHash160(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_HASH160), "Script operation must be OP_HASH160")
    executeHashFunction(program, CryptoUtil.sha256Hash160 _)
  }

  /** The input is hashed using RIPEMD-160. */
  def opRipeMd160(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_RIPEMD160), "Script operation must be OP_RIPEMD160")
    executeHashFunction(program, CryptoUtil.ripeMd160 _)
  }

  /** The input is hashed using SHA-256. */
  def opSha256(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_SHA256), "Script operation must be OP_SHA256")
    executeHashFunction(program, CryptoUtil.sha256 _)
  }

  /** The input is hashed two times with SHA-256. */
  def opHash256(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_HASH256), "Script operation must be OP_HASH256")
    executeHashFunction(program, CryptoUtil.doubleSHA256 _)
  }

  /** The input is hashed using SHA-1. */
  def opSha1(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_SHA1), "Script top must be OP_SHA1")
    executeHashFunction(program, CryptoUtil.sha1 _)
  }

  /**
   * The entire transaction's outputs, inputs, and script (from the most
   * recently-executed OP_CODESEPARATOR to the end) are hashed.
   * The signature used by [[OP_CHECKSIG]] must be a valid signature for this hash and public key.
   */
  def opCheckSig(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_CHECKSIG), "Script top must be OP_CHECKSIG")
    checkSig(p).leftMap(ScriptProgram(p, _)).merge
  }

  /** Runs [[OP_CHECKSIG]] with an OP_VERIFY afterwards. */
  def opCheckSigVerify(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKSIGVERIFY), "Script top must be OP_CHECKSIGVERIFY")
    checkSig(ScriptProgram(program, OP_CHECKSIG :: program.script.tail, ScriptProgram.Script))
      .flatMap(p => p.stackTopIsTrue match {
        case true => \/-(ScriptProgram(p, p.stack.tail, p.script))
        case false => -\/(ScriptErrorCheckSigVerify)
      })
      .leftMap(ScriptProgram(program, _))
      .merge
  }

  /**
    * OP_CHECKDATASIG check whether a signature is valid with respect to a message and a public key.
    * it permits data to be imported into a script, and have its validity checked against
    * some signing authority such as an "Oracle".
    * https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/op_checkdatasig.md
    */
  def opCheckDataSig(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_CHECKDATASIG), "Script top must be OP_CHECKDATASIG")
    checkDataSig(p).leftMap(ScriptProgram(p, _)).merge
  }

  /** Runs [[OP_CHECKDATASIG]] with an OP_VERIFY afterwards. */
  def opCheckDataSigVerify(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKDATASIGVERIFY), "Script top must be OP_CHECKDATASIGVERIFY")
    checkDataSig(ScriptProgram(program, OP_CHECKDATASIG :: program.script.tail, ScriptProgram.Script))
      .flatMap(p => p.stackTopIsTrue match {
        case true => \/-(ScriptProgram(p, p.stack.tail, p.script))
        case false => -\/(ScriptErrorCheckDataSigVerify)
      })
      .leftMap(ScriptProgram(program, _))
      .merge
  }

  /**
   * Compares the first signature against each public key until it finds an ECDSA match.
   * Starting with the subsequent public key, it compares the second signature against each remaining
   * public key until it finds an ECDSA match. The process is repeated until all signatures have been
   * checked or not enough public keys remain to produce a successful result.
   * All signatures need to match a public key.
   * Because public keys are not checked again if they fail any signature comparison,
   * signatures must be placed in the scriptSig using the same order as their corresponding public keys
   * were placed in the scriptPubKey or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise.
   * Due to a bug, one extra unused value is removed from the stack.
   * https://bitcoin.stackexchange.com/questions/40669/checkmultisig-a-worked-out-example
   * ([sig ...] numOfSigs [pubkey ...] numOfPubKeys -> bool)
   */
  def opCheckMultiSig(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKMULTISIG), "Script top must be OP_CHECKMULTISIG")
    multiCheckSig(program).leftMap(ScriptProgram(program, _)).merge
  }

  /** Runs [[OP_CHECKMULTISIG]] with an OP_VERIFY afterwards */
  def opCheckMultiSigVerify(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKMULTISIGVERIFY), "Script top must be OP_CHECKMULTISIGVERIFY")
    (for {
      _ <- script.checkSize(program.stack, 3)
      p <- multiCheckSig(ScriptProgram(program, OP_CHECKMULTISIG :: program.script.tail, ScriptProgram.Script))
      r <- p.stackTopIsTrue match {
        case true => \/-(ScriptProgram(p, p.stack.tail, p.script))
        case false => -\/(ScriptErrorCheckSigVerify)
      }
    } yield r)
      .leftMap(ScriptProgram(program, _))
      .merge
  }

  /**
   * All of the signature checking words will only match signatures to the data
   * after the most recently-executed [[OP_CODESEPARATOR]].
   */
  def opCodeSeparator(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_CODESEPARATOR), "Script top must be OP_CODESEPARATOR")
    p match {
      case e: PreExecutionScriptProgram => opCodeSeparator(ScriptProgram.toExecutionInProgress(e))
      case e: ExecutionInProgressScriptProgram =>
        val indexOfOpCodeSeparator = p.originalScript.size - p.script.size
        ScriptProgram(e, p.script.tail, ScriptProgram.Script, indexOfOpCodeSeparator)
      case e: ExecutedScriptProgram => ScriptProgram(e, ScriptErrorUnknownError)
    }
  }

  @tailrec
  private def multiCheckSig(program: ScriptProgram): ScriptError \/ ScriptProgram = program match {
    case p: PreExecutionScriptProgram => multiCheckSig(ScriptProgram.toExecutionInProgress(p))
    case p: ExecutedScriptProgram => \/-(p)
    case p: ExecutionInProgressScriptProgram =>
      for {
        nKeys <- script.getTop(p.stack).flatMap(ScriptNumber(p, _))
        _ <- script.failIf(nKeys < ScriptNumber.zero || nKeys.toInt > Consensus.maxPublicKeysPerMultiSig, ScriptErrorPubKeyCount)
        _ <- script.checkSize(p.stack, nKeys.toInt + 2)
        restOfStack = p.stack.tail
        stackSansPubKeys = restOfStack.slice(nKeys.toInt, restOfStack.size)
        nSigs <- script.getTop(stackSansPubKeys).flatMap(ScriptNumber(p, _))
        _ <- script.failIf(nSigs < ScriptNumber.zero || nSigs > nKeys, ScriptErrorSigCount)
        pubKeys = restOfStack.slice(0, nKeys.toInt).map(k => ECPublicKey(k.bytes))
        stackSansSigsAndPubKeys = stackSansPubKeys.tail.slice(nSigs.toInt, stackSansPubKeys.tail.size)
        sigs = restOfStack
          .slice(nKeys.toInt + 1, nKeys.toInt + nSigs.toInt + 1)
          .map(t => ECDigitalSignature(t.bytes))
        //this is because of a bug in bitcoin core for the implementation of OP_CHECKMULTISIG
        _ <- script.checkSize(stackSansSigsAndPubKeys, 1)
        notEmpty = stackSansSigsAndPubKeys.headOption.fold(false)(_.bytes.nonEmpty)
        _ <- script.checkFlag(p.flags)(ScriptVerifyNullDummy, ScriptErrorSigNullDummy, notEmpty)
        nonSepScript = BitcoinScriptUtil.removeOpCodeSeparator(p)
        r <- TxSigCheck.multiSigCheck(p.txSignatureComponent, nonSepScript, sigs, pubKeys, p.flags, nSigs.toLong)
        opBoolean = if (r) OP_TRUE else OP_FALSE
      } yield ScriptProgram(p, opBoolean :: stackSansSigsAndPubKeys.tail, p.script.tail)
  }

  @tailrec
  private def checkSig(program: ScriptProgram): ScriptError \/ ScriptProgram = program match {
    case p: PreExecutionScriptProgram => checkSig(ScriptProgram.toExecutionInProgress(p))
    case p: ExecutedScriptProgram => \/-(p)
    case p: ExecutionInProgressScriptProgram =>
      for {
        s <- script.getTwo(p.stack)
        pubKey = ECPublicKey(s._1.bytes)
        sig = ECDigitalSignature(s._2.bytes)
        _ <- SigEncoding.checkTxSigEncoding(sig, p.flags)
        _ <- SigEncoding.checkPubKeyEncoding(pubKey, p.flags)
        nonSepScript = BitcoinScriptUtil.removeOpCodeSeparator(p)
        r <- TxSigCheck.checkSig(p.txSignatureComponent, nonSepScript, pubKey, sig, p.flags)
        opBoolean = if (r) OP_TRUE else OP_FALSE
      } yield ScriptProgram(p, opBoolean :: p.stack.drop(2), p.script.tail)
  }

  @tailrec
  private def checkDataSig(program: ScriptProgram): ScriptError \/ ScriptProgram = program match {
    case p: PreExecutionScriptProgram => checkDataSig(ScriptProgram.toExecutionInProgress(p))
    case p: ExecutedScriptProgram => \/-(p)
    case p: ExecutionInProgressScriptProgram =>
      if (!p.flags.contains(ScriptEnableCheckDataSig)) -\/(ScriptErrorBadOpCode)
      else for {
        s <- getThree(p.stack)
        pubKey = ECPublicKey(s._1.bytes)
        msg = s._2
        sig = ECDigitalSignature(s._3.bytes)
        _ <- SigEncoding.checkDataSigEncoding(sig, p.flags)
        _ <- SigEncoding.checkPubKeyEncoding(pubKey, p.flags)
        success <-
          if (sig.isEmpty) \/-(OP_FALSE)
          else for {
            hash <- CryptoUtil.sha256Opt(msg.bytes).toRightDisjunction(ScriptErrorUnknownError)
            success <- \/-(pubKey.verify(hash, sig))
            _ <- checkFlag(p.flags)(ScriptVerifyNullFail, ScriptErrorSigNullFail, !success)
          } yield if (success) OP_TRUE else OP_FALSE
      } yield ScriptProgram(p, success :: p.stack.drop(3), p.script.tail)
  }
  /**
   * This is a higher order function designed to execute a hash function on the stack top of the program
   * For instance, we could pass in CryptoUtil.sha256 function as the 'hashFunction' argument, which would then
   * apply sha256 to the stack top
   * @param p the script program whose stack top needs to be hashed
   * @param hashFunction the hash function which needs to be used on the stack top (sha256,ripemd160,etc..)
   * @return
   */
  private def executeHashFunction(p: => ScriptProgram, hashFunction: ByteVector => HashDigest) = p.stack match {
    case h :: t => ScriptProgram(p, ScriptConstant(hashFunction(h.bytes).bytes) :: t, p.script.tail)
    case _ => ScriptProgram(p, ScriptErrorInvalidStackOperation)
  }
}

object CryptoInterpreter extends CryptoInterpreter
