package org.scash.core.script.crypto

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils.IO
import org.scash.core.crypto.{ECPrivateKey, TxSigComponent}
import org.scash.core.currency.CurrencyUnits
import org.scash.core.number.UInt32
import org.scash.core.protocol.script.ScriptSignature
import org.scash.core.protocol.transaction._
import org.scash.core.script._
import org.scash.core.script.constant._
import org.scash.core.script.flag._
import org.scash.core.script.result._
import org.scash.core.util.{BitcoinSLogger, CryptoUtil, ScriptProgramTestUtil, TestUtil}
import org.scalatest.{FlatSpec, MustMatchers}
import org.scash.core.TestHelpers
import org.scash.core.policy.Policy
import org.scash.core.script.ScriptProgram.Script
import scodec.bits.ByteVector

import scala.util.Random
import scala.util.Try

/**
 * Created by chris on 1/6/16.
 */
class CryptoInterpreterTest extends FlatSpec with MustMatchers with TestHelpers {

  private def logger = BitcoinSLogger.logger
  val stack = List(ScriptConstant("02218AD6CDC632E7AE7D04472374311CEBBBBF0AB540D2D08C3400BB844C654231".toLowerCase))
  val CI = CryptoInterpreter

    "CryptoInterpreter" must "evaluate OP_HASH160 correctly when it is on top of the script stack" in {

      val script = List(OP_HASH160)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val newProgram = CI.opHash160(program)

      newProgram.stack.head must be(ScriptConstant("5238C71458E464D9FF90299ABCA4A1D7B9CB76AB".toLowerCase))
      newProgram.script.size must be(0)
    }

    it must "mark the script as invalid when there are no arguments for OP_HASH160" in {
      val stack = List()
      val script = List(OP_HASH160)
      val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
      val executedProgram: ExecutedScriptProgram = ScriptProgramTestUtil.toExecutedScriptProgram(CI.opHash160(program))
      executedProgram.error must be(Some(ScriptErrorInvalidStackOperation))

    }

    it must "fail to evaluate all OP codes when the script stack is empty" in {
      val script = List()
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      Try(CI.opHash160(program)).isFailure must be(true)
      Try(CI.opRipeMd160(program)).isFailure must be(true)
      Try(CI.opSha256(program)).isFailure must be(true)
      Try(CI.opHash256(program)).isFailure must be(true)
      Try(CI.opSha1(program)).isFailure must be(true)
      Try(CI.opCheckSig(program)).isFailure must be(true)
      Try(CI.opCheckSigVerify(program)).isFailure must be(true)
      Try(CI.opCodeSeparator(program)).isFailure must be(true)
      Try(CI.opCheckMultiSig(program)).isFailure must be(true)
      Try(CI.opCheckMultiSigVerify(program)).isFailure must be(true)
    }

    it must "evaluate an OP_RIPEMD160 correctly" in {
      val stack = List(ScriptConstant(""))
      val script = List(OP_RIPEMD160)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val newProgram = CI.opRipeMd160(program)
      newProgram.stack must be(List(ScriptConstant("9c1185a5c5e9fc54612808977ee8f548b2258d31")))
      newProgram.script.isEmpty must be(true)
    }

    it must "evaluate a OP_SHA1 correctly" in {
      val stack = List(ScriptConstant("ab"))
      val script = List(OP_SHA1)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val newProgram = CI.opSha1(program)
      newProgram.stack.head must be(ScriptConstant("fe83f217d464f6fdfa5b2b1f87fe3a1a47371196"))
      newProgram.script.isEmpty must be(true)
    }

    it must "evaluate an OP_SHA256 correctly" in {
      val stack = List(ScriptConstant(""))
      val script = List(OP_SHA256)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val newProgram = CI.opSha256(program)
      newProgram.stack must be(List(ScriptConstant("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))
      newProgram.script.isEmpty must be(true)
    }

    it must "evaluate an OP_HASH256 correctly" in {
      val stack = List(ScriptConstant(""))
      val script = List(OP_HASH256)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val newProgram = CI.opHash256(program)
      newProgram.stack must be(List(ScriptConstant("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")))
      newProgram.script.isEmpty must be(true)
    }

    it must "evaluate an OP_CHECKMULTISIG with zero signatures and zero pubkeys" in {
      val stack = List(OP_0, OP_0, OP_0)
      val script = List(OP_CHECKMULTISIG)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
      val newProgram = CI.opCheckMultiSig(programNoFlags)
      newProgram.stack must be(List(OP_TRUE))
      newProgram.script.isEmpty must be(true)
    }

    it must "evaluate an OP_CHECKMULTISIG and leave the remaining operations on the stack" in {
      val stack = List(OP_0, OP_0, OP_0, OP_16, OP_16, OP_16)
      val script = List(OP_CHECKMULTISIG, OP_16, OP_16, OP_16, OP_16)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
      val newProgram = CI.opCheckMultiSig(programNoFlags)
      newProgram.stack must be(List(OP_TRUE, OP_16, OP_16, OP_16))
      newProgram.script must be(List(OP_16, OP_16, OP_16, OP_16))
    }

    it must "evaluate an OP_CHECKMULTISIGVERIFY with zero signatures and zero pubkeys" in {
      val stack = List(ScriptNumber.zero, ScriptNumber.zero, ScriptNumber.zero)
      val script = List(OP_CHECKMULTISIGVERIFY)
      val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
      val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
      val newProgram = CI.opCheckMultiSigVerify(programNoFlags)
      newProgram.script.isEmpty must be(true)
      newProgram.stack.isEmpty must be(true)
      newProgram.isInstanceOf[ExecutedScriptProgram] must be(false)
    }

    it must "evaluate an OP_CHECKMULTISIGVERIFY and leave the remaining operations on the stack" in {
      val stack = List(OP_0, OP_0, OP_0, OP_16, OP_16, OP_16)
      val script = List(OP_CHECKMULTISIGVERIFY, OP_16, OP_16, OP_16, OP_16)
      val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
      val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
      val newProgram = CI.opCheckMultiSigVerify(programNoFlags)
      newProgram.stack must be(List(OP_16, OP_16, OP_16))
      newProgram.script must be(List(OP_16, OP_16, OP_16, OP_16))
      newProgram.isInstanceOf[ExecutedScriptProgram] must be(false)
    }

    it must "evaluate an OP_CHECKMULTISIG for" in {
      //0 0 0 1 CHECKMULTISIG VERIFY DEPTH 0 EQUAL
      val stack = List(OP_1, OP_0, OP_0, OP_0)
      val script = List(OP_CHECKMULTISIG)
      val program = ScriptProgram(TestUtil.testProgram, stack, script)
      val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
      val newProgram = CI.opCheckMultiSig(programNoFlags)
      newProgram.stack must be(List(OP_TRUE))
      newProgram.script.isEmpty must be(true)
      newProgram.isInstanceOf[ExecutedScriptProgram] must be(false)
    }

    it must "mark a transaction invalid when the NULLDUMMY flag is set for a OP_CHECKMULTISIG operation & the scriptSig does not begin with OP_0" in {
      val flags = Seq(ScriptVerifyNullDummy)
      val scriptSig = ScriptSignature.fromAsm(Seq(OP_1))
      val input = TransactionInput(EmptyTransactionOutPoint, scriptSig, TransactionConstants.sequence)
      val empty = EmptyTransaction
      val tx = BaseTransaction(empty.version, Seq(input), empty.outputs, empty.lockTime)
      val t = TxSigComponent(
        transaction = tx,
        inputIndex = UInt32.zero,
        output = TransactionOutput(CurrencyUnits.zero, TestUtil.scriptPubKey),
        flags = flags)
      val pre = PreExecutionScriptProgram(t)
      val baseProgram = ScriptProgram.toExecutionInProgress(pre)
      val stack = Seq(OP_0, OP_0, OP_1)
      val script = Seq(OP_CHECKMULTISIG)
      val program = ScriptProgram(baseProgram, stack, script)
      val executedProgram = CI.opCheckMultiSig(program)
      val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(executedProgram)
      newProgram.error must be(Some(ScriptErrorSigNullDummy))

    }

    it must "mark a transaction invalid when the DERSIG flag is set for a OP_CHECKSIG operaetion & the signature is not a strict der sig" in {
      val flags = Seq(ScriptVerifyDerSig)
      //signature is from script_valid.json, it has a negative S value which makes it non strict der
      val stack = Seq(OP_0, ScriptConstant("302402107777777777777777777777777777777702108777777777777777777777777777777701"))
      val script = Seq(OP_CHECKSIG)
      val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script)
      val programWithFlags = ScriptProgram(program, flags)
      val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(CI.opCheckSig(programWithFlags))
      newProgram.error must be(Some(ScriptErrorSigDer))

    }

    it must "evaluate an OP_CODESEPARATOR" in {
      val stack = List()
      val script = Seq(OP_CODESEPARATOR)
      val program = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress, stack, script), script, ScriptProgram.OriginalScript)
      val newProgram = ScriptProgramTestUtil.toExecutionInProgressScriptProgram(CI.opCodeSeparator(program))
      newProgram.lastCodeSeparator must be(Some(0))
    }

  it must "evaluate all invalid stack operation in OP_CHECKDATASIG and OP_CHECKDATASIGVERIFY" in {
    val f = checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _) _
    val fv = checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _) _
    val msg = ScriptConstant(ByteVector.empty)
    val hash = CryptoUtil.sha256(msg.bytes)
    List(f, fv).map { ff =>
      ff(List.empty, ScriptErrorInvalidStackOperation)
      ff(List(ScriptNumber(0x00)), ScriptErrorInvalidStackOperation)
      ff(List(ScriptNumber(0x00), ScriptNumber(0x00)), ScriptErrorInvalidStackOperation)
    }
  }

  it must "pass 100 CheckDataSig tests" in {
    val dSigPass = checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _) _
    val dSigVPass = checkPass(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _) _

    List.fill(100){
      ByteVector.encodeAscii((0 to Random.nextInt(500)).map(_ => Random.nextPrintableChar()).mkString)
        .getOrElse(ByteVector.empty)
    }.map { msg =>
      val stack = genStack(ScriptConstant(msg))
      dSigPass(stack, Some(OP_TRUE), List(ScriptEnableCheckDataSig))
      dSigVPass(stack, None, List(ScriptEnableCheckDataSig))
    }
  }

  it must "fail if the ScriptEnableDataSigFlag is not passed" in {
    val flags = Policy.standardFlags.filterNot(_ == ScriptEnableCheckDataSig)
    val dSigError = checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, flags) _
    val dSigVError = checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, flags) _
    List.fill(10)(genStack()).foreach { stack =>
      dSigVError(stack, ScriptErrorBadOpCode)
      dSigError(stack, ScriptErrorBadOpCode)
    }
  }


  it must "check for various pubkey encodings in OP_CHECKDATASIG" in {
    val privKeyC = ECPrivateKey.fromBytes(ByteVector.fill(31)(0x00) :+ 0x01, true)
    val dSigPass = checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _) _
    val dSigVPass = checkPass(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _) _
    val msg = ScriptConstant(ByteVector.empty)
    val stack = genStack(msg)
    val stackC = genStack(msg, privKeyC)

    dSigPass(stack, Some(OP_TRUE), List(ScriptEnableCheckDataSig))
    dSigPass(stackC, Some(OP_TRUE), List(ScriptEnableCheckDataSig))
    dSigVPass(stack, None, List(ScriptEnableCheckDataSig))
    dSigVPass(stackC, None, List(ScriptEnableCheckDataSig))
  }

  it must "check for StrictEnc in OP_CHECKDATASIG" in {
    val privKey = ECPrivateKey.fromBytes(ByteVector.fill(31)(0x00) :+ 0x01, false)
    val pubKey = privKey.publicKey
    val msg = ScriptConstant(ByteVector.empty)
    val pubKeyH = ScriptConstant((0x06 | (pubKey.bytes.last & 1)).toByte +: pubKey.bytes.tail)
    val sig = ScriptConstant(privKey.sign(CryptoUtil.sha256(msg.bytes)).bytes)

    val dataSig = List(ScriptEnableCheckDataSig)
    val strictEnc = List(ScriptEnableCheckDataSig, ScriptVerifyStrictEnc)

    val strictEncStack = List(pubKeyH, msg, sig)
    checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, strictEnc)(strictEncStack, ScriptErrorPubKeyType)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, strictEnc)(strictEncStack, ScriptErrorPubKeyType)
    checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _)(strictEncStack, Some(OP_TRUE), dataSig)
    checkPass(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _)(strictEncStack, None, dataSig)
  }

  it must "check for NullFail in OP_CHECKDATASIG" in {
    val privKey = ECPrivateKey.fromBytes(ByteVector.fill(31)(0x00) :+ 0x01, false)
    val pubKey = ScriptConstant(privKey.publicKey.bytes)
    val msg = ScriptConstant(ByteVector.empty)
    val sig = ScriptConstant(privKey.sign(CryptoUtil.sha256(msg.bytes)).bytes)
    val minimalSig = ScriptConstant(ByteVector(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))
    val dataSig = List(ScriptEnableCheckDataSig)
    val nullFail = List(ScriptEnableCheckDataSig, ScriptVerifyNullFail)
    val nullFailStack = List(pubKey, msg, minimalSig)
    val validSigStack = List(pubKey, ScriptConstant(ByteVector(0x01)), sig)
    // Invalid message cause checkdatasig to fail
    checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, nullFail)(nullFailStack, ScriptErrorSigNullFail)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, nullFail)(nullFailStack, ScriptErrorSigNullFail)
    checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, nullFail)(validSigStack, ScriptErrorSigNullFail)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, nullFail)(validSigStack, ScriptErrorSigNullFail)

    // When nullfail is not enforced, invalid signature are just false.
    checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _)(nullFailStack, Some(OP_FALSE), dataSig)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, dataSig)(nullFailStack, ScriptErrorCheckDataSigVerify)

    // Invalid message cause checkdatasig to fail.
    checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _)(validSigStack, Some(OP_FALSE), dataSig)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, dataSig)(validSigStack, ScriptErrorCheckDataSigVerify)
  }

  it must "check for LOW_S in OP_CHECKDATASIG" in {
    val privKey = ECPrivateKey.fromBytes(ByteVector.fill(31)(0x00) :+ 0x01, false)
    val pubKey = ScriptConstant(privKey.publicKey.bytes)
    val msg = ScriptConstant(ByteVector.empty)
    val highSig = ByteVector.fromValidHex("0x304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef0")
    val dataSig = List(ScriptEnableCheckDataSig)
    val lowS = List(ScriptEnableCheckDataSig, ScriptVerifyLowS)
    val highSigStack = List(pubKey, msg, ScriptConstant(highSig))

    // If we do enforce low S, then high S sigs are rejected.
    checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, lowS)(highSigStack, ScriptErrorSigHighS)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, lowS)(highSigStack, ScriptErrorSigHighS)

    // If we do not enforce low S, then high S sigs are accepted.
    checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _)(highSigStack, Some(OP_FALSE), dataSig)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, dataSig)(highSigStack, ScriptErrorCheckDataSigVerify)
  }

  it must "check for DER SIG in OP_CHECKDATASIG" in {
    val privKey = ECPrivateKey.fromBytes(ByteVector.fill(31)(0x00) :+ 0x01, false)
    val pubKey = ScriptConstant(privKey.publicKey.bytes)
    val msg = ScriptConstant(ByteVector.empty)

    val nonDERSig = ScriptConstant(ByteVector(0x30, 0x80, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))

    val dataSig = List(ScriptEnableCheckDataSig)
    val strictEnc = List(ScriptEnableCheckDataSig, ScriptVerifyStrictEnc)
    val lowS = List(ScriptEnableCheckDataSig, ScriptVerifyLowS)
    val derSig = List(ScriptEnableCheckDataSig, ScriptVerifyDerSig)

    val nonderSigStack = List(pubKey, msg, nonDERSig)

    // If we do enforce low S, then high S sigs are rejected.
    List(strictEnc, lowS, derSig).map { flags =>
      checkOpError(OP_CHECKDATASIG, CI.opCheckDataSig _, flags)(nonderSigStack, ScriptErrorSigDer)
      checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, flags)(nonderSigStack, ScriptErrorSigDer)
    }
    // If we do not enforce low S, then high S sigs are accepted.
    checkPass(OP_CHECKDATASIG, CI.opCheckDataSig _)(nonderSigStack, Some(OP_FALSE), dataSig)
    checkOpError(OP_CHECKDATASIGVERIFY, CI.opCheckDataSigVerify _, dataSig)(nonderSigStack, ScriptErrorCheckDataSigVerify)
  }

  def genStack(
    msg: ScriptConstant = ScriptConstant(ByteVector.empty),
    privKey: ECPrivateKey = ECPrivateKey()
  ) = {
    val pubKey = privKey.publicKey
    List(ScriptConstant(pubKey.bytes), msg, ScriptConstant(privKey.sign(CryptoUtil.sha256(msg.bytes)).bytes))
  }
}
