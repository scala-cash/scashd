package org.scash.core.protocol.script

import org.scash.core.crypto._
import org.scash.core.currency.CurrencyUnits
import org.scash.core.number.Int32
import org.scash.core.policy.Policy
import org.scash.core.protocol.script.testprotocol.{ LegacySignatureHashTestCase, SignatureHashTestCase }
import org.scash.core.protocol.transaction.{ Transaction, TransactionOutput }
import org.scash.core.script.crypto.{ HashType, SIGHASH_ALL }
import org.scash.core.serializers.script.RawScriptSignatureParser
import org.scash.core.util.{ BitcoinSLogger, BitcoinSUtil, TestUtil }
import org.scash.core.script.flag.{ ScriptEnableReplayProtection, ScriptEnableSigHashForkId }
import org.scalatest.{ FlatSpec, MustMatchers }
import scodec.bits.ByteVector
import spray.json._

import scala.io.Source

/**
 * Created by chris on 2/17/16.
 */
class ScriptSignatureTest extends FlatSpec with MustMatchers {
  private val logger = BitcoinSLogger.logger

  "ScriptSignature" must "find the digital signature for the transaction inside of a p2pkh script signature" in {
    val scriptSig = ScriptSignature(TestUtil.rawScriptSig)
    scriptSig.signatures.head.hex must be("3045022100ad8e961fe3c22b2647d92b078f4c0cf81b3106ea5bf8b900ab8646aa4430216f022071d4edc2b5588be20ac4c2d07edd8ed069e10b2402d3dce2d3b835ccd075f28301")
  }

  it must "derive the signature hash type from the signature" in {
    HashType(ByteVector.fromByte(TestUtil.scriptSig.signatures.head.bytes.last)) must be(HashType.sigHashAll)
  }

  it must "find the digital signature for a p2sh script signature" in {
    val scriptSig = TestUtil.p2shInputScript
    scriptSig.signatures.head.hex must be("304402207df6dd8dad22d49c3c83d8031733c32a53719278eb7985d3b35b375d776f84f102207054f9209a1e87d55feafc90aa04c33008e5bae9191da22aeaa16efde96f41f001")
  }

  it must "find the digital signatures for a p2sh script signature for a 2/3 p2sh address" in {
    val scriptSig = TestUtil.p2shInputScript2Of2
    scriptSig.signatures must be(Seq(
      ECDigitalSignature("304402207d764cb90c9fd84b74d33a47cf3a0ffead9ded98333776becd6acd32c4426dac02203905a0d064e7f53d07793e86136571b6e4f700c1cfb888174e84d78638335b8101"),
      ECDigitalSignature("3045022100906aaca39f022acd8b7a38fd2f92aca9e9f35cfeaee69a6f13e1d083ae18222602204c9ed96fc6c4de56fd85c679fc59c16ee1ccc80c42563b86174e1a506fc007c801")))
  }

  it must "find all the digital signatures for a p2sh script signature with a large amount of sigs" in {
    val scriptSig = TestUtil.p2shInputScriptLargeSignature

    scriptSig.signatures must be(Seq(
      ECDigitalSignature("3045022100a077d4fe9a81411ecb796c254d8b4e0bc73ff86a42288bc3b3ecfa1ef26c00dd02202389bf96cf38c14c3a6ccb8c688339f3fd880b724322862547a8ee3b547a9df901"),
      ECDigitalSignature("304402207c0692464998e7f3869f8501cdd25bbcd9d32b6fd34ae8aeae643b422a8dfd42022057eb16f8ca1f34e88babc9f8beb4c2521eb5c4dea41f8902a70d045f1c132a4401"),
      ECDigitalSignature("3044022024233923253c73569f4b34723a5495698bc124b099c5542a5997d13fba7d18a802203c317bddc070276c6f6c79cb3415413e608af30e4759e31b0d53eab3ca0acd4e01"),
      ECDigitalSignature("30450221009b9f0d8b945717d2fca3685093d547a3928d122b8894903ed51e2248303213bc022008b376422c9f2cd713b9d10b5b106d1c56c5893dcc01ae300253ed2234bdb63f01"),
      ECDigitalSignature("30440220257b57cb09386d82c4328461f8fe200c2f381d6b635e2a2f4ea40c8d945e9ec102201ec67d58d51a309af4d8896e9147a42944e9f9833a456f733ea5fa6954ed2fed01")))
  }
  it must "find the hash type for a p2sh script signature" in {
    HashType(ByteVector.fromByte(TestUtil.p2shInputScript2Of2.signatures.head.bytes.last)) must be(HashType.sigHashAll)
  }

  it must "find the digital signature and hash type for a SIGHASH_SINGLE" in {
    TestUtil.p2shInputScriptSigHashSingle.signatures.head.hex must be("3045022100dfcfafcea73d83e1c54d444a19fb30d17317f922c19e2ff92dcda65ad09cba24022001e7a805c5672c49b222c5f2f1e67bb01f87215fb69df184e7c16f66c1f87c2903")
    HashType(TestUtil.p2shInputScriptSigHashSingle.signatures.head.bytes.last) must be(HashType.sigHashSingle)
  }

  it must "find the hash type for the weird occurrence of hash type being 0 on the blockchain" in {
    //from this tx https://btc.blockr.io/api/v1/tx/raw/c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73
    val hex = "8c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5"
    val scriptSig: ScriptSignature = RawScriptSignatureParser.read(hex)
    HashType(scriptSig.signatures.head.bytes.last) must be(SIGHASH_ALL(Int32.zero))
  }

  it must "have an empty script signature" in {
    EmptyScriptSignature.hex must be("00")
    EmptyScriptSignature.bytes must be(ByteVector.low(1))
    EmptyScriptSignature.asm must be(Nil)
    EmptyScriptSignature.signatures must be(Nil)
  }

  it must "create a p2pkh scriptSig" in {
    val scriptSig = ScriptSignature(TestUtil.p2pkhScriptSig.hex)
    scriptSig.isInstanceOf[P2PKHScriptSignature] must be(true)
    scriptSig.hex must be(TestUtil.p2pkhScriptSig.hex)
  }

  it must "create a p2sh scriptSig" in {
    val scriptSig = ScriptSignature(TestUtil.p2sh2Of3ScriptSig.hex)
    scriptSig.isInstanceOf[P2SHScriptSignature] must be(true)
    scriptSig.hex must be(TestUtil.p2sh2Of3ScriptSig.hex)
  }

  it must "create a p2pk scriptSig" in {
    val scriptSig = ScriptSignature(TestUtil.p2pkScriptSig.hex)
    scriptSig.isInstanceOf[P2PKScriptSignature] must be(true)
    scriptSig.hex must be(TestUtil.p2pkScriptSig.hex)
  }

  it must "read sighash.json and return result for all types of sigs" in {
    import org.scash.core.protocol.script.testprotocol.HashTestCaseProtocol._
    //"raw_transaction,
    // script,
    // input_index,
    // hashType,
    // signature_hash (regular) bip143,
    // signature_hash old(no forkid),
    // signature_hash(replay protected)"

    val source = Source.fromURL(this.getClass.getResource("/sighash.json"))
    val lines = try source.getLines.filterNot(_.isEmpty).map(_.trim).mkString("\n") finally source.close()
    val testCases = lines.parseJson.convertTo[Seq[SignatureHashTestCase]]

    for {
      testCaseI <- testCases.zipWithIndex
    } yield {
      val (test, _) = testCaseI

      Transaction(test.transaction.hex) must be(test.transaction)

      val output = TransactionOutput(CurrencyUnits.zero, test.script)

      val regTx = TxSigComponent(
        test.transaction,
        test.inputIndex,
        output,
        List(ScriptEnableSigHashForkId))

      val oldTx = TxSigComponent(
        test.transaction,
        test.inputIndex,
        output,
        (Policy.standardFlags.toSet - ScriptEnableSigHashForkId).toList)

      val repTx = TxSigComponent(
        test.transaction,
        test.inputIndex,
        output,
        List(ScriptEnableReplayProtection, ScriptEnableSigHashForkId))

      Vector(regTx, oldTx, repTx)
        .map(TransactionSignatureSerializer.hashForSignature(_, test.hashType))
        .zip(List(test.regularSigHash.hex, test.noForkKidSigHash.hex, test.replayProtectedSigHash.hex)
          .map(BitcoinSUtil.flipEndianness))
        .map { case (sig, test) => sig must be(DoubleSha256Digest(test)) }
    }
  }

  it must "read sighash_bip143.json and return result" in {
    import org.scash.core.protocol.script.testprotocol.HashTestCaseProtocol._
    //"raw_transaction,
    // script,
    // input_index,
    // hashType,
    // signature_ bip143

    val source = Source.fromURL(this.getClass.getResource("/sighash_bip143.json"))
    val lines = try source.getLines.filterNot(_.isEmpty).map(_.trim).mkString("\n") finally source.close()
    val testCases = lines.parseJson.convertTo[Seq[LegacySignatureHashTestCase]]

    for {
      testCaseI <- testCases.zipWithIndex
    } yield {
      val (testCase, _) = testCaseI

      Transaction(testCase.transaction.hex) must be(testCase.transaction)

      val output = TransactionOutput(CurrencyUnits.zero, testCase.script)

      val regTx = TxSigComponent(
        testCase.transaction,
        testCase.inputIndex,
        output,
        List(ScriptEnableSigHashForkId))

      val test = TransactionSignatureSerializer.hashForSignature(regTx, testCase.hashType)

      test must be(DoubleSha256Digest(BitcoinSUtil.flipEndianness(testCase.regularSigHash.hex)))

    }
  }
}
