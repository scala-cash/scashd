package org.scash.core.util

import org.scash.core.util.testprotocol._
import org.scalatest.{ FlatSpec, MustMatchers }
import scodec.bits.ByteVector
import spray.json._

import scala.io.Source

/**
 * Created by tom on 5/17/16.
 */
class Base58Test extends FlatSpec with MustMatchers {
  "Base58" must "encode byte value of 0 to character of 1" in {
    ByteVector.fromByte(0.toByte).toBase58 must be("1")
  }

  it must "encode byte value of 22 to character P" in {
    ByteVector.fromByte(22.toByte).toBase58 must be("P")
  }

  it must "decode base58 character '1' to byte value of 0 then encode back to base58 char '1'" in {
    val char = "1"
    val decoded = Base58.fromValidBase58(char)
    decoded.toBase58 must be(char)
  }

  it must "decode character Z to byte value of 32" in {
    Base58.fromValidBase58("Z").head must be(32.toByte)
  }

  it must "decode and return same result as bitcoinj" in {
    val address = "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    val bitcoinj = org.bitcoinj.core.Base58.decode(address)
    Base58.fromValidBase58(address).toArray must be(bitcoinj)
  }

  it must "encode tests in base58_encode_decode.json" in {
    Base58.fromValidHex("") must be("")
    Base58.fromValidHex("61") must be("2g")
    Base58.fromValidHex("626262") must be("a3gV")
    Base58.fromValidHex("636363") must be("aPEr")
    Base58.fromValidHex("73696d706c792061206c6f6e6720737472696e67") must be("2cFupjhnEsSn59qHXstmK2ffpLv2")
    Base58.fromValidHex("00eb15231dfceb60925886b67d065299925915aeb172c06647") must be("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L")
    Base58.fromValidHex("516b6fcd0f") must be("ABnLTmg")
    Base58.fromValidHex("bf4f89001e670274dd") must be("3SEo3LWLoPntC")
    Base58.fromValidHex("572e4794") must be("3EFU7m")
    Base58.fromValidHex("ecac89cad93923c02321") must be("EJDM8drfXA6uyA")
    Base58.fromValidHex("10c8511e") must be("Rt5zm")
    Base58.fromValidHex("00000000000000000000") must be("1111111111")
  }

  it must "decode tests in base58_encode_decode.json" in {
    def decodedBase58EncodeToHex(value: String): String = BitcoinSUtil.encodeHex(Base58.fromValidBase58(value))
    decodedBase58EncodeToHex("2g") must be("61")
    decodedBase58EncodeToHex("a3gV") must be("626262")
    decodedBase58EncodeToHex("aPEr") must be("636363")
    decodedBase58EncodeToHex("2cFupjhnEsSn59qHXstmK2ffpLv2") must be("73696d706c792061206c6f6e6720737472696e67")
    decodedBase58EncodeToHex("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L") must be("00eb15231dfceb60925886b67d065299925915aeb172c06647")
    decodedBase58EncodeToHex("ABnLTmg") must be("516b6fcd0f")
    decodedBase58EncodeToHex("3SEo3LWLoPntC") must be("bf4f89001e670274dd")
    decodedBase58EncodeToHex("3EFU7m") must be("572e4794")
    decodedBase58EncodeToHex("EJDM8drfXA6uyA") must be("ecac89cad93923c02321")
    decodedBase58EncodeToHex("Rt5zm") must be("10c8511e")
    decodedBase58EncodeToHex("1111111111") must be("00000000000000000000")
  }

  it must "decode address into bytes, then encode bytes back to address the same as bitcoinj" in {
    //1C4kYhyLftmkn48YarSoLupxHfYFo8kp64
    val address = TestUtil.bitcoinAddress.get.value
    val bitcoinj = org.bitcoinj.core.Base58.encode(org.bitcoinj.core.Base58.decode(address))
    Base58.fromValidHex(Base58.fromValidBase58(address).toHex) must be(bitcoinj)
    Base58.fromValidHex(Base58.fromValidBase58(address).toHex) must be("1C4kYhyLftmkn48YarSoLupxHfYFo8kp64")
  }

  it must "decode multisig address into bytes then encode back to multisig" in {
    val multi = TestUtil.multiSigAddress.get.value
    val bitcoinj = org.bitcoinj.core.Base58.encode(org.bitcoinj.core.Base58.decode(multi))
    Base58.fromValidBase58(multi).toBase58 must be(TestUtil.multiSigAddress.get.value)
    Base58.fromValidBase58(multi).toBase58 must be(bitcoinj)
  }

  it must "read base58_keys_valid.json and validate each case" in {
    import org.scash.core.util.testprotocol.Base58ValidTestCaseProtocol._
    val source = Source.fromURL(this.getClass.getResource("/base58_keys_valid.json"))
    val lines = try source.getLines.filterNot(_.isEmpty).map(_.trim) mkString "\n" finally source.close()
    val json = lines.parseJson
    val testCases: Seq[Base58ValidTestCase] = json.convertTo[Seq[Base58ValidTestCase]]
    for {
      testCase <- testCases
    } yield {
      //if testCase is an Address, it must have a valid base58 representation
      if (testCase.addressOrWIFPrivKey.isLeft) {
        Base58.isValidBitcoinBase58(testCase.addressOrWIFPrivKey.left.get.value) must be(true)
      } else {
        Base58.isValidBitcoinBase58(testCase.addressOrWIFPrivKey.right.get) must be(true)
      }
    }
  }

  it must "read base58_keys_invalid.json and return each as an invalid base58 string" in {
    import org.scash.core.util.testprotocol.Base58InvalidTestCase
    import org.scash.core.util.testprotocol.Base58InvalidTestCaseProtocol._

    val source = Source.fromURL(this.getClass.getResource("/base58_keys_invalid.json"))
    val lines = try source.getLines.filterNot(_.isEmpty).map(_.trim) mkString "\n" finally source.close()
    val json = lines.parseJson
    val testCases = json.convertTo[Seq[Base58InvalidTestCase]]
    testCases.map { testCase =>
      testCase must be(Base58InvalidTestCaseImpl(testCase.base58EncodedString))
      Base58.isValidBitcoinBase58(testCase.base58EncodedString) must be(false)
    }
  }

}
