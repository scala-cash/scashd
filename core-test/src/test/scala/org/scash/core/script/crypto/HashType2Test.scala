package org.scash.core.script.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scalatest.{ FlatSpec, MustMatchers }
import org.scash.core.number.Int32
import org.scash.core.script.crypto.BaseHashT._
import org.scash.core.script.crypto._
import org.scash.core.script.crypto.HashType2._
import scodec.bits.ByteVector

class HashType2Test extends FlatSpec with MustMatchers {

  "HashType" must "correctly cast with all available applies" in {
    val hashAll = HashType2(0x81.toByte)
    val hashNone = HashType2(0x82.toByte)
    val hashSingle = HashType2(0x83.toByte)

    hashAll.has(SIGHASHALL) must be(true)
    hashAll must be(SIGHASHALL *> SIGHASHANYONECANPAY)
    hashAll mustNot be(SIGHASHALL *> SIGHASHFORKID)

    hashNone has (SIGHASHNONE) must be(true)
    hashNone mustNot be(SIGHASHNONE *> (SIGHASHFORKID, SIGHASHANYONECANPAY))
    hashNone.has(BaseHashT.SIGHASHNONE) must be(true)

    hashNone has (SIGHASHNONE) must be(true)
    hashSingle mustNot be(SIGHASHSINGLE *> SIGHASHFORKID)
    hashSingle has (SIGHASHSINGLE) must be(true)
  }

  it must "roundtrip succesfully" in {
    val hashInt = BCHashT(BaseHashT.SIGHASHALL)
    val b = hashInt.byte
    val h = HashType2(b.last)
    hashInt must be(h)
    b must be(ByteVector(0x41))
  }

  it must "find a hash type by its byte value" in {
    HashType2(0.toByte) must be(LegacyHashT(SIGHASHUNSUPPORTED(0.toByte)))
    HashType2(1.toByte) must be(LegacyHashT(SIGHASHALL))
    HashType2(2.toByte) must be(LegacyHashT(SIGHASHNONE))
    HashType2(3.toByte) must be(LegacyHashT(SIGHASHSINGLE))
    HashType2(0x40.toByte) has (SIGHASHFORKID) must be(true)
    HashType2(0x80.toByte) has (SIGHASHANYONECANPAY) must be(true)

  }

  it must "default to SIGHASH_ALL if the given string/byte is not known" in {
    HashType2.apply(0x124.toByte) must be(LegacyHashT(SIGHASHUNSUPPORTED(0x124.toByte)))
  }

  it must "find hashType for number 1190874345" in {
    //1190874345 & 0x80 = 0x80
    val num = Int32(1190874345)
    HashType2(num.bytes).has(SIGHASHANYONECANPAY) must be(true)
  }

  it must "determine if a given number is of hashType SIGHASH_ALL" in {
    HashType2(Int32.one.bytes) must be(LegacyHashT(SIGHASHALL))
    HashType2(Int32(5).bytes) must be(LegacyHashT(SIGHASHUNSUPPORTED(5)))

    (SIGHASHNONE *> SIGHASHFORKID) must be(BCHashT(SIGHASHNONE))
    (SIGHASHNONE *> (SIGHASHFORKID, SIGHASHANYONECANPAY)) must be(BCHAnyoneCanPayHashT(SIGHASHNONE))
    (SIGHASHALL *> SIGHASHANYONECANPAY) must be(LegacyAnyoneCanPayHashT(SIGHASHALL))
  }

  it must "find a hashtype with only an integer" in {
    HashType2(Int32(105512910).bytes) has (SIGHASHANYONECANPAY) must be(true)
  }

  /*
      it must "return the correct byte for a given hashtype" in {
        SIGHASH_ALL(HashType.sigHashAllByte).byte must be(0x01.toByte)
        HashType.sigHashNone.byte must be(0x02.toByte)
        HashType.sigHashSingle.byte must be(0x03.toByte)
        HashType.sigHashAnyoneCanPay.byte must be(0x80.toByte)
        HashType.sigHashAllAnyoneCanPay.byte must be(0x81.toByte)
        HashType.sigHashNoneAnyoneCanPay.byte must be(0x82.toByte)
        HashType.sigHashSingleAnyoneCanPay.byte must be(0x83.toByte)
      }

      it must "intercept require statements for each hashType with illegal inputs" in {
        intercept[IllegalArgumentException] {
          SIGHASH_ALL(Int32(2))
        }
      }

      it must "find each specific hashType from byte sequence of default value" in {
        //tests each hashtypes overriding fromBytes function
        HashType(HashType.sigHashAll.num.bytes) must be(HashType.sigHashAll)
        HashType(HashType.sigHashNone.num.bytes) must be(HashType.sigHashNone)
        HashType(HashType.sigHashSingle.num.bytes) must be(HashType.sigHashSingle)
        HashType(HashType.sigHashAnyoneCanPay.num.bytes) must be(HashType.sigHashAnyoneCanPay)
        HashType(HashType.sigHashAllAnyoneCanPay.num.bytes) must be(HashType.sigHashAllAnyoneCanPay)
        HashType(HashType.sigHashNoneAnyoneCanPay.num.bytes) must be(HashType.sigHashNoneAnyoneCanPay)
        HashType(HashType.sigHashSingleAnyoneCanPay.num.bytes) must be(HashType.sigHashSingleAnyoneCanPay)
      }


    */
}
