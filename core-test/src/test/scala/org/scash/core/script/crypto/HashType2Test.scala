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
    HashType2(0.toByte) must be(LegacyHashT(SIGHASHZERO))
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

  it must "return the correct byte for a given hashtype" in {
    HashType2(SIGHASHALL).byte must be(ByteVector(0x01))
    HashType2(SIGHASHNONE).byte must be(ByteVector(0x02))
    HashType2(SIGHASHSINGLE).byte must be(ByteVector(0x03))
    HashType2.SIGHASH_ANYONECANPAY.byte must be(ByteVector(0x80))
    (SIGHASHALL *> SIGHASHANYONECANPAY).byte must be(ByteVector(0x81))
    (SIGHASHNONE *> SIGHASHANYONECANPAY).byte must be(ByteVector(0x82))
    (SIGHASHSINGLE *> SIGHASHANYONECANPAY).byte must be(ByteVector(0x83))

    (SIGHASHALL *> SIGHASHFORKID).byte must be(ByteVector(0x41))
    (SIGHASHNONE *> SIGHASHFORKID).byte must be(ByteVector(0x42))
    (SIGHASHSINGLE *> SIGHASHFORKID).byte must be(ByteVector(0x43))
    HashType2.SIGHASH_FORKID.byte must be(ByteVector(0x40))
    (SIGHASHALL *> (SIGHASHANYONECANPAY, SIGHASHFORKID)).byte must be(ByteVector(0xc1))
    (SIGHASHNONE *> (SIGHASHANYONECANPAY, SIGHASHFORKID)).byte must be(ByteVector(0xc2))
    (SIGHASHSINGLE *> (SIGHASHANYONECANPAY, SIGHASHFORKID)).byte must be(ByteVector(0xc3))

  }

  it must "find each specific hashType from Bytevector of default value" in {
    HashType2(ByteVector(0x01)) must be(HashType2(SIGHASHALL))
    HashType2(ByteVector(0x02)) must be(HashType2(SIGHASHNONE))
    HashType2(ByteVector(0x03)) must be(HashType2(SIGHASHSINGLE))
    HashType2(ByteVector(0x80)) must be(HashType2.SIGHASH_ANYONECANPAY)
    HashType2(ByteVector(0x81)) must be(SIGHASHALL *> SIGHASHANYONECANPAY)
    HashType2(ByteVector(0x82)) must be(SIGHASHNONE *> SIGHASHANYONECANPAY)
    HashType2(ByteVector(0x83)) must be(SIGHASHSINGLE *> SIGHASHANYONECANPAY)

    HashType2(ByteVector(0x41)) must be(SIGHASHALL *> SIGHASHFORKID)
    HashType2(ByteVector(0x42)) must be((SIGHASHNONE *> SIGHASHFORKID))
    HashType2(ByteVector(0x43)) must be(SIGHASHSINGLE *> SIGHASHFORKID)
    HashType2(ByteVector(0x40)) must be(HashType2.SIGHASH_FORKID)
    HashType2(ByteVector(0xc1)) must be(SIGHASHALL *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
    HashType2(ByteVector(0xc2)) must be(SIGHASHNONE *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
    HashType2(ByteVector(0xc3)) must be(SIGHASHSINGLE *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
  }

  it must "find each specific hashType from Byte of default value" in {
    HashType2(0x01.toByte) must be(HashType2(SIGHASHALL))
    HashType2(0x02.toByte) must be(HashType2(SIGHASHNONE))
    HashType2(0x03.toByte) must be(HashType2(SIGHASHSINGLE))
    HashType2(0x80.toByte) must be(HashType2.SIGHASH_ANYONECANPAY)
    HashType2(0x81.toByte) must be(SIGHASHALL *> SIGHASHANYONECANPAY)
    HashType2(0x82.toByte) must be(SIGHASHNONE *> SIGHASHANYONECANPAY)
    HashType2(0x83.toByte) must be(SIGHASHSINGLE *> SIGHASHANYONECANPAY)

    HashType2(0x41.toByte) must be(SIGHASHALL *> SIGHASHFORKID)
    HashType2(0x42.toByte) must be((SIGHASHNONE *> SIGHASHFORKID))
    HashType2(0x43.toByte) must be(SIGHASHSINGLE *> SIGHASHFORKID)
    HashType2(0x40.toByte) must be(HashType2.SIGHASH_FORKID)
    HashType2(0xc1.toByte) must be(SIGHASHALL *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
    HashType2(0xc2.toByte) must be(SIGHASHNONE *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
    HashType2(0xc3.toByte) must be(SIGHASHSINGLE *> (SIGHASHANYONECANPAY, SIGHASHFORKID))
  }
}
