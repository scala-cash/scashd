package org.scash.core.script.crypto
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scalatest.{ FlatSpec, MustMatchers }
import org.scash.core.number.{ Int32, UInt32 }
import org.scash.core.script.crypto
import scodec.bits.ByteVector

class SigHashTypeTest extends FlatSpec with MustMatchers {

  "HashType" must "correctly cast with all available applies" in {
    val hashAll = SigHashType(0x81.toByte)
    val hashNone = SigHashType(0x82.toByte)
    val hashSingle = SigHashType(0x83.toByte)

    hashAll.has(BaseHashType.ALL) must be(true)
    hashAll mustNot be(SigHashType(BaseHashType.ALL, HashType.FORKID, HashType.ANYONE_CANPAY))
    hashAll must be(SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY))

    hashNone has (BaseHashType.NONE) must be(true)
    hashNone mustNot be(SigHashType(BaseHashType.NONE, HashType.FORKID, HashType.ANYONE_CANPAY))
    hashNone must be(SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY))

    hashSingle has (BaseHashType.SINGLE) must be(true)
    hashSingle mustNot be(SigHashType(BaseHashType.SINGLE, HashType.FORKID, HashType.ANYONE_CANPAY))
    hashSingle must be(SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY))
  }

  it must "roundtrip succesfully" in {
    val hashInt = SigHashType(BaseHashType.ALL)
    val b = hashInt.byte
    val h = SigHashType(b)
    hashInt must be(h)
    b must be(0x01.toByte)
  }

  it must "find a hash type by its byte value" in {
    SigHashType(0.toByte) must be(SigHashType(BaseHashType.ZERO))
    SigHashType(1.toByte) must be(SigHashType(BaseHashType.ALL))
    SigHashType(2.toByte) must be(SigHashType(BaseHashType.NONE))
    SigHashType(3.toByte) must be(SigHashType(BaseHashType.SINGLE))
    SigHashType(0x40.toByte) has (HashType.FORKID) must be(true)
    SigHashType(0x80.toByte) has (HashType.ANYONE_CANPAY) must be(true)

  }

  it must "default to SIGHASH_ALL if the given string/byte is not known" in {
    SigHashType.from4Bytes(ByteVector(0x124)) must be(SigHashType.decode(Int32(ByteVector(0x124))))
  }

  it must "find hashType for number 1190874345" in {
    //1190874345 & 0x80 = 0x80
    val num = Int32(1190874345)
    SigHashType.decode(num).has(HashType.ANYONE_CANPAY) must be(true)
  }

  it must "determine if a given number is of the correct SigHashType" in {
    SigHashType.from4Bytes(Int32.one.bytes) must be(SigHashType.decode(Int32.one))
    SigHashType.from4Bytes(Int32(5).bytes) must be(SigHashType.decode(Int32(5)))

    SigHashType(BaseHashType.NONE, HashType.FORKID) must be(SigHashType.decode(Int32(0x42.toByte)))
    SigHashType(BaseHashType.NONE, HashType.FORKID, HashType.ANYONE_CANPAY) must be(SigHashType.decode(Int32(0xc2.toByte)))
    SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY) must be(SigHashType.decode(Int32(0x81.toByte)))
  }

  it must "find a hashtype with only an integer" in {
    SigHashType.decode(Int32(105512910)) has (HashType.ANYONE_CANPAY) must be(true)
  }

  it must "return the correct byte for a given hashtype" in {
    BaseHashType.ALL.byte must be(0x01.toByte)
    BaseHashType.NONE.byte must be(0x02.toByte)
    BaseHashType.SINGLE.byte must be(0x03.toByte)
    SigHashType.ANYONECANPAY.byte must be(0x80.toByte)
    SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY).byte must be(0x81.toByte)
    SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY).byte must be(0x82.toByte)
    SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY).byte must be(0x83.toByte)

    SigHashType(BaseHashType.ALL, HashType.FORKID).byte must be(0x41.toByte)
    SigHashType(BaseHashType.NONE, HashType.FORKID).byte must be(0x42.toByte)
    SigHashType(BaseHashType.SINGLE, HashType.FORKID).byte must be(0x43.toByte)
    SigHashType.FORKID.byte must be(0x40.toByte)
    SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY, HashType.FORKID).byte must be(0xc1.toByte)
    SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY, HashType.FORKID).byte must be(0xc2.toByte)
    SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY, HashType.FORKID).byte must be(0xc3.toByte)

  }

  it must "find each specific hashType from Bytevector of default value" in {
    SigHashType.from4Bytes(ByteVector(0x01)) must be(SigHashType(BaseHashType.ALL))
    SigHashType.from4Bytes(ByteVector(0x02)) must be(SigHashType(BaseHashType.NONE))
    SigHashType.from4Bytes(ByteVector(0x03)) must be(SigHashType(BaseHashType.SINGLE))
    SigHashType.from4Bytes(ByteVector(0x80)) must be(SigHashType.ANYONECANPAY)
    SigHashType.from4Bytes(ByteVector(0x81)) must be(SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY))
    SigHashType.from4Bytes(ByteVector(0x82)) must be(SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY))
    SigHashType.from4Bytes(ByteVector(0x83)) must be(SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY))

    SigHashType.from4Bytes(ByteVector(0x41)) must be(SigHashType.bchALL)
    SigHashType.from4Bytes(ByteVector(0x42)) must be(SigHashType.bchNONE)
    SigHashType.from4Bytes(ByteVector(0x43)) must be(SigHashType.bchSINGLE)
    SigHashType.from4Bytes(ByteVector(0x40)) must be(SigHashType.FORKID)
    SigHashType.from4Bytes(ByteVector(0xc1)) must be(SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY, HashType.FORKID))
    SigHashType.from4Bytes(ByteVector(0xc2)) must be(SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY, HashType.FORKID))
    SigHashType.from4Bytes(ByteVector(0xc3)) must be(SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY, HashType.FORKID))
  }

  it must "find each specific hashType from Byte of default value" in {
    SigHashType(0x01.toByte) must be(SigHashType(BaseHashType.ALL))
    SigHashType(0x02.toByte) must be(SigHashType(BaseHashType.NONE))
    SigHashType(0x03.toByte) must be(SigHashType(BaseHashType.SINGLE))
    SigHashType(0x80.toByte) must be(SigHashType.ANYONECANPAY)
    SigHashType(0x81.toByte) must be(SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY))
    SigHashType(0x82.toByte) must be(SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY))
    SigHashType(0x83.toByte) must be(SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY))

    SigHashType(0x41.toByte) must be(SigHashType.bchALL)
    SigHashType(0x42.toByte) must be(SigHashType.bchNONE)
    SigHashType(0x43.toByte) must be(SigHashType.bchSINGLE)
    SigHashType(0x40.toByte) must be(SigHashType.FORKID)
    SigHashType(0xc1.toByte) must be(SigHashType(BaseHashType.ALL, HashType.ANYONE_CANPAY, HashType.FORKID))
    SigHashType(0xc2.toByte) must be(SigHashType(BaseHashType.NONE, HashType.ANYONE_CANPAY, HashType.FORKID))
    SigHashType(0xc3.toByte) must be(SigHashType(BaseHashType.SINGLE, HashType.ANYONE_CANPAY, HashType.FORKID))
  }
}
