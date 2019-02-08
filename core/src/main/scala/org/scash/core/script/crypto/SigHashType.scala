package org.scash.core.script.crypto

import org.scash.core.crypto.ECDigitalSignature
import org.scash.core.number.UInt32
import org.scash.core.script.crypto.BaseHashType._
import org.scash.core.script.crypto.HashType.HashType
import org.scash.core.script.crypto.SigHashType.{ BCHAnyoneCanPayHashT, BCHashT, LegacyAnyoneCanPayHashT, LegacyHashT }
import org.scash.core.script.crypto.BaseHashType.ops._

import scalaz.Equal
import scalaz.syntax.equal._
import scodec.bits.ByteVector

abstract class SigHashType { self =>

  def baseType: BaseHashType

  def sighash: UInt32

  def has(h: HashType): Boolean = (h, self) match {
    case (HashType.FORKID, _: BCHAnyoneCanPayHashT | _: BCHashT) => true
    case (HashType.ANYONE_CANPAY, _: BCHAnyoneCanPayHashT | _: LegacyAnyoneCanPayHashT) => true
    case _ => false
  }

  def has(b: BaseHashType): Boolean = baseType === b

  def byte: Byte = sighash.bytes.last

  def sigAlgo: HashType = self match {
    case _: BCHashT | _: BCHAnyoneCanPayHashT => HashType.FORKID
    case _: LegacyHashT | _: LegacyAnyoneCanPayHashT => HashType.LEGACY
  }

  def anyoneCanPay: HashType = self match {
    case _: BCHAnyoneCanPayHashT | _: LegacyAnyoneCanPayHashT => HashType.ANYONE_CANPAY
    case _: BCHashT | _: LegacyHashT => HashType.LEGACY
  }

  //The encoding results on casting the Byte into a 4 byte container
  def serialize = sighash.bytes.reverse
}

object SigHashType {
  private case class LegacyHashT(baseType: BaseHashType, sighash: UInt32) extends SigHashType
  private case class LegacyAnyoneCanPayHashT(baseType: BaseHashType, sighash: UInt32) extends SigHashType
  private case class BCHashT(baseType: BaseHashType, sighash: UInt32) extends SigHashType
  private case class BCHAnyoneCanPayHashT(baseType: BaseHashType, sighash: UInt32) extends SigHashType

  private val zero = 0.toByte

  private val anyoneCanPayByte = HashType.ANYONE_CANPAY.byte
  private val forkIdByte = HashType.FORKID.byte

  val bchSINGLE = SigHashType(BaseHashType.SINGLE, HashType.FORKID)
  val bchNONE = SigHashType(BaseHashType.NONE, HashType.FORKID)
  val bchALL = SigHashType(BaseHashType.ALL, HashType.FORKID)
  val bchANYONECANPAY = SigHashType(BaseHashType.ZERO, HashType.FORKID, HashType.ANYONE_CANPAY)

  val ANYONECANPAY = SigHashType(BaseHashType.ZERO, HashType.ANYONE_CANPAY)
  val FORKID = SigHashType(BaseHashType.ZERO, HashType.FORKID)

  val bchHashTypes = List(
    //  FORKID,
    bchSINGLE,
    bchNONE,
    bchALL)
  //  ANYONECANPAY)
  // bchANYONECANPAY)
  // SigHashType(BaseHashType.SINGLE, HashType.FORKID, HashType.ANYONE_CANPAY),
  // SigHashType(BaseHashType.NONE, HashType.FORKID, HashType.ANYONE_CANPAY),
  //  SigHashType(BaseHashType.ALL, HashType.FORKID, HashType.ANYONE_CANPAY))

  def decode(b: UInt32): SigHashType = from4Bytes(b.bytes)

  def fromInt(i: Int): SigHashType = from4Bytes(ByteVector.fromInt(i))

  /*the padding ensures that when 0x80 is being passed the sign is removed*/
  def fromByte(b: Byte): SigHashType = from4Bytes(ByteVector(0, 0, 0, b))

  def from4Bytes(bvec: ByteVector): SigHashType = {
    val b = bvec.last
    val n = UInt32(bvec)
    val baseHashT = BaseHashType(b)
    val hasAnyoneCanPay = (b & anyoneCanPayByte) != zero

    if ((b & forkIdByte) != zero)
      if (hasAnyoneCanPay) BCHAnyoneCanPayHashT(baseHashT, n)
      else BCHashT(baseHashT, n)
    else if (hasAnyoneCanPay) LegacyAnyoneCanPayHashT(baseHashT, n)
    else LegacyHashT(baseHashT, n)
  }

  def apply(b: BaseHashType, h: HashType) = h match {
    case HashType.FORKID => fromByte(((b.byte & ~forkIdByte) | forkIdByte).toByte)
    case HashType.ANYONE_CANPAY => fromByte(((b.byte & ~anyoneCanPayByte) | anyoneCanPayByte).toByte)
  }

  def apply(b: BaseHashType, h1: HashType, h2: HashType): SigHashType = (h1, h2) match {
    case (HashType.FORKID, HashType.FORKID) => apply(b, HashType.FORKID)
    case (HashType.ANYONE_CANPAY, HashType.ANYONE_CANPAY) => apply(b, HashType.ANYONE_CANPAY)
    case _ => fromByte((b.byte & ~(anyoneCanPayByte | forkIdByte) | (anyoneCanPayByte | forkIdByte)).toByte)
  }

  def apply(b: BaseHashType): SigHashType = LegacyHashT(b, UInt32(b.byte))

  /**
   * Checks if the given digital signature has a valid hash type
   */

  def isDefined(sig: ECDigitalSignature): Boolean = {
    sig.bytes.lastOption.fold(false) { last =>
      val byte = last & ~(forkIdByte | anyoneCanPayByte)
      byte >= BaseHashType.ALL.byte && byte <= BaseHashType.SINGLE.byte
    }
  }

  implicit val equalBaseHash = new Equal[SigHashType] {
    override def equal(a1: SigHashType, a2: SigHashType): Boolean = a1.sighash == a2.sighash
  }
}

