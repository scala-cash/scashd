package org.scash.core.script.crypto

import org.scash.core.crypto.ECDigitalSignature
import org.scash.core.number.Int32
import org.scash.core.script.crypto.BaseHashType.BaseHashType
import org.scash.core.script.crypto.HashType.HashType
import org.scash.core.script.crypto.SigHashType.{ BCHAnyoneCanPayHashT, BCHashT, LegacyAnyoneCanPayHashT, LegacyHashT }
import scalaz.Equal
import scalaz.syntax.equal._
import scodec.bits.ByteVector

abstract class SigHashType { self =>

  def baseType: BaseHashType

  def sighash: Int32

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
  private case class LegacyHashT(baseType: BaseHashType, sighash: Int32) extends SigHashType
  private case class LegacyAnyoneCanPayHashT(baseType: BaseHashType, sighash: Int32) extends SigHashType
  private case class BCHashT(baseType: BaseHashType, sighash: Int32) extends SigHashType
  private case class BCHAnyoneCanPayHashT(baseType: BaseHashType, sighash: Int32) extends SigHashType

  private val zero = 0.toByte

  val bchSINGLE = SigHashType(BaseHashType.SINGLE, HashType.FORKID)
  val bchNONE = SigHashType(BaseHashType.NONE, HashType.FORKID)
  val bchALL = SigHashType(BaseHashType.ALL, HashType.FORKID)
  val bchANYONECANPAY = SigHashType(BaseHashType.ZERO, HashType.FORKID, HashType.ANYONE_CANPAY)

  val ANYONECANPAY = SigHashType(BaseHashType.ZERO, HashType.ANYONE_CANPAY)
  val FORKID = SigHashType(BaseHashType.ZERO, HashType.FORKID)

  val bchHashTypes = List(
    FORKID,
    bchSINGLE,
    bchNONE,
    bchALL,
    bchANYONECANPAY,
    SigHashType(BaseHashType.SINGLE, HashType.FORKID, HashType.ANYONE_CANPAY),
    SigHashType(BaseHashType.NONE, HashType.FORKID, HashType.ANYONE_CANPAY),
    SigHashType(BaseHashType.ALL, HashType.FORKID, HashType.ANYONE_CANPAY))

  def decode(b: Int32): SigHashType = from4Bytes(b.bytes)

  def from4Bytes(bvec: ByteVector): SigHashType = {
    val b = bvec.last
    val n = Int32(bvec)
    val baseHashT = BaseHashType(b)
    val hasAnyoneCanPay = (b & HashType.ANYONE_CANPAY.byte) != zero

    if ((b & HashType.FORKID.byte) != zero)
      if (hasAnyoneCanPay) BCHAnyoneCanPayHashT(baseHashT, n)
      else BCHashT(baseHashT, n)
    else if (hasAnyoneCanPay) LegacyAnyoneCanPayHashT(baseHashT, n)
    else LegacyHashT(baseHashT, n)
  }

  def apply(b: BaseHashType, h: HashType) = h match {
    case HashType.FORKID => BCHashT(b, Int32((b.byte & ~HashType.FORKID.byte) | HashType.FORKID.byte))
    case HashType.ANYONE_CANPAY => LegacyAnyoneCanPayHashT(b, Int32((b.byte & ~HashType.ANYONE_CANPAY.byte) | HashType.ANYONE_CANPAY.byte))
  }
  def apply(b: BaseHashType, h1: HashType, h2: HashType) = (h1, h2) match {
    case (HashType.FORKID, HashType.FORKID) => BCHashT(b, Int32((b.byte & ~HashType.FORKID.byte) | HashType.FORKID.byte))
    case (HashType.ANYONE_CANPAY, HashType.ANYONE_CANPAY) => LegacyAnyoneCanPayHashT(b, Int32((b.byte & ~HashType.ANYONE_CANPAY.byte) | HashType.ANYONE_CANPAY.byte))
    case _ => BCHAnyoneCanPayHashT(b, Int32(b.byte & ~(HashType.ANYONE_CANPAY.byte | HashType.FORKID.byte) | (HashType.ANYONE_CANPAY.byte | HashType.FORKID.byte)))
  }

  def apply(b: BaseHashType): SigHashType = LegacyHashT(b, Int32(b.byte))

  def apply(b: Byte): SigHashType = from4Bytes(ByteVector.fromByte(b))

  /**
   * Checks if the given digital signature has a valid hash type
   */

  def isDefined(sig: ECDigitalSignature): Boolean =
    sig.bytes.lastOption.fold(false) { last =>
      val byte = last & ~(HashType.FORKID.byte | HashType.ANYONE_CANPAY.byte)
      byte >= BaseHashType.ALL.byte && byte <= BaseHashType.SINGLE.byte
    }

  implicit val equalBaseHash = new Equal[SigHashType] {
    override def equal(a1: SigHashType, a2: SigHashType): Boolean = a1.sighash == a2.sighash
  }
}

