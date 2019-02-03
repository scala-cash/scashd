package org.scash.core.script.crypto

import org.scash.core.script.crypto.BaseHashT.BaseHashT

import scalaz.Equal
import scodec.bits.ByteVector

object BaseHashT {
  abstract class BaseHashT

  case object SIGHASHALL extends BaseHashT
  case object SIGHASHNONE extends BaseHashT
  case object SIGHASHSINGLE extends BaseHashT
  case object SIGHASHUNSUPPORTED extends BaseHashT

  private val _1f = 0x1f.toByte

  private val sigHashUnsupportedB = 0.toByte
  private val sigHashAllB = 1.toByte
  private val sigHashNoneB = 2.toByte
  private val sigHashSingleB = 3.toByte

  def apply(b: Byte): BaseHashT = (b & _1f) match {
    case `sigHashAllB` => SIGHASHALL
    case `sigHashNoneB` => SIGHASHNONE
    case `sigHashSingleB` => SIGHASHSINGLE
    case _ => SIGHASHUNSUPPORTED
  }

  def unapply(b: BaseHashT) = b match {
    case SIGHASHUNSUPPORTED => sigHashUnsupportedB
    case SIGHASHALL => sigHashAllB
    case SIGHASHNONE => sigHashNoneB
    case SIGHASHSINGLE => sigHashSingleB
  }

  implicit val equalBaseHash = new Equal[BaseHashT] {
    override def equal(a1: BaseHashT, a2: BaseHashT): Boolean = (a1, a2) match {
      case (SIGHASHALL, SIGHASHALL) => true
      case (SIGHASHNONE, SIGHASHNONE) => true
      case (SIGHASHSINGLE, SIGHASHSINGLE) => true
      case _ => false
    }
  }
}


sealed trait HashTypeT
case class LegacyHashT(abc: BaseHashT) extends HashTypeT
case class BCHashT(abc: BaseHashT) extends HashTypeT
case class LegacyAnyoneCanPayHashT(abc: BaseHashT) extends HashTypeT
case class BCHAnyoneCanPayHashT(abc: BaseHashT) extends HashTypeT

object HashType2 {

  private object HashT {
    abstract class HashT
    case object SIGHASHFORKID extends HashT
    case object SIGHASHANYONECANPAY extends HashT

    private val sigHashForkIdB = 0x40.toByte
    private val sigHashAnyoneCanPayB = 0x80.toByte

    implicit class HashTOps(arg: HashT) {
      def byte: Byte = arg match {
        case SIGHASHFORKID => sigHashForkIdB
        case SIGHASHANYONECANPAY => sigHashAnyoneCanPayB
      }
    }
  }

  private val zero = 0.toByte

  def fromByte(b: Byte): HashTypeT = {
    val baseHashT = BaseHashT(b)
    val hasAnyoneCanPay = (b & HashT.SIGHASHANYONECANPAY.byte) != zero

    if ((b & HashT.SIGHASHFORKID.byte) != zero)
      if (hasAnyoneCanPay) BCHAnyoneCanPayHashT(baseHashT)
      else BCHashT(baseHashT)
    else if (hasAnyoneCanPay) LegacyAnyoneCanPayHashT(baseHashT)
    else LegacyHashT(baseHashT)
  }

  implicit class HashTypeTOps(hashType: HashTypeT) {

    def bch = hashType match {
      case LegacyHashT(h) => BCHashT(h)
      case LegacyAnyoneCanPayHashT(h) => BCHAnyoneCanPayHashT(h)
      case a => a
    }

    def byte = ByteVector( hashType match {
      case BCHashT(b) => BaseHashT.unapply(b) | HashT.SIGHASHFORKID.byte
      case BCHAnyoneCanPayHashT(b) => BaseHashT.unapply(b) | HashT.SIGHASHANYONECANPAY.byte | HashT.SIGHASHFORKID.byte
      case LegacyHashT(b) => BaseHashT.unapply(b)
      case LegacyAnyoneCanPayHashT(b) => BaseHashT.unapply(b) | HashT.SIGHASHANYONECANPAY.byte
    })
  }
}

