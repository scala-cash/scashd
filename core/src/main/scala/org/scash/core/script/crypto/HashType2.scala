package org.scash.core.script.crypto

import org.scash.core.script.crypto.BaseHashT.BaseHashT
import scalaz.Equal
import scalaz.syntax.equal._
import scodec.bits.ByteVector

abstract class HashT
case object SIGHASHFORKID extends HashT
case object SIGHASHANYONECANPAY extends HashT

object HashT {
  private val sigHashForkIdB = 0x40.toByte
  private val sigHashAnyoneCanPayB = 0x80.toByte

  implicit class HashTOps(arg: HashT) {
    def byte: Byte = arg match {
      case SIGHASHFORKID => sigHashForkIdB
      case SIGHASHANYONECANPAY => sigHashAnyoneCanPayB
    }
  }
}

object BaseHashT {
  abstract class BaseHashT

  case object SIGHASHALL extends BaseHashT
  case object SIGHASHNONE extends BaseHashT
  case object SIGHASHSINGLE extends BaseHashT
  case object SIGHASHZERO extends BaseHashT
  case class SIGHASHUNSUPPORTED(b: Byte) extends BaseHashT

  private val _1f = 0x1f.toByte

  private val sigHashZeroB = 0.toByte
  private val sigHashAllB = 1.toByte
  private val sigHashNoneB = 2.toByte
  private val sigHashSingleB = 3.toByte

  def apply(b: Byte): BaseHashT = (b & _1f) match {
    case `sigHashAllB` => SIGHASHALL
    case `sigHashNoneB` => SIGHASHNONE
    case `sigHashSingleB` => SIGHASHSINGLE
    case `sigHashZeroB` => SIGHASHZERO
    case _ => SIGHASHUNSUPPORTED(b)
  }


  def unapply(b: BaseHashT) = b match {
    case SIGHASHUNSUPPORTED(n) => n
    case SIGHASHALL => sigHashAllB
    case SIGHASHNONE => sigHashNoneB
    case SIGHASHSINGLE => sigHashSingleB
    case SIGHASHZERO => sigHashZeroB
  }

  implicit class BaseHashTOps(b: BaseHashT) {
    def *>(h: HashT) = h match {
      case SIGHASHFORKID => BCHashT(b)
      case SIGHASHANYONECANPAY => LegacyAnyoneCanPayHashT(b)
    }

    def *>(h1: HashT, h2: HashT) = (h1, h2) match {
      case (SIGHASHANYONECANPAY, SIGHASHANYONECANPAY) => LegacyAnyoneCanPayHashT(b)
      case (SIGHASHFORKID, SIGHASHFORKID) => BCHashT(b)
      case _ => BCHAnyoneCanPayHashT(b)
    }
  }

  implicit val equalBaseHash = new Equal[BaseHashT] {
    override def equal(a1: BaseHashT, a2: BaseHashT): Boolean = (a1, a2) match {
      case (SIGHASHALL, SIGHASHALL) => true
      case (SIGHASHNONE, SIGHASHNONE) => true
      case (SIGHASHSINGLE, SIGHASHSINGLE) => true
      case (SIGHASHZERO, SIGHASHZERO) => true
      case (SIGHASHUNSUPPORTED(n1), SIGHASHUNSUPPORTED(n2)) => n1 == n2
      case _ => false
    }
  }
}

sealed trait HashType2
case class LegacyHashT(abc: BaseHashT) extends HashType2
case class LegacyAnyoneCanPayHashT(abc: BaseHashT) extends HashType2
case class BCHashT(abc: BaseHashT) extends HashType2
case class BCHAnyoneCanPayHashT(abc: BaseHashT) extends HashType2

object HashType2 {

  private val zero = 0.toByte

  def apply(b: ByteVector): HashType2 = apply(b.last)

  def apply(b: BaseHashT) = LegacyHashT(b)

  val SIGHASH_ANYONECANPAY = BaseHashT.SIGHASHZERO *> SIGHASHANYONECANPAY
  val SIGHASH_FORKID = BaseHashT.SIGHASHZERO *> SIGHASHFORKID

  def apply(b: Byte): HashType2 = {
    val baseHashT = BaseHashT(b)
    val hasAnyoneCanPay = (b & SIGHASHANYONECANPAY.byte) != zero

    if ((b & SIGHASHFORKID.byte) != zero)
      if (hasAnyoneCanPay) BCHAnyoneCanPayHashT(baseHashT)
      else BCHashT(baseHashT)
    else if (hasAnyoneCanPay) LegacyAnyoneCanPayHashT(baseHashT)
    else LegacyHashT(baseHashT)
  }

  implicit class HashType2Ops(hashType: HashType2) {
    def has(h: HashT): Boolean = (h, hashType) match {
      case (SIGHASHFORKID, _: BCHAnyoneCanPayHashT | _: BCHashT) => true
      case (SIGHASHANYONECANPAY, _: BCHAnyoneCanPayHashT | _: LegacyAnyoneCanPayHashT) => true
      case _ => false
    }

    def has(b: BaseHashT): Boolean = hashType match {
      case BCHashT(h2) => h2 === b
      case BCHAnyoneCanPayHashT(h2) => h2 === b
      case LegacyHashT(h2) => h2 === b
      case LegacyAnyoneCanPayHashT(h2) => h2 === b
    }

    def byte = ByteVector(hashType match {
      case BCHashT(b) => BaseHashT.unapply(b) | SIGHASHFORKID.byte
      case BCHAnyoneCanPayHashT(b) => BaseHashT.unapply(b) | SIGHASHANYONECANPAY.byte | SIGHASHFORKID.byte
      case LegacyHashT(b) => BaseHashT.unapply(b)
      case LegacyAnyoneCanPayHashT(b) => BaseHashT.unapply(b) | SIGHASHANYONECANPAY.byte
    })
  }

  implicit val equalBaseHash = new Equal[HashType2] {
    override def equal(a1: HashType2, a2: HashType2): Boolean = (a1, a2) match {
      case (BCHashT(h1), BCHashT(h2)) => h1 === h2
      case (BCHAnyoneCanPayHashT(h1), BCHAnyoneCanPayHashT(h2)) => h1 === h2
      case (LegacyHashT(h1), LegacyHashT(h2)) => h1 === h2
      case (LegacyAnyoneCanPayHashT(h1) , LegacyAnyoneCanPayHashT(h2) ) => h1 === h2
      case _ => false
    }
  }
}

