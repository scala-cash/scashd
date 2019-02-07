package org.scash.core.script.crypto

import scalaz.Equal

object BaseHashType {
  abstract class BaseHashType { self =>
    def byte: Byte = unapply(self)
  }

  case object ALL extends BaseHashType
  case object NONE extends BaseHashType
  case object SINGLE extends BaseHashType
  case object ZERO extends BaseHashType
  private case class UNDEFINED(b: Byte) extends BaseHashType

  private val _1f = 0x1f.toByte

  private val sigHashZeroB = 0.toByte
  private val sigHashAllB = 1.toByte
  private val sigHashNoneB = 2.toByte
  private val sigHashSingleB = 3.toByte

  def apply(b: Byte): BaseHashType = (b & _1f).toByte match {
    case `sigHashAllB` => ALL
    case `sigHashNoneB` => NONE
    case `sigHashSingleB` => SINGLE
    case `sigHashZeroB` => ZERO
    case _ => UNDEFINED(b)
  }

  def unapply(b: BaseHashType) = b match {
    case ALL => sigHashAllB
    case NONE => sigHashNoneB
    case SINGLE => sigHashSingleB
    case ZERO => sigHashZeroB
    case UNDEFINED(by) => by
  }

  implicit val equalBaseHash = new Equal[BaseHashType] {
    def equal(a1: BaseHashType, a2: BaseHashType) = (a1, a2) match {
      case (SINGLE, SINGLE) => true
      case (ALL, ALL) => true
      case (NONE, NONE) => true
      case (ZERO, ZERO) => true
      case (UNDEFINED(_), UNDEFINED(_)) => true
      case _ => false
    }
  }
}

object HashType {
  abstract class HashType
  case object LEGACY extends HashType
  case object FORKID extends HashType
  case object ANYONE_CANPAY extends HashType

  private val sigHashForkIdB = 0x40.toByte
  private val sigHashAnyoneCanPayB = 0x80.toByte

  implicit class HashTOps(arg: HashType) {
    def byte: Byte = arg match {
      case FORKID => sigHashForkIdB
      case ANYONE_CANPAY => sigHashAnyoneCanPayB
      case LEGACY => 0x00.toByte
    }
  }
}

