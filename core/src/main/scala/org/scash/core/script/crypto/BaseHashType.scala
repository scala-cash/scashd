package org.scash.core.script.crypto

import scalaz.Equal

object BaseHashType {
  abstract class BaseHashType
  case object ALL extends BaseHashType
  case object NONE extends BaseHashType
  case object SINGLE extends BaseHashType
  case object ZERO extends BaseHashType
  case object UNDEFINED extends BaseHashType

  val zeroB = 0.toByte
  val allB = 1.toByte
  val noneB = 2.toByte
  val singleB = 3.toByte

  private val _1f = 0x1f.toByte

  def apply(b2: Byte): BaseHashType = (b2 & _1f).toByte match {
    case `allB` => ALL
    case `noneB` => NONE
    case `singleB` => SINGLE
    case `zeroB` => ZERO
    case _ => ZERO
  }

  object ops {

    implicit final class BaseHashTypeOps(private val b: BaseHashType) extends AnyVal {
      def byte = b match {
        case ALL => allB
        case NONE => noneB
        case SINGLE => singleB
        case ZERO => zeroB
      }
    }

    implicit val equalBaseHash = new Equal[BaseHashType] {
      def equal(a1: BaseHashType, a2: BaseHashType) = (a1, a2) match {
        case (SINGLE, SINGLE) => true
        case (ALL, ALL) => true
        case (NONE, NONE) => true
        case (ZERO, ZERO) => true
        case _ => false
      }
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

  implicit final class HashTOps(private val arg: HashType) extends AnyVal {
    def byte: Byte = arg match {
      case FORKID => sigHashForkIdB
      case ANYONE_CANPAY => sigHashAnyoneCanPayB
      case LEGACY => 0x00.toByte
    }
  }
}

