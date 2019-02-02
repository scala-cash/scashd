package org.scash.core.script.crypto

import org.scash.core.number.Int32

abstract class BaseHashT

case object SIGHASHALL extends BaseHashT
case object SIGHASHNONE  extends BaseHashT
case object SIGHASHSINGLE extends BaseHashT
case object SIGHASHUNSUPPORTED  extends BaseHashT

abstract class HashT
case object SIGHASHFORKID extends HashT
case object SIGHASHANYONECANPAY extends HashT


case class HashType2(num: Int32)

object HashType2 {

}

trait HashTypeOps {

  def getBaseHash(hashType: HashType2): BaseHashT = (hashType.num & Int32(0x1f)) match {
    case Int32.one => SIGHASHALL
    case Int32.two => SIGHASHNONE
    case Int32.three => SIGHASHSINGLE
  }

  def hasAnyoneCanPay(hashType: HashType2): Boolean
  def hasForkId(hashType: HashType2): Boolean

}
