package org.scash.core.number

import scodec.Attempt.Successful

import scodec.Codec
import scodec.codecs._
import org.scash.core.typeclass._

case class Uint32B(private[core] val num: BigInt)

object Uint32B {

  implicit val uint32Codec: Codec[Uint32B] = uint32L.widen(
    l => Uint32B(NumericUtil.longToBigInt(l)),
    u => Successful(NumericUtil.bigIntToLong(u.num))
  )
  /*
  implicit val uint32Numeric: CNumeric[Uint32B] =
    CNumeric[Uint32B](0xFFFFFFFFL)(_.num, Uint32B(_))
 */
}
