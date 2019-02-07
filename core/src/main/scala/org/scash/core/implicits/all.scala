package org.scash.core.implicits

import scalaz.Monoid
import scodec.bits.ByteVector

object all {
  implicit val byteVectorMonoid: Monoid[ByteVector] = new Monoid[ByteVector] {
    def zero: ByteVector = ByteVector.empty
    def append(f1: ByteVector, f2: => ByteVector): ByteVector = f1 ++ f2
  }
}
