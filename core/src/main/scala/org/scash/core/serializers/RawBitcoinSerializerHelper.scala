package org.scash.core.serializers

import org.scash.core.number.UInt64
import org.scash.core.protocol.{ CompactSizeUInt, NetworkElement }

import scodec.bits.ByteVector

/**
 * Created by chris on 2/18/16.
 */
object RawSerializerHelper {

  /**
   * Used parse a byte sequence to a Seq[TransactionInput], Seq[TransactionOutput], etc
   * Makes sure that we parse the correct amount of elements
   */
  def parseCmpctSizeUIntSeq[T <: NetworkElement](bytes: ByteVector, constructor: ByteVector => T): (Seq[T], ByteVector) = {
    val count = CompactSizeUInt.parse(bytes)
    val payload = bytes.splitAt(count.size.toInt)._2
    def loop(accum: Seq[T], remaining: ByteVector): (Seq[T], ByteVector) = {
      if (accum.size == count.num.toInt) {
        (accum.reverse, remaining)
      } else {
        val parsed = constructor(remaining)
        val (_, newRemaining) = remaining.splitAt(parsed.size)
        loop(parsed +: accum, newRemaining)
      }
    }

    val (parsed, remaining) = loop(Nil, payload)
    require(parsed.size == count.num.toInt, "Could not parse the amount of required elements, got: " + parsed.size + " required: " + count)
    (parsed, remaining)
  }

  /** Writes a Seq[TransactionInput]/Seq[TransactionOutput]/Seq[Transaction] -> ByteVector */
  def writeCmpctSizeUInt[T](ts: Seq[T], serializer: T => ByteVector): ByteVector = {
    val serializedSeq: Seq[ByteVector] = ts.map(serializer(_))
    val serialized = serializedSeq.foldLeft(ByteVector.empty)(_ ++ _)
    val cmpct = CompactSizeUInt(UInt64(ts.size))
    cmpct.bytes ++ serialized
  }
}
