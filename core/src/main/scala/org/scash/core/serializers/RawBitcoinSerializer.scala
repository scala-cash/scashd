package org.scash.core.serializers

import org.scash.core.util.BitcoinSUtil
import scodec.bits.ByteVector

/**
 * Created by chris on 1/11/16.
 * A common trait for reading/writing bitcoin objects to/from bytes/hex
 */
abstract class RawBitcoinSerializer[T] {

  /** Reads a hexadecimal value and transforms it into the native scala type T. */
  def read(hex: String): T = read(BitcoinSUtil.decodeHex(hex))

  /** Reads in bytes and transforms it into the appropriate scala type T. */
  def read(bytes: ByteVector): T

  /** Takes a type T and writes it into the appropriate hexadecimal serialization for type T. */
  def write(t: T): ByteVector
}