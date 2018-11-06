package org.scash.core.script

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.util.BitcoinSUtil
import org.scash.core.script.arithmetic.ArithmeticOperation
import org.scash.core.script.bitwise.BitwiseOperation
import org.scash.core.script.constant._
import org.scash.core.script.control.ControlOperations
import org.scash.core.script.crypto.CryptoOperation
import org.scash.core.script.locktime.LocktimeOperation
import org.scash.core.script.reserved.ReservedOperation
import org.scash.core.script.splice.SpliceOperation
import org.scash.core.script.stack.StackOperation
import org.scash.core.util.BitcoinSLogger

/**
 * Responsible for matching script op codes with their given
 * hexadecimal representation or byte representation
 */
trait ScriptOperationFactory[T <: ScriptOperation] extends BitcoinSLogger {

  /** All of the [[ScriptOperation]]s for a particular T. */
  def operations: Seq[T]

  /**
   * Finds a [[ScriptOperation]] from a given string
   */
  def fromString(str: String): Option[T] = {
    logger.trace(s"parsing string: $str")
    val result: Option[T] = operations.find(_.toString == str)
    if (result.isEmpty) {
      //try and remove the 'OP_' prefix on the operations and see if it matches anything.
      operations.find(op => removeOP_Prefix(op.toString) == removeOP_Prefix(str))
    } else result
  }

  /**
   * Finds a [[ScriptOperation]] from its hexadecimal representation.
   */
  def fromHex(hex: String): Option[T] = operations.find(_.hex == hex.toLowerCase)

  /**
   * Removes the 'OP_' prefix from a given operation.
   * Example: OP_EQUALVERIFY would be transformed into EQUALVERIFY
   */
  private def removeOP_Prefix(str: String): String = {
    str.replace("OP_", "")
  }

  /** Finds a [[ScriptOperation]] from a given [[Byte]]. */
  def fromByte(byte: Byte): Option[T] = {
    val hex = BitcoinSUtil.encodeHex(byte)
    fromHex(hex)
  }

  def apply(byte: Byte): Option[T] = fromByte(byte)

  def apply(hex: String): Option[T] = fromHex(hex)
}

object ScriptOperation extends ScriptOperationFactory[ScriptOperation] {

  lazy val operations = ScriptNumberOperation.operations ++ Seq(OP_FALSE, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_TRUE) ++ StackOperation.operations ++ LocktimeOperation.operations ++
    CryptoOperation.operations ++ ControlOperations.operations ++ BitwiseOperation.operations ++
    ArithmeticOperation.operations ++ BytesToPushOntoStack.operations ++ SpliceOperation.operations ++
    ReservedOperation.operations

}
