package org.scash.core.script.splice
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script.constant.ScriptOperation
import org.scash.core.script.ScriptOperationFactory

sealed trait SpliceOperation extends ScriptOperation

case object OP_CAT extends SpliceOperation {
  override def opCode = 126
}

case object OP_SPLIT extends SpliceOperation {
  override def opCode = 127
}

case object OP_NUM2BIN extends SpliceOperation {
  override def opCode = 128
}

case object OP_BIN2NUM extends SpliceOperation {
  override def opCode = 129
}

case object OP_SIZE extends SpliceOperation {
  override def opCode = 130
}

object SpliceOperation extends ScriptOperationFactory[SpliceOperation] {
  def operations = Seq(OP_CAT, OP_NUM2BIN, OP_BIN2NUM, OP_SIZE, OP_SPLIT)
}