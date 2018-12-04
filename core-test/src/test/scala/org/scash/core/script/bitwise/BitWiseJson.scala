package org.scash.core.script.bitwise

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import spray.json._

case class BitWiseCase(
  a: List[String],
  b: List[String],
  and: List[String],
  or: List[String])

object BitWiseJsonProtocol extends DefaultJsonProtocol {
  implicit val format = jsonFormat4(BitWiseCase)
}

