package org.scash.core.serializers

import org.scash.core.protocol.transaction.{Transaction, TransactionInput, TransactionOutput}
import org.scalacheck.{Prop, Properties}
import org.scash.testkit.gen.TransactionGenerators
import scodec.bits.ByteVector

class RawSerializerHelperSpec extends Properties("RawSerializerHelperSpec") {

  property("serialization symmetry of txs") = {
    Prop.forAll(TransactionGenerators.smallOutputs) { txs: Seq[TransactionOutput] =>
      val serialized = RawSerializerHelper.writeCmpctSizeUInt(txs, { tx: TransactionOutput => tx.bytes })
      val (deserialized, remaining) = RawSerializerHelper.parseCmpctSizeUIntSeq(serialized, TransactionOutput(_: ByteVector))
      deserialized == txs && remaining == ByteVector.empty
    }
  }

}
