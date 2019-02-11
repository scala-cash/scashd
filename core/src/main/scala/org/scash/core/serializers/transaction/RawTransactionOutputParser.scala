package org.scash.core.serializers.transaction

import org.scash.core.protocol.transaction.TransactionOutput
import org.scash.core.serializers.script.RawScriptPubKeyParser
import org.scash.core.serializers.RawSatoshisSerializer
import org.scash.core.currency.{ CurrencyUnits, Satoshis }
import org.scash.core.serializers.RawBitcoinSerializer

import scodec.bits.ByteVector

/**
 * Created by chris on 1/11/16.
 * https://bitcoin.org/en/developer-reference#txout
 */
sealed abstract class RawTransactionOutputParser extends RawBitcoinSerializer[TransactionOutput] {

  /** Writes a single transaction output */
  override def write(output: TransactionOutput): ByteVector = {
    val satoshis: Satoshis = CurrencyUnits.toSatoshis(output.value)
    satoshis.bytes ++ output.scriptPubKey.bytes
  }

  /**
   * Reads a single output from the given bytes, note this is different than RawTransactionOutputParser.read
   * because it does NOT expect a CompactSizeUInt to be the first element in the byte array indicating how many outputs we have
   */
  override def read(bytes: ByteVector): TransactionOutput = {
    val satoshisBytes = bytes.take(8)
    val satoshis = RawSatoshisSerializer.read(satoshisBytes)
    //it doesn't include itself towards the size, thats why it is incremented by one
    val scriptPubKeyBytes = bytes.slice(8, bytes.size)
    val scriptPubKey = RawScriptPubKeyParser.read(scriptPubKeyBytes)
    TransactionOutput(satoshis, scriptPubKey)
  }

}

object RawTransactionOutputParser extends RawTransactionOutputParser
