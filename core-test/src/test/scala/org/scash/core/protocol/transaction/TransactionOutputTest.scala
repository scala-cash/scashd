package org.scash.core.protocol.transaction

import org.scash.core.currency.CurrencyUnits
import org.scash.core.protocol.script.EmptyScriptPubKey
import org.scash.core.util.TestUtil
import org.scalatest.{ FlatSpec, MustMatchers }

/**
 * Created by chris on 3/30/16.
 */
class TransactionOutputTest extends FlatSpec with MustMatchers {

  "TransactionOutput" must "define an empty transaction output" in {
    EmptyTransactionOutput.scriptPubKey must be(EmptyScriptPubKey)
    EmptyTransactionOutput.value must be(CurrencyUnits.negativeSatoshi)
  }
}
