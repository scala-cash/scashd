package org.scash.core.wallet.builder

import org.scash.core.currency.Satoshis
import org.scash.core.number.Int64
import org.scash.core.wallet.fee.SatoshisPerByte
import org.scalatest.{ FlatSpec, MustMatchers }

class TxBuilderTest extends FlatSpec with MustMatchers {

  "TxBuilder" must "detect a bad fee on the tx" in {
    val estimatedFee = Satoshis(Int64(1000))
    val actualFee = Satoshis.one
    val feeRate = SatoshisPerByte(Satoshis.one)
    TxBuilder.isValidFeeRange(estimatedFee, actualFee, feeRate).isFailure must be(true)

    TxBuilder.isValidFeeRange(actualFee, estimatedFee, feeRate).isFailure must be(true)
  }
}
