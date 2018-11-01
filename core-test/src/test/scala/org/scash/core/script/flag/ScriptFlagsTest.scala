package org.scash.core.script.flag

import org.scalatest.{ MustMatchers, FlatSpec }

/**
 * Created by chris on 3/23/16.
 */
class ScriptFlagsTest extends FlatSpec with MustMatchers {

  "ScriptVerifyNone" must "have the flag zero" in {
    ScriptVerifyNone.flag must be(0)
  }

  "ScriptVerifyP2SH" must "have the flag one" in {
    ScriptVerifyP2SH.flag must be(1)
  }

  "ScriptVerifyStrictEnc" must "have the flag 2" in {
    ScriptVerifyStrictEnc.flag must be(2)
  }

  "ScriptVerifyDerSig" must "have the flag 1 << 2" in {
    ScriptVerifyDerSig.flag must be(1 << 2)
  }

  "ScriptVerifyLowS" must "have the flag 1 << 3" in {
    ScriptVerifyLowS.flag must be(1 << 3)
  }

  "ScriptVerifyNullDummy" must "have the flag 1 << 4" in {
    ScriptVerifyNullDummy.flag must be(1 << 4)
  }

  "ScriptVerifySigPushOnly" must "have the flag 1 << 5" in {
    ScriptVerifySigPushOnly.flag must be(1 << 5)
  }

  "ScriptVerifyMinimalData" must "have the flag 1 << 6" in {
    ScriptVerifyMinimalData.flag must be(1 << 6)
  }

  "ScriptVerifyDiscourageUpgradableNOPs" must "have the flag 1 << 7" in {
    ScriptVerifyDiscourageUpgradableNOPs.flag must be(1 << 7)
  }

  "ScriptVerifyCleanStack" must "have the flag 1 << 8" in {
    ScriptVerifyCleanStack.flag must be(1 << 8)
  }

  "ScriptVerifyCheckLocktimeVerify" must "have the flag 1 << 9" in {
    ScriptVerifyCheckLocktimeVerify.flag must be(1 << 9)
  }

  "ScriptVerifyCheckSequenceVerify" must "have the flag 1 << 10" in {
    ScriptVerifyCheckSequenceVerify.flag must be(1 << 10)
  }
  "ScriptVerifyMinimalIf" must "have the flag 1 << 11" in {
    ScriptVerifyMinimalIf.flag must be(1 << 11)
  }
  "ScriptVerifyNullFail" must "have the flag 1 << 13" in {
    ScriptVerifyNullFail.flag must be(1 << 13)
  }
  "ScriptVerifyCompressedPubkeytype" must "have the flag 1 << 15" in {
    ScriptVerifyCompressedPubkeytype.flag must be(1 << 15)
  }
  "ScriptEnableSigHashForkId" must "have the flag 1 << 16" in {
    ScriptEnableSigHashForkId.flag must be(1 << 16)
  }
  "ScriptEnableReplayProtection" must "have the flag 1 << 17" in {
    ScriptEnableReplayProtection.flag must be(1 << 17)
  }

}
