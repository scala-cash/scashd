package org.scash.core.policy

/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */

import org.scash.core.script.flag._
import org.scash.core.currency.{ CurrencyUnit, CurrencyUnits, Satoshis }
import org.scash.core.number.Int64

/**
 * Mimics the policy files found in bitcoin cash
 * https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/policy/policy.h
 */
sealed abstract class Policy {

  /**
   * Mandatory script verification flags that all new blocks must comply with for
   * them to be valid. (but old blocks may not comply with)
   *
   * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
   * details.
   */
  def mandatoryScriptVerifyFlags: Seq[ScriptFlag] = Seq(
    ScriptVerifyP2SH,
    ScriptVerifyStrictEnc,
    ScriptEnableSigHashForkId,
    ScriptVerifyLowS,
    ScriptVerifyNullFail)

  /**
   * The default script verify flags used to validate the blockchain
   * and bitcoin transactions
   */
  def standardScriptVerifyFlags: Seq[ScriptFlag] = mandatoryScriptVerifyFlags ++ Seq(
    ScriptVerifyDerSig,
    ScriptVerifyLowS,
    ScriptVerifyNullDummy,
    // ScriptVerifySigPushOnly, //TODO: this is causing 2 tests to fail
    ScriptVerifyMinimalData,
    ScriptVerifyDiscourageUpgradableNOPs,
    ScriptVerifyCleanStack,
    ScriptVerifyCheckLocktimeVerify,
    ScriptVerifyCheckSequenceVerify,
    ScriptVerifyNullFail)

  /**
   * For convenience, standard but not mandatory verify flags.
   */
  def standardNonMandatoryVerifyFlags = standardScriptVerifyFlags
    .filterNot(mandatoryScriptVerifyFlags.contains)

  def standardFlags = standardScriptVerifyFlags

  /** The number of confirmations for a payment to be considered as accepted */
  def confirmations: Long = 6

  /** The minimum amount of satoshis we can spend to an output */
  def dustThreshold: CurrencyUnit = Satoshis(Int64(1000))

  /** A default fee to use per byte on the bitcoin network */
  def defaultFee: CurrencyUnit = Satoshis(Int64(50))

  /** Max fee for a transaction is set to 10 mBTC right now */
  def maxFee: CurrencyUnit = Satoshis(Int64(10)) * CurrencyUnits.oneMBTC
}

object Policy extends Policy
