package org.scash.rpc.jsonmodels

import org.scash.core.crypto.DoubleSha256DigestBE
import org.scash.core.currency.Bitcoins
import org.scash.core.number.UInt32
import org.scash.core.protocol.script.{ ScriptPubKey, ScriptSignature }
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.protocol.{ P2PKHAddress, P2SHAddress }
import org.scash.core.script.ScriptType

import scala.concurrent.duration.FiniteDuration

sealed abstract class RawTransactionResult

case class RpcTransaction(
  txid: DoubleSha256DigestBE,
  hash: DoubleSha256DigestBE,
  version: Int,
  size: Int,
  locktime: UInt32,
  vin: Vector[RpcTInput],
  vout: Vector[RpcTransactionOutput],
  hex: Option[String]
) extends RawTransactionResult

sealed trait RpcTInput

case class RpcCoinbaseInput(
  coinbase: String,
  sequence: UInt32
) extends RpcTInput

case class RpcTransactionInput(
  txid: DoubleSha256DigestBE,
  vout: Int,
  scriptSig: RpcScriptSig,
  sequence: UInt32
) extends RpcTInput

case class RpcScriptSig(
  asm: String,
  hex: String
) extends RawTransactionResult

case class RpcTransactionOutput(
  value: Bitcoins,
  n: Int,
  scriptPubKey: RpcScriptPubKey
) extends RawTransactionResult

case class RpcScriptPubKey(
  asm: String,
  hex: String,
  reqSigs: Option[Int],
  scriptType: ScriptType,
  addresses: Option[Vector[String]] //TODO: cant support cashaddr yet store as string for now
) extends RawTransactionResult

case class DecodeScriptResult(
  asm: String,
  typeOfScript: Option[ScriptType],
  reqSigs: Option[Int],
  addresses: Option[Vector[P2PKHAddress]],
  p2sh: P2SHAddress
) extends RawTransactionResult

case class FundRawTransactionResult(hex: Transaction, fee: Bitcoins, changepos: Int) extends RawTransactionResult

case class GetRawTransactionResult(
  in_active_blockchain: Option[Boolean],
  hex: Transaction,
  txid: DoubleSha256DigestBE,
  hash: DoubleSha256DigestBE,
  size: Int,
  version: Int,
  locktime: UInt32,
  vin: Vector[GetRawTransactionVin],
  vout: Vector[RpcTransactionOutput],
  blockhash: Option[DoubleSha256DigestBE],
  confirmations: Option[Int],
  time: Option[UInt32],
  blocktime: Option[UInt32]
) extends RawTransactionResult

case class GetRawTransactionVin(
  txid: Option[DoubleSha256DigestBE],
  vout: Option[Int],
  scriptSig: Option[GetRawTransactionScriptSig],
  sequence: Option[BigDecimal]
) extends RawTransactionResult

case class GetRawTransactionScriptSig(asm: String, hex: ScriptSignature) extends RawTransactionResult

case class SignRawTransactionResult(
  hex: Transaction,
  complete: Boolean,
  errors: Option[Vector[SignRawTransactionError]]
) extends RawTransactionResult

case class SignRawTransactionError(
  txid: DoubleSha256DigestBE,
  vout: Int,
  scriptSig: ScriptPubKey,
  sequence: UInt32,
  error: String
) extends RawTransactionResult

final case class GetRpcInfoResult(
  active_commands: Vector[RpcCommands]
) extends RawTransactionResult

final case class RpcCommands(
  method: String,
  duration: FiniteDuration //this time is in microseconds
) extends RawTransactionResult
