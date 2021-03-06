package org.scash.rpc.client.v19

import akka.actor.ActorSystem
import org.scash.core.crypto.ECPrivateKey
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.script.crypto.SigHashType
import org.scash.rpc.client.common.RpcOpts.WalletFlag
import org.scash.rpc.client.common.{ BitcoindRpcClient, BitcoindVersion, DescriptorRpc, PsbtRpc, RpcOpts }
import org.scash.rpc.config.BitcoindInstance
import org.scash.rpc.jsonmodels.{ GetBalancesResult, SetWalletFlagResult, SignRawTransactionResult }
import play.api.libs.json.Json
import play.api.libs.json.JsString
import org.scash.rpc.serializers.JsonSerializers._
import org.scash.rpc.serializers.JsonWriters._

import scala.concurrent.Future
import scala.util.Try

/**
 * Class for creating a BitcoindV19 instance that can access RPCs
 */
class BitcoindV21RpcClient(override val instance: BitcoindInstance)(
  implicit
  actorSystem: ActorSystem
) extends BitcoindRpcClient(instance)
    with DescriptorRpc
    with PsbtRpc {

  override lazy val version: BitcoindVersion = BitcoindVersion.V21

  /**
   * $signRawTx
   *
   * This RPC call signs the raw transaction with keys found in
   * the Bitcoin Core wallet.
   */
  def signRawTransactionWithWallet(
    transaction: Transaction,
    utxoDeps: Vector[RpcOpts.SignRawTransactionOutputParameter] = Vector.empty,
    sigHash: SigHashType = SigHashType.bchALL
  ): Future[SignRawTransactionResult] =
    bitcoindCall[SignRawTransactionResult](
      "signrawtransactionwithwallet",
      List(JsString(transaction.hex), Json.toJson(utxoDeps), Json.toJson(sigHash))
    )

  /**
   * $signRawTx
   *
   * This RPC call signs the raw transaction with keys provided
   * manually.
   */
  def signRawTransactionWithKey(
    transaction: Transaction,
    keys: Vector[ECPrivateKey],
    utxoDeps: Vector[RpcOpts.SignRawTransactionOutputParameter] = Vector.empty,
    sigHash: SigHashType = SigHashType.bchALL
  ): Future[SignRawTransactionResult] =
    bitcoindCall[SignRawTransactionResult](
      "signrawtransactionwithkey",
      List(JsString(transaction.hex), Json.toJson(keys), Json.toJson(utxoDeps), Json.toJson(sigHash))
    )

  /**
   * Change the state of the given wallet flag for a wallet.
   */
  def setWalletFlag(
    flag: WalletFlag,
    value: Boolean
  ): Future[SetWalletFlagResult] =
    bitcoindCall[SetWalletFlagResult]("setwalletflag", List(JsString(flag.toString), Json.toJson(value)))

  def getBalances: Future[GetBalancesResult] =
    bitcoindCall[GetBalancesResult]("getbalances")

}

object BitcoindV21RpcClient {

  /**
   * Creates an RPC client from the given instance.
   *
   * Behind the scenes, we create an actor system for
   * you. You can use `withActorSystem` if you want to
   * manually specify an actor system for the RPC client.
   */
  def apply(instance: BitcoindInstance): BitcoindV21RpcClient = {
    implicit val system =
      ActorSystem.create(BitcoindRpcClient.ActorSystemName)
    withActorSystem(instance)
  }

  /**
   * Creates an RPC client from the given instance,
   * together with the given actor system. This is for
   * advanced users, where you need fine grained control
   * over the RPC client.
   */
  def withActorSystem(instance: BitcoindInstance)(implicit system: ActorSystem): BitcoindV21RpcClient =
    new BitcoindV21RpcClient(instance)(system)

  def fromUnknownVersion(rpcClient: BitcoindRpcClient): Try[BitcoindV21RpcClient] =
    Try {
      new BitcoindV21RpcClient(rpcClient.instance)(rpcClient.system)
    }

}
