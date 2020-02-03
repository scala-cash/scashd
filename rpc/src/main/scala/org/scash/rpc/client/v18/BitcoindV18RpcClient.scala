package org.scash.rpc.client.v18

import akka.actor.ActorSystem
import org.scash.rpc.client.common.{BitcoindRpcClient, BitcoindVersion, PsbtRpc, DescriptorRpc, RpcOpts}
import org.scash.rpc.config.BitcoindInstance

import scala.util.Try
import org.scash.core.protocol.transaction.Transaction
import org.scash.core.crypto.ECPrivateKey
import org.scash.core.script.crypto.SigHashType
import org.scash.rpc.jsonmodels.SignRawTransactionResult
import play.api.libs.json.Json
import play.api.libs.json.JsString

import scala.concurrent.Future
import org.scash.rpc.serializers.JsonSerializers._
import org.scash.rpc.serializers.JsonWriters._
import org.scash.rpc.config.BitcoindInstance

/**
  * Class for creating a BitcoindV18 instance that can access RPCs
  * @param instance
  * @param actorSystem
  */
class BitcoindV18RpcClient(override val instance: BitcoindInstance)(
    implicit
    actorSystem: ActorSystem)
    extends BitcoindRpcClient(instance)
    with DescriptorRpc
    with PsbtRpc
    with V18AssortedRpc {

  override lazy val version: BitcoindVersion = BitcoindVersion.V18

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
    bitcoindCall[SignRawTransactionResult]("signrawtransactionwithwallet",
                                           List(JsString(transaction.hex),
                                                Json.toJson(utxoDeps),
                                                Json.toJson(sigHash)))

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
    bitcoindCall[SignRawTransactionResult]("signrawtransactionwithkey",
                                           List(JsString(transaction.hex),
                                                Json.toJson(keys),
                                                Json.toJson(utxoDeps),
                                                Json.toJson(sigHash)))

}

object BitcoindV18RpcClient {

  /**
    * Creates an RPC client from the given instance.
    *
    * Behind the scenes, we create an actor system for
    * you. You can use `withActorSystem` if you want to
    * manually specify an actor system for the RPC client.
    */
  def apply(instance: BitcoindInstance): BitcoindV18RpcClient = {
    implicit val system = ActorSystem.create(BitcoindRpcClient.ActorSystemName)
    withActorSystem(instance)
  }

  /**
    * Creates an RPC client from the given instance,
    * together with the given actor system. This is for
    * advanced users, where you need fine grained control
    * over the RPC client.
    */
  def withActorSystem(instance: BitcoindInstance)(
      implicit system: ActorSystem): BitcoindV18RpcClient =
    new BitcoindV18RpcClient(instance)(system)

  def fromUnknownVersion(
      rpcClient: BitcoindRpcClient): Try[BitcoindV18RpcClient] =
    Try {
      new BitcoindV18RpcClient(rpcClient.instance)(rpcClient.system)
    }

}
