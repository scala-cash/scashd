package org.scash.rpc.v19

import org.scash.rpc.client.common.BitcoindVersion
import org.scash.rpc.client.common.RpcOpts.WalletFlag
import org.scash.rpc.client.v19.BitcoindV21RpcClient
import org.scash.testkit.rpc.BitcoindRpcTestUtil
import org.scash.testkit.util.BitcoindRpcTest

import scala.concurrent.Future

class BitcoindV21RpcClientTest extends BitcoindRpcTest {
  lazy val clientF: Future[BitcoindV21RpcClient] = {
    val client = new BitcoindV21RpcClient(BitcoindRpcTestUtil.v19Instance())
    val clientIsStartedF = BitcoindRpcTestUtil.startServers(Vector(client))
    clientIsStartedF.map(_ => client)
  }
  lazy val clientPairF: Future[(BitcoindV21RpcClient, BitcoindV21RpcClient)] =
    BitcoindRpcTestUtil.createNodePairV21(clientAccum)

  clientF.foreach(c => clientAccum.+=(c))

  behavior of "BitcoindV19RpcClient"

  it should "be able to start a V19 bitcoind instance" in {

    clientF.map { client =>
      assert(client.version == BitcoindVersion.V21)
    }

  }

  it should "be able to get the balances" in {
    for {
      (client, _) <- clientPairF
      immatureBalance <- client.getBalances
      _ <- client.getNewAddress.flatMap(client.generateToAddress(1, _))
      newImmatureBalance <- client.getBalances
    } yield {
      val blockReward = 12.5
      assert(immatureBalance.mine.immature.toBigDecimal >= 0)
      assert(
        immatureBalance.mine.immature.toBigDecimal + blockReward == newImmatureBalance.mine.immature.toBigDecimal)
    }
  }

  it should "be able to set the wallet flag 'avoid_reuse'" in {
    for {
      (client, _) <- clientPairF
      unspentPre <- client.listUnspent
      result <- client.setWalletFlag(WalletFlag.AvoidReuse, value = true)
      unspentPost <- client.listUnspent
    } yield {
      assert(result.flag_name == "avoid_reuse")
      assert(result.flag_state)
      assert(unspentPre.forall(utxo => utxo.reused.isEmpty))
      assert(unspentPost.forall(utxo => utxo.reused.isDefined))
    }
  }

  it should "create a wallet with a passphrase" in {
    for {
      (client, _) <- clientPairF
      _ <- client.createWallet("suredbits", passphrase = "stackingsats")
      wallets <- client.listWallets
    } yield {
      assert(wallets.contains("suredbits"))
    }

  }

  it should "check to see if the utxoUpdate input has been updated" in {

    val descriptor =
      "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"

    val psbt =
      "cHNidP8BACoCAAAAAAFAQg8AAAAAABepFG6Rty1Vk+fUOR4v9E6R6YXDFkHwhwAAAAAAAA=="
    val updatedF =
      clientF.flatMap(client => client.utxoUpdatePsbt(psbt, Seq(descriptor)))

    updatedF.map { result =>
      assert(result.contains(psbt))
    }
  }
}
