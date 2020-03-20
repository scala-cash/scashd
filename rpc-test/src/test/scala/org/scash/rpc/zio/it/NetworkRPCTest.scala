package org.scash.rpc.zio.it

import org.scash.rpc.jsonmodels._
import org.scash.rpc.zio.TestUtil
import org.scash.rpc.zrpc.zrpc
import zio.test.Assertion._
import zio.test._

object NetworkRPCTest extends DefaultRunnableSpec {
  val spec =
    suite("BlockchainRPC")(
      testM("Add Node from getPeerInfo and remove it from addnode list") {
        for {
          peers <- zrpc.getPeerInfo
          _     <- zrpc.addNodeFromPeer(peers.head)
          a     <- zrpc.removeAddedNodeByPeer(peers.head)
        } yield assert(a)(isUnit)
      },
      testM("ClearBanned") {
        assertM(zrpc.clearBanned)(isUnit)
      },
      testM("DisconnectNode") {
        for {
          peer <- zrpc.getPeerInfo
          ans  <- zrpc.disconnectPeer(peer.head)
        } yield assert(ans)(isUnit)
      },
      testM("GetAddedNodeInfo") {
        assertM(zrpc.getAllAddedNodes)(isSubtype[Vector[Node]](Assertion.anything))
      },
      testM("GetConnectionCount") {
        assertM(zrpc.getConnectionCount)(isSubtype[Int](Assertion.anything))
      },
      testM("GetExcessiveBlock") {
        assertM(zrpc.getExcessiveBlock)(isSubtype[GetExcessiveBlockSize](Assertion.anything))
      },
      testM("GetNetTotals") {
        assertM(zrpc.getNetTotals)(isSubtype[GetNetTotalsResult](Assertion.anything))
      },
      testM("GetNetworkInfo") {
        assertM(zrpc.getNetworkInfo)(isSubtype[GetNetworkInfoResult](Assertion.anything))
      },
      testM("isNetworkActive") {
        assertM(zrpc.isNetworkActive)(isTrue)
      },
      testM("GetNodeAddresses") {
        assertM(zrpc.getNodeAddresses(1))(isSubtype[Vector[GetNodeAddressesResult]](Assertion.anything))
      },
      testM("GetPeerInfo") {
        assertM(zrpc.getPeerInfo)(isSubtype[Vector[Peer]](Assertion.anything))
      },
      testM("Listbanned") {
        assertM(zrpc.listBanned)(isSubtype[Vector[NodeBan]](Assertion.anything))
      },
      testM("Ping") {
        assertM(zrpc.ping)(isUnit)
      },
      testM("SetExcessiveBlock") {
        assertM(zrpc.setExcessiveBlock(32000000L))(isSubtype[String](Assertion.anything))
      },
      suite("SetNetworkActive")(
        testM("ActivateNetwork") {
          for {
            act  <- zrpc.activateNetwork
            bool <- zrpc.isNetworkActive
          } yield assert(bool && act)(isTrue)
        },
        testM("DeactivateNetwork") {
          for {
            dis <- zrpc.deactivateNetwork
            con <- zrpc.activateNetwork
          } yield assert(!dis && con)(isTrue)
        }
      )
    ).provideCustomLayer(TestUtil.instance) @@ TestAspect.sequential
}
