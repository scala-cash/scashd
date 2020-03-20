package org.scash.rpc.zrpc

import java.net.URI

import org.scash.rpc.client.common.RpcOpts.SetBanCommand
import org.scash.rpc.jsonmodels._
import org.scash.rpc.serializers.JsonSerializers._
import org.scash.rpc.zrpc.zrpc.ZClient
import play.api.libs.json.{ JsBoolean, JsNumber, JsString }
import sttp.model.Uri
import zio.{ RIO, ZIO }

trait NetworkRPC {

  def addNode(node: Node): ZIO[ZClient, Throwable, Unit] = addNodeFromUri(node.addednode)

  def addNodeFromPeer(peer: Peer): ZIO[ZClient, Throwable, Unit] = addNodeFromUri(peer.networkInfo.addr)

  def addNodeFromUri(address: URI): ZIO[ZClient, Throwable, Unit] = addNodeFull(address, "add")

  def removeAddedNode(node: Node): ZIO[ZClient, Throwable, Unit] = addNodeFull(node.addednode, "remove")

  def removeAddedNodeByPeer(node: Peer): ZIO[ZClient, Throwable, Unit] = addNodeFull(node.networkInfo.addr, "remove")

  def clearBanned: ZIO[ZClient, Throwable, Unit] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Unit]("clearbanned"))

  def disconnectPeerbyUri(address: URI): ZIO[ZClient, Throwable, Unit] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Unit]("disconnectnode", List(JsString(address.getAuthority))))

  def disconnectPeer(peer: Peer): ZIO[ZClient, Throwable, Unit] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Unit]("disconnectnode", List(JsString(""), JsNumber(peer.id))))

  def getAllAddedNodes: ZIO[ZClient, Throwable, Vector[Node]] = getAddedNodeInfo(None)

  def getAddedNode(node: URI): ZIO[ZClient, Throwable, Vector[Node]] =
    getAddedNodeInfo(Some(node))

  def getConnectionCount: ZIO[ZClient, Throwable, Int] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Int]("getconnectioncount"))

  def getExcessiveBlock: ZIO[ZClient, Throwable, GetExcessiveBlockSize] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[GetExcessiveBlockSize]("getexcessiveblock"))

  def getNetTotals: ZIO[ZClient, Throwable, GetNetTotalsResult] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[GetNetTotalsResult]("getnettotals"))

  def getNetworkInfo: ZIO[ZClient, Throwable, GetNetworkInfoResult] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[GetNetworkInfoResult]("getnetworkinfo"))

  def getNodeAddresses(count: Int = 1): ZIO[ZClient, Throwable, Vector[GetNodeAddressesResult]] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[Vector[GetNodeAddressesResult]]("getnodeaddresses", List(JsNumber(count)))
    )

  def getPeerInfo: ZIO[ZClient, Throwable, Vector[Peer]] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Vector[Peer]]("getpeerinfo"))

  def listBanned: ZIO[ZClient, Throwable, Vector[NodeBan]] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Vector[NodeBan]]("listbanned"))

  def ping: RIO[ZClient, Unit] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Unit]("ping"))

  def setBan(
    address: Uri,
    command: SetBanCommand,
    banTime: Int = 86400,
    absolute: Boolean = false
  ): ZIO[ZClient, Throwable, Unit] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[Unit](
        "setban",
        List(
          JsString(address.toJavaUri.getAuthority),
          JsString(command.toString),
          JsNumber(banTime),
          JsBoolean(absolute)
        )
      )
    )

  def setExcessiveBlock(blockSize: Long): ZIO[ZClient, Throwable, String] =
    ZIO.accessM[ZClient](
      _.get
        .bitcoindCall[String]("setexcessiveblock", List(JsNumber(blockSize)))
    )

  def isNetworkActive: ZIO[ZClient, Throwable, Boolean] = getNetworkInfo.map(_.networkactive)

  def activateNetwork: ZIO[ZClient, Throwable, Boolean] = setNetworkActive(true)

  def deactivateNetwork: ZIO[ZClient, Throwable, Boolean] = setNetworkActive(false)

  private def setNetworkActive(activate: Boolean) =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Boolean]("setnetworkactive", List(JsBoolean(activate))))

  private def addNodeFull(address: URI, cmd: String) =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[Unit]("addnode", List(JsString(address.getAuthority), JsString(cmd)))
    )

  private def getAddedNodeInfo(node: Option[URI]) = {
    val params = node.fold(List.empty[JsString])(n => List(JsString(n.getAuthority)))
    ZIO.accessM[ZClient](_.get.bitcoindCall[Vector[Node]]("getaddednodeinfo", params))
  }
}
