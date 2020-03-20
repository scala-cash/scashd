package org.scash.rpc.zrpc

import org.scash.core.crypto.{ DoubleSha256Digest, DoubleSha256DigestBE }
import org.scash.core.protocol.blockchain.{ Block, BlockHeader }
import org.scash.rpc.jsonmodels.{
  ChainTip,
  GetBlockChainInfoResult,
  GetBlockHeaderResult,
  GetBlockResult,
  GetBlockWithTransactionsResult
}

import org.scash.rpc.serializers.JsonSerializers._
import org.scash.rpc.zrpc.zrpc.ZClient
import play.api.libs.json.{ JsBoolean, JsNumber, JsString }
import zio.{ RIO, ZIO }

trait BlockchainRPC {
  def getBestBlockHash: RIO[ZClient, DoubleSha256DigestBE] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[DoubleSha256DigestBE]("getbestblockhash"))

  /**
   * Returns a `GetBlockResult` from the block <hash>, with a Vector of tx hashes inside the block
   * Equivalent to bitcoin-cli getblock <hash> 1`
   */
  def getBlock(headerHash: DoubleSha256DigestBE): RIO[ZClient, GetBlockResult] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[GetBlockResult]("getblock", List(JsString(headerHash.hex), JsNumber(1)))
    )

  /**
   * Same as [[getBlock]] but takes a Little Endian DoubleSha256 Hex instead of Big endian (BE)
   */
  def getBlock(headerHash: DoubleSha256Digest): RIO[ZClient, GetBlockResult] = getBlock(headerHash.flip)

  /**
   * Returns a `GetBlockWithTransactionsResult` from the block <hash>, with a Vector of tx `RpcTransaction`
   * Equivalent to bitcoin-cli getblock <hash> 2
   */
  def getBlockWithTransactions(headerHash: DoubleSha256DigestBE): RIO[ZClient, GetBlockWithTransactionsResult] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[GetBlockWithTransactionsResult]("getblock", List(JsString(headerHash.hex), JsNumber(2)))
    )

  def getBlockWithTransactions(headerHash: DoubleSha256Digest): RIO[ZClient, GetBlockWithTransactionsResult] =
    getBlockWithTransactions(headerHash.flip)

  def getBlockChainInfo: RIO[ZClient, GetBlockChainInfoResult] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[GetBlockChainInfoResult]("getblockchaininfo"))

  def getBlockCount: RIO[ZClient, Int] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Int]("getblockcount"))

  def getBlockHash(height: Int): RIO[ZClient, DoubleSha256DigestBE] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[DoubleSha256DigestBE]("getblockhash", List(JsNumber(height))))

  def getBlockHeader(headerHash: DoubleSha256DigestBE): RIO[ZClient, GetBlockHeaderResult] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[GetBlockHeaderResult]("getblockheader", List(JsString(headerHash.hex), JsBoolean(true)))
    )

  def getBlockHeader(headerHash: DoubleSha256Digest): RIO[ZClient, GetBlockHeaderResult] =
    getBlockHeader(headerHash.flip)

  def getBlockHeaderRaw(headerHash: DoubleSha256DigestBE): RIO[ZClient, BlockHeader] =
    ZIO.accessM[ZClient](
      _.get.bitcoindCall[BlockHeader]("getblockheader", List(JsString(headerHash.hex), JsBoolean(false)))
    )

  def getBlockHeaderRaw(headerHash: DoubleSha256Digest): RIO[ZClient, BlockHeader] =
    getBlockHeaderRaw(headerHash.flip)

  def getBlockRaw(headerHash: DoubleSha256DigestBE): RIO[ZClient, Block] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Block]("getblock", List(JsString(headerHash.hex), JsNumber(0))))

  def getBlockRaw(headerHash: DoubleSha256Digest): RIO[ZClient, Block] =
    getBlockRaw(headerHash.flip)

  def getChainTips: RIO[ZClient, Vector[ChainTip]] =
    ZIO.accessM[ZClient](_.get.bitcoindCall[Vector[ChainTip]]("getchaintips"))
}
