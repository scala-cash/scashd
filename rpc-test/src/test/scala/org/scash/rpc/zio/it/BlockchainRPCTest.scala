package org.scash.rpc.zio.it

import org.scash.core.crypto.DoubleSha256DigestBE
import org.scash.core.protocol.blockchain.{ Block, BlockHeader }
import org.scash.rpc.jsonmodels._
import org.scash.rpc.zio.TestUtil
import org.scash.rpc.zrpc.zrpc
import zio.test.Assertion.{ equalTo, isSubtype }
import zio.test._

object BlockchainRPCTest extends DefaultRunnableSpec {
  val spec = suite("BlockchainRPC")(
    testM("getBestBlockHash") {
      assertM(zrpc.getBestBlockHash)(isSubtype[DoubleSha256DigestBE](Assertion.anything))
    },
    testM("getBlock") {
      assertM(zrpc.getBlock(TestUtil.genesisBlockHash))(isSubtype[GetBlockResult](Assertion.anything))
    },
    testM("getBlockWithTransactions") {
      assertM(zrpc.getBlockWithTransactions(TestUtil.test1Hash))(
        isSubtype[GetBlockWithTransactionsResult](Assertion.anything)
      )
    },
    testM("getBlockchainInfo") {
      assertM(zrpc.getBlockChainInfo)(isSubtype[GetBlockChainInfoResult](Assertion.anything))
    },
    testM("getBlockCount") {
      assertM(zrpc.getBlockCount)(isSubtype[Int](Assertion.anything))
    },
    testM("getBlockHash") {
      assertM(zrpc.getBlockHash(1))(equalTo(TestUtil.genesisBlockHash))
    },
    testM("getBlockHeader") {
      assertM(zrpc.getBlockHeader(TestUtil.genesisBlockHash))(isSubtype[GetBlockHeaderResult](Assertion.anything))
    },
    testM("getBlockHeaderRaw") {
      assertM(zrpc.getBlockHeaderRaw(TestUtil.genesisBlockHash))(isSubtype[BlockHeader](Assertion.anything))
    },
    testM("getBlock") {
      assertM(zrpc.getBlockRaw(TestUtil.genesisBlockHash))(isSubtype[Block](Assertion.anything))
    },
    testM("getChainTips") {
      assertM(zrpc.getChainTips)(isSubtype[Vector[ChainTip]](Assertion.anything))
    }
  ).provideCustomLayerShared(TestUtil.instance) @@ TestAspect.sequential
}
