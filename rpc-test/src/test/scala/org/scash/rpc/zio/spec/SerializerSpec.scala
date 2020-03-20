package org.scash.rpc.zio.spec

import org.scash.rpc.jsonmodels.{ Bip9Softfork, GetBlockChainInfoResult, Softfork }
import org.scash.rpc.serializers.JsonSerializers._

import play.api.libs.json.Json

import zio.ZIO
import zio.test.Assertion.{ equalTo, isSubtype }
import zio.test._

object SerializerSpec extends DefaultRunnableSpec {
  val spec = suite("BitcoinRPC")(
    testM("GetBlockchainInfo") {
      val p = Json.parse("""{
            "chain": "main",
            "blocks": 568749,
            "headers": 568749,
            "bestblockhash": "0000000000000000056c84123ed3469668c95d302bb1f3a2c3da9471ed7ba95c",
            "difficulty": 188284050802.8465,
            "mediantime": 1549568282,
            "verificationprogress": 0.7179360160311195,
            "initialblockdownload": true,
            "chainwork": "000000000000000000000000000000000000000000ddd938dee0aae5f0722d82",
            "size_on_disk": 159089098034,
            "pruned": false,
            "softforks": {
              "minerfund": {
                "type": "bip9",
                "bip9": {
                  "status": "defined",
                  "start_time": 1573819200,
                  "timeout": 1589544000,
                  "since": 0
                },
                "active": false
              },
              "minerfundabc": {
                "type": "bip9",
                "bip9": {
                  "status": "defined",
                  "start_time": 1573819200,
                  "timeout": 1589544000,
                  "since": 0
                },
                "active": false
              }
            },
            "warnings": ""
            }""")

      assertM(ZIO.succeed(p.validate[GetBlockChainInfoResult].asOpt))(
        isSubtype[Some[GetBlockChainInfoResult]](Assertion.anything)
      )
    },
    testM("Softfork") {
      val p = Json.parse(
        """{
              "type": "bip9",
              "bip9": {
                "status": "defined",
                "start_time": 1573819200,
                "timeout": 1589544000,
                "since": 0
              },
              "active": false}"""
      )

      val r = Softfork("bip9", Bip9Softfork("defined", 1573819200, 1589544000, 0), false)
      assertM(ZIO.succeed(p.validate[Softfork].get))(equalTo(r))
    },
    testM("Bip9Softfork") {
      val e = Json.parse(
        """{ 
               "status" : "defined", 
               "start_time" : 1573819200, 
               "timeout" : 1589544000, 
               "since" : 0 
               }"""
      )

      val j = Json.fromJson[Bip9Softfork](e)
      val r = Bip9Softfork("defined", 1573819200, 1589544000, 0)

      ZIO.succeed(assert(j.get)(equalTo(r)))
    }
  )
}
