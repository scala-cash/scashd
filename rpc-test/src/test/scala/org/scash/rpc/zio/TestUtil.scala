package org.scash.rpc.zio

import org.scash.core.crypto.DoubleSha256DigestBE
import org.scash.rpc.zrpc.ZClient
import sttp.client._
import zio.test.TestFailure

object TestUtil {

  val test1Hash        = DoubleSha256DigestBE("000000000000000002010fbeac4ccbb5ad3abafe684228219134bb5354978644")
  val genesisBlockHash = DoubleSha256DigestBE("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048")

  val instance = ZClient
    .make(uri"http://127.0.0.1:8332", "user", "password")
    .mapError(error => TestFailure.fail(error))
}
