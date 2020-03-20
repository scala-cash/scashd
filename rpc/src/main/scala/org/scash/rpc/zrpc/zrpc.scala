package org.scash.rpc.zrpc

import zio.Has

package object zrpc extends BlockchainRPC with NetworkRPC {
  type ZClient = Has[ZClient.Service]
}
