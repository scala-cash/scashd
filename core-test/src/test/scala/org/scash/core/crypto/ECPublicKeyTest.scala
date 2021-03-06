package org.scash.core.crypto

import org.bitcoinj.core.Sha256Hash
import org.scalatest.{ FlatSpec, MustMatchers }
import scodec.bits.ByteVector

/**
 * Created by chris on 2/29/16.
 */
class ECPublicKeyTest extends FlatSpec with MustMatchers {

  "ECPublicKey" must "verify that a arbitrary piece of data was signed by the private key corresponding to a public key" in {

    val privateKeyHex = "180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"
    val key: ECPrivateKey = ECPrivateKey(privateKeyHex)

    val hash = DoubleSha256Digest(ByteVector(Sha256Hash.ZERO_HASH.getBytes))
    val signature: ECDigitalSignature = key.signECDSA(hash)

    val isValid: Boolean = key.publicKey.verifyECDSA(ByteVector(Sha256Hash.ZERO_HASH.getBytes), signature)
    isValid must be(true)
  }

  it must "fail to verify a piece of data if the wrong public key is given" in {
    val privateKeyHex = "180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"
    val key: ECPrivateKey = ECPrivateKey(privateKeyHex)
    val hash = DoubleSha256Digest(ByteVector(Sha256Hash.ZERO_HASH.getBytes))
    val signature: ECDigitalSignature = key.signECDSA(hash)

    val wrongPublicKey = ECPublicKey.freshPublicKey
    val isValid: Boolean = wrongPublicKey.verifyECDSA(hash, signature)
    isValid must be(false)
  }

  it must "verify a piece of data signed with a bitcoinj private key" in {
    val bitcoinjPrivKey = new org.bitcoinj.core.ECKey
    val bitcoinjSignature = bitcoinjPrivKey.sign(Sha256Hash.ZERO_HASH)
    val bitcoinsSignature = ECDigitalSignature(ByteVector(bitcoinjSignature.encodeToDER()))
    val bitcoinsPublicKey = ECPublicKey(ByteVector(bitcoinjPrivKey.getPubKey))
    bitcoinsPublicKey.verifyECDSA(ByteVector(Sha256Hash.ZERO_HASH.getBytes), bitcoinsSignature) must be(true)

  }

  it must "verify a piece of data was signed with a scash private key inside of bitcoinj" in {
    val bitcoinsPrivKey = ECPrivateKey.freshPrivateKey
    val hash = DoubleSha256Digest(ByteVector(Sha256Hash.ZERO_HASH.getBytes))
    val bitcoinsSignature = bitcoinsPrivKey.signECDSA(hash)
    val bitcoinjPublicKey = org.bitcoinj.core.ECKey.fromPublicOnly(bitcoinsPrivKey.publicKey.bytes.toArray)
    bitcoinjPublicKey.verify(
      Sha256Hash.ZERO_HASH.getBytes,
      bitcoinsSignature.bytes.toArray) must be(true)
  }

}
