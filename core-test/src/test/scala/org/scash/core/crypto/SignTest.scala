package org.scash.core.crypto

import org.scalatest.prop.PropertyChecks
import org.scalatest.{FlatSpec, MustMatchers}
import org.scash.testkit.gen.CryptoGenerators
import scodec.bits.ByteVector

import scala.concurrent.{ExecutionContext, Future}

class SignTest extends FlatSpec with MustMatchers with PropertyChecks {
  implicit val ec = ExecutionContext.global

  //ECPrivateKey implements the sign interface
  //so just use it for testing purposes
  val signTestImpl = new Sign {
    private val key = ECPrivateKey.freshPrivateKey
    def signECDSAFunction: ByteVector => Future[ECDigitalSignature] = key.signECDSAFunction
    def signECDSA(bytes: ByteVector): ECDigitalSignature = key.signECDSA(bytes)
    def signSchnorrFunction: ByteVector => Future[SchnorrSignature] = key.signSchnorrFunction
    def signSchnorr(bytes: ByteVector): SchnorrSignature = key.signSchnorr(bytes)
    def publicKey: ECPublicKey = key.publicKey
  }

  it must "ECDSA sign arbitrary pieces of data correctly" in {
    forAll(CryptoGenerators.sha256Digest) {
      case hash: Sha256Digest =>
        val pubKey = signTestImpl.publicKey
        val sigF = signTestImpl.signECDSAFunction(hash.bytes)

        sigF.map(sig => assert(pubKey.verifyECDSA(hash, sig)))

    }
  }

  it must "schnorr sign arbitrary pieces of data correctly" in {
    forAll(CryptoGenerators.sha256Digest) {
      case hash: Sha256Digest =>
        val pubKey = signTestImpl.publicKey
        val sigF = signTestImpl.signSchnorrFunction(hash.bytes)

        sigF.map(sig => assert(pubKey.verifySchnorr(hash, sig)))
    }
  }

}
