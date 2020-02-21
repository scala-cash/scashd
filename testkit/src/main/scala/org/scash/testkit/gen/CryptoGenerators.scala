package org.scash.testkit.gen

import org.scalacheck.Gen
import org.scash.core.crypto._
import org.scash.core.script.crypto.SigHashType
import org.scash.core.util.CryptoUtil

/**
 * Created by chris on 6/22/16.
 */
sealed abstract class CryptoGenerators {

  def privateKey: Gen[ECPrivateKey] = Gen.delay(ECPrivateKey())

  /**
   * Generate a sequence of private keys
   * @param num maximum number of keys to generate
   * @return
   */
  def privateKeySeq(num: Int): Gen[Seq[ECPrivateKey]] = Gen.listOfN(num, privateKey)

  /**
   * Generates a sequence of private keys, and determines an amount of 'required' private keys
   * that a transaction needs to be signed with
   * @param num the maximum number of keys to generate
   * @return
   */
  def privateKeySeqWithRequiredSigs(num: Int): Gen[(Seq[ECPrivateKey], Int)] =
    if (num <= 0) {
      Gen.const(Nil, 0)
    } else {
      val privateKeys = privateKeySeq(num)
      for {
        keys         <- privateKeys
        requiredSigs <- Gen.choose(0, keys.size - 1)
      } yield (keys, requiredSigs)
    }

  /**
   * Generates a random number of private keys less than the max public keys setting in [[ScriptSettings]]
   * also generates a random 'requiredSigs' number that a transaction needs to be signed with
   */
  def privateKeySeqWithRequiredSigs: Gen[(Seq[ECPrivateKey], Int)] =
    for {
      num                 <- Gen.choose(0, 15)
      keysAndRequiredSigs <- privateKeySeqWithRequiredSigs(num)
    } yield keysAndRequiredSigs

  /** A generator with 7 or less private keys -- useful for creating smaller scripts */
  def smallPrivateKeySeqWithRequiredSigs: Gen[(Seq[ECPrivateKey], Int)] =
    for {
      num                 <- Gen.choose(0, 7)
      keysAndRequiredSigs <- privateKeySeqWithRequiredSigs(num)
    } yield keysAndRequiredSigs

  /** Generates a random public key */
  def publicKey: Gen[ECPublicKey] =
    for {
      privKey <- privateKey
    } yield privKey.publicKey

  /** Generates a random digital signature */
  def digitalSignature: Gen[ECDigitalSignature] =
    for {
      privKey <- privateKey
      hash    <- CryptoGenerators.doubleSha256Digest
    } yield privKey.signECDSA(hash)

  def sha256Digest: Gen[Sha256Digest] = StringGenerators.hexString.map(CryptoUtil.sha256)

  /** Generates a random [[DoubleSha256Digest]] */
  def doubleSha256Digest: Gen[DoubleSha256Digest] =
    for {
      key    <- privateKey
      digest = CryptoUtil.doubleSHA256(key.bytes)
    } yield digest

  /**
   * Generates a sequence of [[DoubleSha256Digest]]
   * @param num the number of digets to generate
   * @return
   */
  def doubleSha256DigestSeq(num: Int): Gen[Seq[DoubleSha256Digest]] = Gen.listOfN(num, doubleSha256Digest)

  /** Generates a random [[Sha256Hash160Digest]] */
  def sha256Hash160Digest: Gen[Sha256Hash160Digest] =
    for {
      pubKey <- publicKey
      hash   = CryptoUtil.sha256Hash160(pubKey.bytes)
    } yield hash

  /** Generates a random [[SigHashType]] with forkid for BCH txs */
  def bchHashType: Gen[SigHashType] = Gen.oneOf(SigHashType.bchHashTypes)

  def extVersion: Gen[ExtKeyVersion] = Gen.oneOf(MainNetPriv, MainNetPub, TestNet3Priv, TestNet3Pub)

  /** Generates an [[ExtPrivateKey]] */
  def extPrivateKey: Gen[ExtPrivateKey] =
    for {
      version <- Gen.oneOf(MainNetPriv, TestNet3Priv)
      ext     = ExtPrivateKey(version)
    } yield ext

  def extPublicKey: Gen[ExtPublicKey] = extPrivateKey.map(_.extPublicKey)

  def extKey: Gen[ExtKey] = Gen.oneOf(extPrivateKey, extPublicKey)

}

object CryptoGenerators extends CryptoGenerators