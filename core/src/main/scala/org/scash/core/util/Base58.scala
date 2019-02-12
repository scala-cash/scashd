package org.scash.core.util

import org.scash.core.protocol.blockchain._
import org.scash.core.crypto.ECPrivateKey
import org.scash.core.protocol.blockchain.Base58Type._
import scodec.bits.ByteVector

import scala.util.{Failure, Success, Try}

/**
 * Created by chris on 5/16/16.
 * source of values: https://en.bitcoin.it/wiki/Base58Check_encoding
 */
object Base58 {

  /** Verifies a given [[Base58Type]] string against its checksum (last 4 decoded bytes). */
  def decodeCheck(input: String): Try[ByteVector] = ByteVector.fromBase58(input) match {
    case None => Failure(new IllegalArgumentException("Invalid input"))
    case Some(decoded) =>
      if (decoded.length < 4) Failure(new IllegalArgumentException("Invalid input"))
      else {
        val (data, checksum) = decoded.splitAt(decoded.length - 4)
        val actualChecksum = CryptoUtil.doubleSHA256(data).bytes.take(4)
        if (checksum == actualChecksum) Success(data)
        else Failure(new IllegalArgumentException("checksums don't validate"))
      }
  }
  /** Encodes a Hex string into its base58 representation. this call is unsafe so it can throw exceptions when invalid hex **/
  def fromValidHex(hex: String) = ByteVector.fromValidHex(hex).toBase58

  /** Takes in [[Base58Type]] string and returns sequence of Bytes **/
  def fromValidBase58(input: String) = ByteVector.fromValidBase58(input)

  /**
   * Determines if a string is a valid [[Base58Type]] string.
   * * Checks the validity of a [[Base58Type]] string. A [[Base58Type]] string must not contain ('0', 'O', 'l', 'I').
   * * If the string is an address: it must have a valid address prefix byte and  must be between 26-35 characters in length.
   * * If the string is a private key: it must have a valid private key prefix byte and must have a byte size of 32.
   * * If the string is a private key corresponding to a compressed public key, the 5th-to-last byte must be 0x01.
   *
   */
  def isValidBitcoinBase58(base58: String): Boolean = Try {
    (for {
      decoded <- ByteVector.fromBase58(base58)
      firstChar <- base58.headOption
      firstByte <- decoded.headOption
    } yield {
      val compressedPubKey = List('K', 'L', 'c').contains(firstChar)
      if (compressedPubKey) decoded(decoded.length - 5) == 0x01.toByte
      else if (isValidAddressPreFixByte(firstByte)) base58.length >= 26 && base58.length <= 35
      else if (isValidSecretKeyPreFixByte(firstByte)) ECPrivateKey.fromWIFToPrivateKey(base58).bytes.size == 32
      else false
    }).getOrElse(false)
  } match {
    case Failure(_) => false
    case Success(value) => value
  }

  /**
   * Checks if the string begins with an Address prefix byte/character.
   * ('1', '3', 'm', 'n', '2')
   */
  private def isValidAddressPreFixByte(byte: Byte): Boolean = {
    val validAddressPreFixBytes: ByteVector =
      MainNetChainParams.base58Prefixes(PubKeyAddress) ++ MainNetChainParams.base58Prefixes(ScriptAddress) ++
        TestNetChainParams.base58Prefixes(PubKeyAddress) ++ TestNetChainParams.base58Prefixes(ScriptAddress)
    validAddressPreFixBytes.toSeq.contains(byte)
  }

  /**
   * Checks if the string begins with a private key prefix byte/character.
   * ('5', '9', 'c')
   */
  private def isValidSecretKeyPreFixByte(byte: Byte): Boolean = {
    val validSecretKeyPreFixBytes: ByteVector =
      MainNetChainParams.base58Prefixes(SecretKey) ++ TestNetChainParams.base58Prefixes(SecretKey)
    validSecretKeyPreFixBytes.toSeq.contains(byte)
  }
}
