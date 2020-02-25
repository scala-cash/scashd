package org.scash.rpc.config

import java.io.{ File, FileNotFoundException }
import java.net.URI
import java.nio.file.{ Files, Paths }

import org.scash.core.config.NetworkParameters
import org.scash.core.util.BitcoinSLogger
import org.scash.rpc.client.common.{ BitcoindRpcClient, BitcoindVersion }

import scala.sys.process._
import org.scash.core.util.BitcoinSLogger
import org.scash.core.config.NetworkParameters
import org.scash.rpc.config.BitcoindAuthCredentials.{ CookieBased, PasswordBased }
import org.scash.rpc.util.AsyncUtil
import zio.{ UIO, ZIO }

import scala.util.{ Failure, Properties, Success }
import scala.concurrent.{ Future, Promise }

/**
 * Created by chris on 4/29/17.
 */
sealed trait BitcoindInstance extends BitcoinSLogger {

  require(binary.exists, s"bitcoind binary path (${binary.getAbsolutePath}) does not exist!")

  // would like to check .canExecute as well, but we've run into issues on some machines
  require(binary.isFile, s"bitcoind binary path (${binary.getAbsolutePath}) must be a file")

  /** The binary file that should get executed to start Bitcoin Core */
  def binary: File

  def datadir: File

  def network: NetworkParameters
  def uri: URI
  def rpcUri: URI
  def authCredentials: BitcoindAuthCredentials
  def zmqConfig: ZmqConfig

  def getVersion: BitcoindVersion = {

    val binaryPath = binary.getAbsolutePath

    val foundVersion =
      Seq(binaryPath, "--version").!!.split(Properties.lineSeparator).head
        .split(" ")
        .last

    foundVersion match {
      case _: String if foundVersion.equals(BitcoindVersion.Experimental.toString) =>
        BitcoindVersion.Experimental
      case _: String if foundVersion.startsWith(BitcoindVersion.V16.toString) =>
        BitcoindVersion.V16
      case _: String if foundVersion.startsWith(BitcoindVersion.V17.toString) =>
        BitcoindVersion.V17
      case _: String if foundVersion.startsWith(BitcoindVersion.V18.toString) =>
        BitcoindVersion.V18
      case _: String if foundVersion.startsWith(BitcoindVersion.V21.toString) =>
        BitcoindVersion.V21
      case _: String => BitcoindVersion.Unknown
    }
  }

  def p2pPort: Int = uri.getPort

  def start: UIO[Process] = {
    val binaryPath = binary.getAbsolutePath
    val cmd = List(
      binaryPath,
      "-datadir=" + datadir,
      "-rpcport=" + rpcUri.getPort,
      "-port=" + uri.getPort
    )

    logger.debug(s"starting bitcoind with datadir ${datadir} and binary path $binaryPath")
    ZIO.succeed(Process(cmd).run())
  }

}

object BitcoindInstance {
  private case class BitcoindInstanceImpl(
    network: NetworkParameters,
    uri: URI,
    rpcUri: URI,
    authCredentials: BitcoindAuthCredentials,
    zmqConfig: ZmqConfig,
    binary: File,
    datadir: File
  ) extends BitcoindInstance

  def apply(
    network: NetworkParameters,
    uri: URI,
    rpcUri: URI,
    authCredentials: BitcoindAuthCredentials,
    zmqConfig: ZmqConfig = ZmqConfig(),
    binary: File = DEFAULT_BITCOIND_LOCATION,
    datadir: File = BitcoindConfig.DEFAULT_DATADIR
  ): BitcoindInstance =
    BitcoindInstanceImpl(
      network,
      uri,
      rpcUri,
      authCredentials,
      zmqConfig = zmqConfig,
      binary = binary,
      datadir = datadir
    )

  lazy val DEFAULT_BITCOIND_LOCATION: File = {

    def findExecutableOnPath(name: String): Option[File] =
      sys.env
        .getOrElse("PATH", "")
        .split(File.pathSeparator)
        .map(directory => new File(directory, name))
        .find(file => file.isFile && file.canExecute)

    val cmd =
      if (Properties.isWin) {
        findExecutableOnPath("bitcoind.exe")
      } else {
        findExecutableOnPath("bitcoind")
      }

    cmd.getOrElse(throw new FileNotFoundException("Cannot find a path to bitcoind"))
  }

  /** Constructs a `bitcoind` instance from the given datadir, using the
   * `bitcoin.conf` found within (if any)
   *
   * @throws IllegalArgumentException if the given datadir does not exist
   */
  def fromDatadir(
    datadir: File = BitcoindConfig.DEFAULT_DATADIR,
    binary: File = DEFAULT_BITCOIND_LOCATION
  ): BitcoindInstance = {
    require(datadir.exists, s"${datadir.getPath} does not exist!")
    require(datadir.isDirectory, s"${datadir.getPath} is not a directory!")

    val configPath = Paths.get(datadir.getAbsolutePath, "bitcoin.conf")
    if (Files.exists(configPath)) {

      val file = configPath.toFile()
      fromConfigFile(file, binary)
    } else {
      fromConfig(BitcoindConfig.empty, binary)
    }
  }

  /**
   * Construct a `bitcoind` from the given config file. If no `datadir` setting
   * is found, the parent directory to the given file is used.
   *
   * @throws  IllegalArgumentException if the given config file does not exist
   */
  def fromConfigFile(
    file: File = BitcoindConfig.DEFAULT_CONF_FILE,
    binary: File = DEFAULT_BITCOIND_LOCATION
  ): BitcoindInstance = {
    require(file.exists, s"${file.getPath} does not exist!")
    require(file.isFile, s"${file.getPath} is not a file!")

    val conf = BitcoindConfig(file, file.getParentFile)

    fromConfig(conf, binary)
  }

  /** Constructs a `bitcoind` instance from the given config */
  def fromConfig(
    config: BitcoindConfig,
    binary: File = DEFAULT_BITCOIND_LOCATION
  ): BitcoindInstance = {

    val authCredentials = BitcoindAuthCredentials.fromConfig(config)
    BitcoindInstance(
      config.network,
      config.uri,
      config.rpcUri,
      authCredentials,
      zmqConfig = ZmqConfig.fromConfig(config),
      binary = binary,
      datadir = config.datadir
    )
  }
}
