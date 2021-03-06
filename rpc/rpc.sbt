import scala.util.Properties
import scala.collection.JavaConverters._
import scala.concurrent.{ Await, Future }
import scala.concurrent.duration.DurationInt
import java.nio.file.Files
import java.nio.file.Paths

name := "rpc"

libraryDependencies ++= Deps.rpc

dependsOn(Projects.core)

CommonSettings.prodSettings

/*
TaskKeys.downloadBitcoind := {
  val logger = streams.value.log
  import scala.sys.process._

  val binaryDir = Paths.get("binaries", "bitcoind")

  if (Files.notExists(binaryDir)) {
    logger.info(s"Creating directory for bitcoind binaries: $binaryDir")
    Files.createDirectories(binaryDir)
  }

  val versions = List("0.21.0")

  logger.debug(s"(Maybe) downloading Bitcoin ABC binaries for versions: ${versions.mkString(",")}")

  val (platFolder, platform, suffix) =
    if (Properties.isLinux) ("linux", "x86_64-linux-gnu", "tar.gz")
    else if (Properties.isMac) ("osx", "osx64", "tar.gz")
    else if (Properties.isWin) ("win", "win64", "zip")
    else sys.error(s"Unsupported OS: ${Properties.osName}")

  implicit val ec = scala.concurrent.ExecutionContext.global
  val downloads = versions.map { version =>
    val versionDir      = binaryDir resolve version
    val archiveLocation = binaryDir resolve s"$version.$suffix"
    val location =
      s"https://download.bitcoinabc.org/$version/$platFolder/bitcoin-abc-$version-$platform.$suffix"

    val expectedEndLocation = binaryDir resolve s"bitcoin-$version"

    if (Files
          .list(binaryDir)
          .iterator
          .asScala
          .map(_.toString)
          .exists(expectedEndLocation.toString.startsWith(_))) {
      logger.debug(s"Directory $expectedEndLocation already exists, skipping download of version $version")
      Future.unit
    } else {
      Future {
        logger.info(s"Downloading bitcoind version $version from location: $location")
        logger.info(s"Placing the file in $archiveLocation")
        val downloadCommand = url(location) #> archiveLocation.toFile
        downloadCommand.!!

        logger.info(s"Download complete, unzipping result")

        val extractCommand = s"tar -xzf $archiveLocation --directory $binaryDir"
        logger.info(s"Extracting archive with command: $extractCommand")
        extractCommand.!!

        logger.info(s"Deleting archive")
        Files.delete(archiveLocation)
      }

    }
  }

  //timeout if we cannot download in 120 seconds
  Await.result(Future.sequence(downloads), 120.seconds)
}
 */
