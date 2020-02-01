import sbt._

object Deps {
  object V {
    val bouncyCastle = "1.55"
    val logback = "1.0.13"
    val scalacheck = "1.14.0"
    val scalaTest = "3.0.5"
    val slf4j = "1.7.5"
    val spray = "1.3.2"
    val zeromq = "0.4.3"
    val akkav = "10.1.1"
    val akkaStreamv = "2.5.12"
    val playv = "2.6.9"
    val scalazv = "7.2.26"
    val scodecbitsv = "1.1.9"
    val junitv = "0.11"
    val zio = "1.0.0-RC17"
  }

  object Compile {
    val bouncycastle = "org.bouncycastle" % "bcprov-jdk15on" % V.bouncyCastle
    val scodec = "org.scodec" %% "scodec-bits" % V.scodecbitsv
    val slf4j = "org.slf4j" % "slf4j-api" % V.slf4j % "provided"
    val zeromq = "org.zeromq" % "jeromq" % V.zeromq
    val akkaHttp = "com.typesafe.akka" %% "akka-http" % V.akkav
    val akkaStream = "com.typesafe.akka" %% "akka-stream" % V.akkaStreamv
    val playJson = "com.typesafe.play" %% "play-json" % V.playv
    val scalaz = "org.scalaz" %% "scalaz-core" % V.scalazv withSources() withJavadoc()
    val zio = "dev.zio" %% "zio" % V.zio withSources() withJavadoc()
  }

  object Test {
    val bitcoinj = ("org.bitcoinj" % "bitcoinj-core" % "0.14.4" % "test").exclude("org.slf4j", "slf4j-api")
    val junitInterface = "com.novocode" % "junit-interface" % V.junitv % "test"
    val logback = "ch.qos.logback" % "logback-classic" % V.logback % "test"
    val scalacheck = "org.scalacheck" %% "scalacheck" % V.scalacheck % "test" withSources() withJavadoc()
    val scalaTest = "org.scalatest" %% "scalatest" % V.scalaTest % "test"
    val spray = "io.spray" %% "spray-json" % V.spray  % "test"
    val akkaHttp = "com.typesafe.akka" %% "akka-http-testkit" % V.akkav % "test"
    val akkaStream = "com.typesafe.akka" %% "akka-stream-testkit" % V.akkaStreamv % "test"
  }

  val core = List(
    Compile.bouncycastle,
    Compile.scodec,
    Compile.slf4j,
    Compile.scalaz
  )

  val coreGen = List(
    Compile.slf4j,
    Test.scalacheck
  )

  val coreTest = List(
    Test.bitcoinj,
    Test.junitInterface,
    Test.logback,
    Test.scalaTest,
    Test.spray
  )
  
  val rpc = List(
    Compile.akkaHttp,
    Compile.akkaStream,
    Compile.playJson,
    Compile.slf4j,
    Compile.zio,
    Test.akkaHttp,
    Test.akkaStream,
    Test.logback,
    Test.scalaTest,
    Test.scalacheck
  )
}
