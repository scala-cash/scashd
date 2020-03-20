// these two imports are needed for sbt syntax to work
import sbt._
import sbt.Keys._

import scala.util.Properties

object CommonSettings {
  private val isCI = {
    sys.props
      .get("CI")
      .isDefined
  }

  lazy val settings: Seq[Setting[_]] = List(
    organization := "scash",
    homepage := Some(url("https://github.com/scala-cash/scash")),
    scalacOptions in Compile := compilerOpts(scalaVersion.value),
    //remove annoying import unused things in the scala console
    //https://stackoverflow.com/questions/26940253/in-sbt-how-do-you-override-scalacoptions-for-console-in-all-configurations
    scalacOptions in (Compile, console) ~= (_ filterNot (s =>
      s == "-Ywarn-unused-import"
        || s == "-Ywarn-unused"
      //for 2.13 -- they use different compiler opts
        || s == "-Xlint:unused"
    )),
    scalacOptions in (Test, console) := (scalacOptions in (Compile, console)).value,
    scalacOptions in Test := testCompilerOpts,
    Compile / compile / javacOptions ++= {
      if (isCI) {
        //jdk11 is used on CI, we need to use the --release flag to make sure
        //byte code is compatible with jdk 8
        //https://github.com/eclipse/jetty.project/issues/3244#issuecomment-495322586
        Seq("--release", "8")
      } else {
        Seq("-source", "1.8", "-target", "1.8")
      }
    },
    resolvers ++= Seq(
      Resolver.bintrayRepo("scala-cash", "io")
    ),
    //show full stack trace of failed tests
    testOptions in Test += Tests.Argument(TestFrameworks.ScalaTest, "-oF"),
    //show duration of tests
    testOptions in Test += Tests.Argument(TestFrameworks.ScalaTest, "-oD"),
    licenses += ("MIT", url("http://opensource.org/licenses/MIT")),
    // Travis has performance issues on macOS
    Test / parallelExecution := !(Properties.isMac && isCI)
  )

  private val commonCompilerOpts = {
    List(
      "-Xsource:2.12",
      "-target:jvm-1.8"
    )
  }

  //https://docs.scala-lang.org/overviews/compiler-options/index.html
  def compilerOpts(scalaVersion: String): Seq[String] =
    Seq(
      "-encoding",
      "UTF-8",
      "-unchecked",
      "-feature",
      "-deprecation",
      "-Ywarn-dead-code",
      "-Ywarn-value-discard",
      "-Ywarn-unused",
      "-unchecked",
      "-deprecation",
      "-feature",
      "-Xlint:unused"
    ) ++ commonCompilerOpts

  val testCompilerOpts: Seq[String] = commonCompilerOpts

  lazy val testSettings: Seq[Setting[_]] = Seq(
    publish / skip := true
  ) ++ settings

  lazy val prodSettings: Seq[Setting[_]] = settings
}
