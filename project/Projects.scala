import sbt._

object Projects {
  val core = project in file("..") / "core"
  val rpc  = project in file("..") / "rpc"
}
