name := "rpc-test"

libraryDependencies ++= Deps.rpcTest

testFrameworks += new TestFramework("zio.test.sbt.ZTestFramework")

/*
Test / test := (Test / test dependsOn {
  Projects.rpc / TaskKeys.downloadBitcoind
}).value
 */
