name := "scash"

libraryDependencies ++= Deps.core

testOptions in Test += Tests.Argument(TestFrameworks.ScalaCheck, "-verbosity", "2")

coverageExcludedPackages := ".*gen"

coverageMinimum := 80

coverageFailOnMinimum := true
