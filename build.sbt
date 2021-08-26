import sbtassembly.MergeStrategy

name := "verify_sod"

version := "0.1"

scalaVersion := "2.13.5"

idePackagePrefix := Some("nl.cleverbase.verify")

resolvers += Resolver.sonatypeRepo("snapshots")
val http4sVersion = "0.21.21"

libraryDependencies += "org.typelevel"    % "cats-core_2.13"   % "2.5.0"
libraryDependencies += "org.typelevel"    % "cats-effect_2.13" % "2.4.1"
libraryDependencies += "org.bouncycastle" % "bcpkix-jdk15on"   % "1.68"
libraryDependencies ++= Seq(
  "org.http4s"     %% "http4s-dsl"          % http4sVersion,
  "org.http4s"     %% "http4s-blaze-server" % http4sVersion,
  "org.http4s"     %% "http4s-blaze-client" % http4sVersion,
  "org.poreid"     % "poreid"               % "1.53",
  "ch.qos.logback" % "logback-classic"      % "1.2.3"
)

assemblyMergeStrategy in assembly := {
  case x if x.endsWith("/module-info.class") => MergeStrategy.discard
  case x =>
    val oldStrategy = (assemblyMergeStrategy in assembly).value
    oldStrategy(x)
}
