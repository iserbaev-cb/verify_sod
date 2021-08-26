package nl.cleverbase.verify

import cats.effect.{ExitCode, IO, IOApp}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.cms.{SignerInformation, SignerInformationVerifier}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.http4s.HttpRoutes
import org.http4s.dsl.Http4sDsl
import org.http4s.dsl.io.{POST, _}
import org.http4s.implicits._
import org.http4s.server.blaze.BlazeServerBuilder

import java.io.FileInputStream
import java.security.cert.Certificate
import java.security.{KeyStore, Security}
import java.util
import java.util.Base64
import scala.util.{Success, Try}

object Main extends IOApp {

  Security.addProvider(new BouncyCastleProvider)

  private val kstore = {
    val ks = KeyStore.getInstance("BKS", "BC")
    ks.load(new FileInputStream("./masterList.JKS"), null)
    ks
  }

  def verify(text: String): IO[Boolean] = IO {
    new SOD(Base64.getDecoder.decode(text), kstore).verify()
  }

  override def run(args: List[String]): IO[ExitCode] = {
    val dsl = new Http4sDsl[IO] {}

    BlazeServerBuilder[IO]
      .bindHttp(9000, "0.0.0.0")
      .withHttpApp(
        HttpRoutes
          .of[IO] {
            case req @ POST -> Root / "validate" =>
              for {
                text  <- req.as[String]
                check <- verify(text)
                resp  <- if (check) Ok() else BadRequest()
              } yield resp
            case _ => Ok()
          }
          .orNotFound
      )
      .serve
      .compile
      .drain
      .as(ExitCode.Success)
  }
}
