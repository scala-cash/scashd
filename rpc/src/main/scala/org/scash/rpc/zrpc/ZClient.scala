package org.scash.rpc.zrpc

import java.util.UUID

import org.scash.rpc.BitcoindException
import org.scash.rpc.zrpc.zrpc.ZClient
import play.api.libs.json._
import sttp.client.asynchttpclient.zio.AsyncHttpClientZioBackend
import sttp.client.playJson._
import sttp.client.{ asStringAlways, basicRequest }
import sttp.model.Uri
import zio.{ Managed, Task, ZLayer }

import scala.util.{ Failure, Success, Try }

object ZClient {
  trait Service {
    def bitcoindCall[A: Reads](cmd: String, parameters: List[JsValue] = List.empty): Task[A]
  }

  def make(
    uri: Uri,
    userName: String,
    password: String
  ): ZLayer[Any, Throwable, ZClient] =
    ZLayer.fromManaged(
      Managed.make(AsyncHttpClientZioBackend())(_.close().ignore).map { implicit sttp =>
        new ZClient.Service {
          def bitcoindCall[A: Reads](command: String, parameters: List[JsValue] = List.empty): Task[A] = {
            val payload = JsObject(
              Map(
                "method" -> JsString(command),
                "params" -> JsArray(parameters),
                "id"     -> JsString(UUID.randomUUID().toString)
              )
            )

            val response = for {
              r <- basicRequest
                    .response(asStringAlways.map(parseJson[A]))
                    .post(uri)
                    .body(payload)
                    .auth
                    .basic(userName, password)
                    .send()
            } yield r.body

            response.absolve
          }
        }
      }
    )

  private val resultKey: String = "result"
  private val errorKey: String  = "error"

  private def parseJson[A: Reads](json: String): Either[Throwable, A] =
    Try(Json.parse(json)) match {
      case Failure(e) => Left(e)
      case Success(js) => {
        val result = (js \ resultKey).validate[A]
        checkUnitError(result, js).getOrElse(
          result match {
            case JsSuccess(t, _) => Right(t)
            case _: JsError      => parseError(js)
          }
        )
      }
    }

  // Catches errors thrown by calls with Unit as the expected return type (which isn't handled by UnitReads)
  private def checkUnitError[A](
    result: JsResult[A],
    json: JsValue
  ): Option[Either[BitcoindException, Nothing]] =
    if (result == JsSuccess(())) {
      (json \ errorKey).validate[BitcoindException] match {
        case JsSuccess(err, _) => Some(Left(err))
        case _: JsError        => None
      }
    } else None

  private def parseError(js: JsValue) =
    (js \ "errorKey").validate[BitcoindException] match {
      case JsSuccess(err, _) => Left(err)
      case res: JsError =>
        val jsonResult = (js \ resultKey).get
        val errString =
          s"Error when parsing: ${JsError.toJson(res).toString}!"
        Left(
          new IllegalArgumentException(s"Could not parse JsResult: ${Json.prettyPrint(jsonResult)}! Error: $errString")
        )
    }
}
