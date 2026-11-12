package com.jamesward.zio_http_guard.guard

import zio.*
import zio.http.*

/** Identifying the client behind a request, and logging what identifies it. */
object ClientId:

  /**
   * The client IP: the `trustedHops`-th value from the end of
   * `X-Forwarded-For` (each trusted proxy appends the address it saw; on
   * Heroku the router is the only one, so `1` gives the last value). Earlier
   * values are client-supplied and spoofable. Falls back to the socket
   * address when the header is absent.
   */
  def forwardedFor(trustedHops: Int)(request: Request): Option[ClientIp] =
    request.headers.get("X-Forwarded-For")
      .flatMap: header =>
        val hops = header.split(',').toList.map(_.trim).filter(_.nonEmpty)
        hops.lift(hops.size - trustedHops.max(1))
      .orElse(request.remoteAddress.map(_.getHostAddress.nn))
      .map(ClientIp(_))

  /**
   * Request headers to pass to `Middleware.requestLogging`: who the client
   * claims to be, and the headers a real browser sends but a script copying
   * a browser User-Agent often doesn't, or gets inconsistent.
   */
  val identifyingHeaders: Set[Header.HeaderTypeBase] = Set(
    Header.UserAgent,
    Header.Referer,
    Header.Accept,
    Header.AcceptLanguage,
    Header.AcceptEncoding,
    Header.SchemaHeaderType[String]("X-Forwarded-For"),
    Header.SchemaHeaderType[String]("Sec-Fetch-Site"),
    Header.SchemaHeaderType[String]("Sec-Fetch-Mode"),
    Header.SchemaHeaderType[String]("Sec-Fetch-Dest"),
    Header.SchemaHeaderType[String]("Sec-CH-UA"),
    Header.SchemaHeaderType[String]("Sec-CH-UA-Platform"),
  )

  /**
   * Annotates every log line of a request (including lines from fibers it
   * forks) with `client_ip`. Apply outermost so the request logger's line
   * carries it too.
   */
  def annotate(trustedHops: Int = 1): Middleware[Any] =
    Middleware.logAnnotate: request =>
      forwardedFor(trustedHops)(request).map(ip => LogAnnotation("client_ip", ip.value)).toSet
