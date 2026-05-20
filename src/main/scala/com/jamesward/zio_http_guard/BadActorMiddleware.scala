package com.jamesward.zio_http_guard

import zio.*
import zio.direct.*
import zio.http.*
import zio.stream.ZStream

/**
 * `zio-http` middleware that pairs the [[BadActor]] detector with a request
 * pipeline:
 *
 *   1. Extract a client IP from the request (default: last value of
 *      `X-Forwarded-For`, falling back to `request.remoteAddress`).
 *   2. Decide whether the request looks "suspect" (default: WordPress / PHP
 *      probing patterns in the path).
 *   3. Call [[BadActor.checkReq]]. If the IP is now banned, fail the request
 *      with a slow random-byte stream (a tarpit) so the attacker burns time
 *      reading garbage.
 *
 * Apply with `routes @@ BadActorMiddleware()`.
 */
object BadActorMiddleware:

  private given CanEqual[BadActor.Status, BadActor.Status] = CanEqual.derived

  /**
   * Default IP extractor. Reads the **last** value of `X-Forwarded-For`,
   * which is conventionally what a single-hop reverse proxy (Heroku, Fly,
   * Cloud Run, single CDN) writes when it forwards to your origin. Falls
   * back to `request.remoteAddress` when the header is absent.
   *
   * Multi-hop deployments where the client-supplied `X-Forwarded-For` should
   * not be trusted will want to override this with a custom extractor that
   * picks the appropriate value (typically the first one your trust boundary
   * added).
   */
  def forwardedFor(request: Request): Option[BadActor.IP] =
    request.headers.get("X-Forwarded-For")
      .flatMap(_.split(",").lastOption.map(_.trim).filter(_.nonEmpty))
      .orElse(request.remoteAddress.map(_.getHostAddress))

  /**
   * Default "suspect request" predicate. Flags common WordPress / PHP
   * vulnerability-scanner shapes:
   *
   *   - any path ending in `.php`
   *   - any path containing `wp-includes`, `wp-admin`, or `wp-content`
   *
   * This is the dominant signal for opportunistic scanning against a small
   * Scala/JVM HTTP service. Override with your own predicate when serving
   * paths that legitimately contain those substrings.
   */
  val defaultSuspect: Request => Boolean = req =>
    val s = req.path.toString
    s.endsWith(".php") || s.contains("wp-includes") || s.contains("wp-admin") || s.contains("wp-content")

  /**
   * 30-second stream of 1KB random-byte chunks emitted at 10 chunks/sec.
   * Used as the body of the default banned-actor response: the connection
   * stays open and the client keeps reading useless data instead of moving
   * on to its next probe.
   */
  val gibberishStream: ZStream[Any, Nothing, Byte] =
    ZStream
      .repeatZIOWithSchedule(Random.nextBytes(1024), Schedule.fixed(100.millis))
      .flattenChunks
      .interruptAfter(30.seconds)

  /**
   * Default response for banned IPs: `200 OK` with `application/json`
   * Content-Type and a [[gibberishStream]] body. Returning `200` (rather
   * than `403` / `429`) is deliberate — a non-success status is a strong
   * signal to stop, but a `200` with garbage bytes keeps the scanner busy.
   */
  val gibberishResponse: Response =
    Response(
      status  = Status.Ok,
      body    = Body.fromStreamChunked(gibberishStream),
      headers = Headers(Header.ContentType(MediaType.application.json)),
    )

  /**
   * Build the bad-actor `HandlerAspect`.
   *
   * @param suspect        predicate that decides whether a request should
   *                       count toward the ban window. Defaults to
   *                       [[defaultSuspect]].
   * @param bannedResponse response served to a banned IP. Defaults to
   *                       [[gibberishResponse]].
   * @param extractIp      how to derive the client IP from a request.
   *                       Defaults to [[forwardedFor]]. If `None` is
   *                       returned the request is short-circuited with
   *                       `400 Bad Request` — there is no IP to track, so
   *                       letting it through would silently bypass the
   *                       guard.
   */
  def apply(
    suspect: Request => Boolean = defaultSuspect,
    bannedResponse: => Response = gibberishResponse,
    extractIp: Request => Option[BadActor.IP] = forwardedFor,
  ): HandlerAspect[BadActor, Unit] =
    HandlerAspect.interceptIncomingHandler:
      Handler.fromFunctionZIO[Request]: request =>
        extractIp(request) match
          case None =>
            ZIO.fail(Response.badRequest("could not determine client IP"))
          case Some(ip) =>
            defer:
              val isSuspect = suspect(request)
              val now = Clock.instant.run
              val status = ZIO.serviceWithZIO[BadActor](_.checkReq(ip, now, isSuspect)).run
              status match
                case BadActor.Status.Allowed =>
                  request -> ()
                case BadActor.Status.Banned =>
                  ZIO.logWarning(s"Bad actor detected: $ip").run
                  ZIO.fail(bannedResponse).run
