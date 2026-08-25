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
 *   2. Decide whether the request looks "suspect" (default: common secret,
 *      repository, dynamic-script, CMS, and debug-endpoint probe shapes).
 *   3. Record suspect requests with [[BadActor.checkReq]]. A first-seen probe
 *      is rejected immediately with a cheap `404`, before protected work runs.
 *   4. Once the IP is banned, replace the `404` with a slow random-byte stream
 *      (a tarpit) so the attacker burns time reading garbage.
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
   * Default "suspect request" predicate. Flags common security-exposure and
   * vulnerability-scanner shapes that a JVM documentation service should
   * never need to resolve upstream:
   *
   *   - hidden files/directories such as `.env`, `.env.production`, `.git`,
   *     `.ssh`, and `.npmrc`, wherever they occur in the path (`.well-known`
   *     and `.nojekyll` remain allowed)
   *   - a final segment containing a dynamic-script marker such as `.php`,
   *     `.aspx`, `.jsp`, or `.cgi`, including backup suffixes
   *   - WordPress path prefixes such as `wp-admin` and `wp-json`
   *   - shallow deployment/build files and root framework/debug endpoints
   *
   * Matching is case-insensitive and works on individual path segments, not
   * only complete paths. Position/depth constraints avoid treating Maven
   * group IDs such as `com.php` or nested javadoc files such as
   * `Dockerfile.html` as probes. Override the predicate when a service
   * intentionally exposes another matching shape.
   */
  private val dynamicScriptMarkers = Set(".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi")
  private val exposedFileNames = Set(
    "gemfile",
    "jenkinsfile",
    "laravel.log",
    "pipfile",
    "procfile",
  )
  private val frameworkProbePrefixes = Set("__debug", "__nextjs")
  private val serverProbeSegments = Set("actuator", "cgi-bin", "server-info", "server-status")
  private val wordpressSegments = Set("wp-admin", "wp-config", "wp-content", "wp-includes", "wp-json")

  private def allowedDotSegment(segment: String, index: Int): Boolean =
    (index == 0 && segment == ".well-known") || segment == ".nojekyll"

  val defaultSuspect: Request => Boolean = req =>
    val segments = req.path.segments.map(_.toLowerCase(java.util.Locale.ROOT))
    val lastSegment = segments.lastOption
    segments.zipWithIndex.exists((segment, index) =>
      segment.startsWith(".") && !allowedDotSegment(segment, index)
    ) ||
      lastSegment.exists(segment => dynamicScriptMarkers.exists(segment.contains)) ||
      segments.exists(wordpressSegments.contains) ||
      segments.headOption.exists(_.startsWith("wordpress")) ||
      (segments.length <= 3 && lastSegment.exists(exposedFileNames.contains)) ||
      (segments.length <= 3 && lastSegment.exists(segment => segment.startsWith("dockerfile") && !segment.endsWith(".html"))) ||
      segments.headOption.exists(segment => frameworkProbePrefixes.exists(segment.startsWith)) ||
      segments.headOption.exists(serverProbeSegments.contains)

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
   *                       [[defaultSuspect]]. Suspect requests are rejected
   *                       immediately, before the protected handler runs.
   * @param bannedResponse response served to a banned IP. Defaults to
   *                       [[gibberishResponse]].
   * @param extractIp      how to derive the client IP from a request.
   *                       Defaults to [[forwardedFor]]. If `None` is
   *                       returned the request is short-circuited with
   *                       `400 Bad Request` — there is no IP to track, so
   *                       letting it through would silently bypass the
   *                       guard.
   * @param suspectResponse response served to a suspect request before its
   *                        IP reaches the ban threshold. Defaults to a cheap
   *                        `404 Not Found`, avoiding protected work without
   *                        advertising the guard.
   */
  def apply(
    suspect: Request => Boolean = defaultSuspect,
    bannedResponse: => Response = gibberishResponse,
    extractIp: Request => Option[BadActor.IP] = forwardedFor,
    suspectResponse: => Response = Response.status(Status.NotFound),
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
                case BadActor.Status.Allowed if isSuspect =>
                  ZIO.fail(suspectResponse).run
                case BadActor.Status.Allowed =>
                  request -> ()
                case BadActor.Status.Banned =>
                  ZIO.logWarning(s"Bad actor detected: $ip").run
                  ZIO.fail(bannedResponse).run
