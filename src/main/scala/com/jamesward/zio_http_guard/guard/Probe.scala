package com.jamesward.zio_http_guard.guard

import zio.http.*

import java.util.Locale

/**
 * Requests for, or referred from, a probe path: by default a root-level
 * random-hex media file such as `/947870aad1.mkv`; [[Probe.suspectPath]]
 * matches secret, repository, dynamic-script, CMS and debug-endpoint probes.
 * Combine predicates with `||`, e.g.
 * `Probe.path(p => Probe.randomMedia(p) || Probe.suspectPath(p))`.
 */
object Probe:
  val pathName: DetectorName    = DetectorName("probe")
  val refererName: DetectorName = DetectorName("referer-probe")
  val pathReason: Reason        = Reason("probe")
  val refererReason: Reason     = Reason("referer-probe")

  /** A cheap `404` that doesn't advertise the guard. */
  val notFound: Response = Response.status(Status.NotFound)

  private val randomMediaName = "^[0-9a-f]{8,}\\.(avi|flac|flv|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|webm|webp|wmv)$".r

  val randomMedia: Path => Boolean = path =>
    path.segments.toList match
      case List(segment) => randomMediaName.matches(segment.toLowerCase(Locale.ROOT))
      case _             => false

  private val dynamicScriptMarkers   = Set(".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi")
  private val exposedFileNames       = Set("gemfile", "jenkinsfile", "laravel.log", "pipfile", "procfile")
  private val frameworkProbePrefixes = Set("__debug", "__nextjs")
  private val serverProbeSegments    = Set("actuator", "cgi-bin", "server-info", "server-status")
  private val wordpressSegments      = Set("wp-admin", "wp-config", "wp-content", "wp-includes", "wp-json")

  private def allowedDotSegment(segment: String, index: Int): Boolean =
    (index == 0 && segment == ".well-known") || segment == ".nojekyll"

  /**
   * Security-exposure and vulnerability-scanner shapes, matched
   * case-insensitively per path segment:
   *
   *   - hidden files/directories such as `.env`, `.git`, `.ssh` and `.npmrc`
   *     anywhere in the path (`/.well-known` and `.nojekyll` are allowed)
   *   - a final segment containing `.php`, `.aspx`, `.jsp`, `.cgi` etc.,
   *     including backup suffixes such as `shell.php.bak`
   *   - WordPress segments such as `wp-admin` and `wp-json`
   *   - shallow deployment/build files and root framework/debug endpoints
   *
   * Position and depth limits keep Maven group IDs such as `com.php` and
   * nested javadoc pages such as `Dockerfile.html` or `Actuator.html` from
   * matching.
   */
  val suspectPath: Path => Boolean = path =>
    val segments    = path.segments.map(_.toLowerCase(Locale.ROOT))
    val lastSegment = segments.lastOption
    val shallow     = segments.length <= 3
    segments.zipWithIndex.exists((segment, index) => segment.startsWith(".") && !allowedDotSegment(segment, index)) ||
      lastSegment.exists(segment => dynamicScriptMarkers.exists(segment.contains)) ||
      segments.exists(wordpressSegments.contains) ||
      segments.headOption.exists(_.startsWith("wordpress")) ||
      (shallow && lastSegment.exists(exposedFileNames.contains)) ||
      (shallow && lastSegment.exists(segment => segment.startsWith("dockerfile") && !segment.endsWith(".html"))) ||
      segments.headOption.exists(segment => frameworkProbePrefixes.exists(segment.startsWith)) ||
      segments.headOption.exists(serverProbeSegments.contains)

  /**
   * [[Tier.Confirmed]] for a probe path.
   *
   * @param response sent when the probe is blocked (default [[notFound]]);
   *                 `None` uses the configured block response.
   */
  def path(isProbe: Path => Boolean = randomMedia, response: Option[Response] = Some(notFound)): Detector =
    Detector.pure(pathName): (request, _) =>
      Option.when(isProbe(request.path))(Verdict(Tier.Confirmed, pathReason, response))

  /** [[Tier.Confirmed]] for a request whose `Referer` is a probe path. */
  def referer(isProbe: Path => Boolean = randomMedia): Detector =
    Detector.pure(refererName): (request, _) =>
      Option.when(request.header(Header.Referer).exists(r => isProbe(r.url.path)))(Verdict(Tier.Confirmed, refererReason))
