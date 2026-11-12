package com.jamesward.zio_http_guard.guard

import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*
import zio.http.*

import java.time.Instant
import java.util.Locale

/**
 * Many distinct clients requesting the same key within a short window: the
 * signature of a flood that fans each URL out to many proxies. Requests
 * from the `distinctClients`-th client onward are [[Tier.Confirmed]].
 * Settings: `<PREFIX>_SWARM_WINDOW` (default 5s), `<PREFIX>_SWARM_CLIENTS`
 * (default 4).
 */
object Swarm:
  val name: DetectorName = DetectorName("swarm")
  val reason: Reason     = Reason("swarm")

  final case class Settings(window: Duration = 5.seconds, distinctClients: Int = 4) derives CanEqual

  def settings(prefix: String = "GUARD", defaults: Settings = Settings()): Config[Settings] =
    (Config.duration(s"${prefix}_SWARM_WINDOW").withDefault(defaults.window) ++
      Config.int(s"${prefix}_SWARM_CLIENTS").withDefault(defaults.distinctClients)).map(Settings(_, _))

  private type Hits = ConcurrentMap[String, Chunk[(Instant, ClientIp)]]

  /** Records the request and returns how many distinct clients requested `k` within the window. */
  private def distinctClients(hits: Hits, window: Duration, k: String, client: ClientIp): UIO[Int] =
    Clock.instant.flatMap: now =>
      hits.compute(k, (_, existing) => Some(existing.getOrElse(Chunk.empty).filter((at, _) => isRecent(at, now, window)) :+ (now -> client)))
        .map(_.fold(0)(_.map(_._2).distinct.size))

  /** @param key what counts as "the same thing" (e.g. the path), or `None` to skip a request. */
  def make(settings: Settings, key: Request => Option[String]): ZIO[Scope, Nothing, Detector] =
    defer:
      val hits = ConcurrentMap.empty[String, Chunk[(Instant, ClientIp)]].run
      val sweep = Clock.instant.flatMap(now => hits.removeIf((_, h) => h.forall((at, _) => !isRecent(at, now, settings.window))))
      sweep.repeat(Schedule.spaced(settings.window.max(1.second) * 6)).forkScoped.run
      Detector(name, (request, client) =>
        ZIO.foreach(key(request))(distinctClients(hits, settings.window, _, client))
          .map(_.filter(_ >= settings.distinctClients).map(_ => Verdict(Tier.Confirmed, reason)))
      )

/**
 * Who a client is for rate limiting: a declared crawler by its User-Agent
 * token, so one budget covers all of its IPs (crawlers rotate through many,
 * e.g. `meta-externalagent` used 56 addresses in 3.5 minutes), and anyone
 * else by IP.
 */
opaque type ClientKey = String
object ClientKey:
  def apply(key: String): ClientKey = key
  extension (key: ClientKey) def value: String = key
  given CanEqual[ClientKey, ClientKey] = CanEqual.derived

  /** Every client by IP. */
  val ip: (Request, ClientIp) => ClientKey = (_, client) => client.value

  /** A declared crawler (see [[Crawler.identify]]) as `crawler:<token>`, anyone else by IP. */
  def crawlerOrIp(known: Set[String] = Crawler.known): (Request, ClientIp) => ClientKey =
    (request, client) => Crawler.identify(request, known).fold(client.value)(token => s"crawler:$token")

/** Crawlers that name themselves in their User-Agent. */
object Crawler:
  /**
   * Lower-case User-Agent tokens of crawlers that walk whole sites: search
   * engines, SEO tools and AI crawlers. Anyone can send these, so a crawler
   * budget keyed by them can be spent by an impostor; the alternative, keying
   * by IP, gives a crawler that rotates addresses no limit at all.
   */
  val known: Set[String] = Set(
    "googlebot", "bingbot", "applebot", "yandexbot", "baiduspider", "seznambot", "petalbot",
    "duckduckbot", "meta-externalagent", "facebookexternalhit", "amazonbot", "bytespider",
    "gptbot", "oai-searchbot", "claudebot", "perplexitybot", "ccbot",
    "semrushbot", "ahrefsbot", "dotbot", "mj12bot", "dataforseobot", "serankingbacklinksbot", "shapbot",
  )

  /** The first `known` token the User-Agent contains (case-insensitive), if any. */
  def identify(request: Request, known: Set[String] = known): Option[String] =
    request.headers.get(Header.UserAgent.name).flatMap: ua =>
      val lower = ua.toLowerCase(Locale.ROOT)
      known.find(lower.contains)

/**
 * A per-client limit on how many *costly* keys (e.g. GAVs not cached yet)
 * a client may request per window. Requests over the limit get a `429` +
 * `Retry-After` ([[Tier.Confirmed]], but without flagging the client, so its
 * other requests still pass). Who counts as one client is `clientKey`: by
 * default the IP; [[ClientKey.crawlerOrIp]] gives each declared crawler one
 * budget across all its IPs. Settings: `<PREFIX>_NEW_KEYS_PER_CLIENT`
 * (default 30), `<PREFIX>_NEW_KEYS_WINDOW` (default 10m).
 */
object NewKeyPerClient:
  val name: DetectorName = DetectorName("new-key")
  val reason: Reason     = Reason("new-key")

  final case class Settings(perClient: Int = 30, window: Duration = 10.minutes) derives CanEqual

  def settings(prefix: String = "GUARD", defaults: Settings = Settings()): Config[Settings] =
    (Config.int(s"${prefix}_NEW_KEYS_PER_CLIENT").withDefault(defaults.perClient) ++
      Config.duration(s"${prefix}_NEW_KEYS_WINDOW").withDefault(defaults.window)).map(Settings(_, _))

  /**
   * @param key       the resource a request would cost, or `None` if it's free.
   * @param isCostly  whether that key is costly right now (e.g. not in the cache).
   * @param clientKey who shares a budget (default: the IP).
   */
  def make[K](
    settings: Settings,
    key: Request => Option[K],
    isCostly: K => UIO[Boolean],
    clientKey: (Request, ClientIp) => ClientKey = ClientKey.ip,
  ): ZIO[Scope, Nothing, Detector] =
    val limited = Response(
      Status.TooManyRequests,
      Headers(Header.RetryAfter.ByDuration(settings.window.dividedBy(2))),
      Body.fromString("Too many new resources requested; try again later."),
    )
    defer:
      val recent = ConcurrentMap.empty[ClientKey, Ref[Chunk[Instant]]].run
      sweep(recent, settings.window).repeat(Schedule.spaced(1.minute)).forkScoped.run
      Detector(name, (request, client) =>
        ZIO.foreach(key(request)): k =>
          isCostly(k).flatMap:
            case false => ZIO.none
            case true  =>
              tryNew(recent, settings, clientKey(request, client)).map: allowed =>
                Option.unless(allowed)(Verdict(Tier.Confirmed, reason, Some(limited), flag = false))
        .map(_.flatten)
      )

  private type Recent = ConcurrentMap[ClientKey, Ref[Chunk[Instant]]]

  private def sweep(recent: Recent, window: Duration): UIO[Unit] =
    Clock.instant.flatMap: now =>
      recent.toChunk.flatMap: entries =>
        ZIO.foreachDiscard(entries): (client, ref) =>
          ref.get.flatMap(times => recent.remove(client, ref).when(times.forall(!isRecent(_, now, window))))

  /** True if the client is under the limit, recording this request. */
  private def tryNew(recent: Recent, settings: Settings, client: ClientKey): UIO[Boolean] =
    defer:
      val now   = Clock.instant.run
      val fresh = Ref.make(Chunk.empty[Instant]).run
      val ref   = recent.putIfAbsent(client, fresh).run.getOrElse(fresh)
      ref.modify: times =>
        val live = times.filter(isRecent(_, now, settings.window))
        if live.size < settings.perClient then (true, live :+ now) else (false, live)
      .run

/** Requests for, or referred from, a probe path (by default a root-level random-hex media file such as `/947870aad1.mkv`). */
object Probe:
  val pathName: DetectorName    = DetectorName("probe")
  val refererName: DetectorName = DetectorName("referer-probe")
  val pathReason: Reason        = Reason("probe")
  val refererReason: Reason     = Reason("referer-probe")

  private val randomMediaName = "^[0-9a-f]{8,}\\.(avi|flac|flv|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|webm|webp|wmv)$".r

  val randomMedia: Path => Boolean = path =>
    path.segments.toList match
      case List(segment) => randomMediaName.matches(segment.toLowerCase(Locale.ROOT))
      case _             => false

  def path(isProbe: Path => Boolean = randomMedia): Detector =
    Detector.pure(pathName): (request, _) =>
      Option.when(isProbe(request.path))(Verdict(Tier.Confirmed, pathReason))

  def referer(isProbe: Path => Boolean = randomMedia): Detector =
    Detector.pure(refererName): (request, _) =>
      Option.when(request.header(Header.Referer).exists(r => isProbe(r.url.path)))(Verdict(Tier.Confirmed, refererReason))

/**
 * A Chrome-family User-Agent whose client hints contradict it. Real Chrome
 * never sends a `sec-ch-ua` version different from its User-Agent's
 * ([[Tier.Confirmed]] `client-hint-mismatch`), and sends `sec-ch-ua` on every
 * HTTPS request, though privacy tools can strip it ([[Tier.Suspect]]
 * `client-hint-missing`).
 */
object ClientHints:
  val name: DetectorName    = DetectorName("client-hints")
  val mismatch: Reason      = Reason("client-hint-mismatch")
  val missing: Reason       = Reason("client-hint-missing")

  private val uaChrome    = "Chrome/(\\d+)".r
  private val hintVersion = "\"(?:Chromium|Google Chrome|Microsoft Edge)\";v=\"(\\d+)\"".r

  val detector: Detector =
    Detector.pure(name): (request, _) =>
      val uaVersion = request.headers.get(Header.UserAgent.name).flatMap(uaChrome.findFirstMatchIn).map(_.group(1))
      uaVersion.flatMap: version =>
        request.headers.get("Sec-CH-UA") match
          case None => Some(Verdict(Tier.Suspect, missing))
          case Some(hints) =>
            val hinted = hintVersion.findAllMatchIn(hints).map(_.group(1)).toSet
            Option.when(hinted.nonEmpty && !hinted.contains(version))(Verdict(Tier.Confirmed, mismatch))
