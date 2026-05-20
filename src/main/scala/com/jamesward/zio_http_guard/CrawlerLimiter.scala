package com.jamesward.zio_http_guard

import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*
import zio.http.*

import java.time.Instant

/**
 * Per-crawler "one active resource at a time" limiter.
 *
 * Each known crawler User-Agent gets a single slot. While a slot is held,
 * requests from that crawler for the **same** resource key (refresh the
 * slot) and requests from that crawler for paths with **no** key (homepage,
 * static assets, etc.) are allowed; requests for a **different** resource
 * key are denied with `429 Too Many Requests` until the slot's last access
 * is older than `hold`.
 *
 * The "resource key" is whatever you compute from the request — typically a
 * coarse grouping that maps to an expensive backend operation. Examples:
 *
 *   - a Maven `groupId/artifactId/version` triple, when each new triple
 *     triggers a fresh archive download + extraction
 *   - a tenant ID, when each new tenant warms an isolated cache
 *   - a date bucket, when each bucket spans a separate database shard
 *
 * Crawlers that don't legitimately need to walk the whole keyspace in
 * parallel (Googlebot et al.) will simply move on to a different page from
 * the same key while their slot is held; well-behaved crawlers absorb the
 * limit invisibly.
 *
 * @param active map from crawler User-Agent token to its currently held slot.
 */
final case class CrawlerLimiter[K](active: ConcurrentMap[String, CrawlerLimiter.Slot[K]]):

  /**
   * Try to claim or refresh `crawler`'s slot for `key`.
   *
   * Returns `true` (allow the request) if:
   *   - the crawler has no slot yet, or
   *   - the existing slot is for the same `key` (refreshes its
   *     `lastAccess`), or
   *   - the existing slot for a *different* key has been idle for at
   *     least `hold` (steals the slot).
   *
   * Returns `false` (deny) if the crawler currently holds a slot for a
   * different key and that slot is still within its `hold` window.
   */
  def tryClaim(crawler: String, key: K, hold: Duration)(using CanEqual[K, K]): UIO[Boolean] =
    defer:
      val now = Clock.instant.run
      val fresh = CrawlerLimiter.Slot(key, now)
      active.putIfAbsent(crawler, fresh).run match
        case None =>
          true
        case Some(existing) if existing.key == key =>
          // Refresh the timestamp. Last-writer-wins is fine — the value is
          // a coarse "recent activity" signal, not a counter.
          active.put(crawler, fresh).run
          true
        case Some(existing) =>
          val idle = java.time.Duration.between(existing.lastAccess, now)
          if idle.compareTo(hold.asJava) >= 0 then
            active.put(crawler, fresh).run
            true
          else
            false

object CrawlerLimiter:

  /** A held slot: which key the crawler last touched, and when. */
  final case class Slot[K](key: K, lastAccess: Instant)

  /**
   * User-Agent substrings (lowercase) for the crawlers we limit by default.
   * A request is "from a crawler" when its `User-Agent` (lowercased)
   * contains at least one of these substrings; the matched substring
   * becomes the slot key.
   *
   * The set leans toward bots that crawl aggressively against open
   * documentation/data sites: AI-training scrapers, SEO tools, generic
   * search bots. Override via the `knownCrawlers` parameter on
   * [[middleware]] / [[matchedCrawler]] for your own list.
   */
  val defaultKnownCrawlers: Set[String] = Set(
    "meta-externalagent",
    "semrushbot",
    "amazonbot",
    "petalbot",
    "dotbot",
    "bytespider",
    "gptbot",
    "claudebot",
    "bingbot",
    "googlebot",
    "yandexbot",
    "baiduspider",
    "ahrefsbot",
    "dataforseobot",
    "seznambot",
  )

  /**
   * Returns the matched crawler token (one of `knownCrawlers`) if the
   * request's `User-Agent` contains one, else `None`.
   */
  def matchedCrawler(
    request: Request,
    knownCrawlers: Set[String] = defaultKnownCrawlers,
  ): Option[String] =
    request.header(Header.UserAgent).flatMap: ua =>
      val lower = ua.renderedValue.toLowerCase
      knownCrawlers.find(lower.contains)

  /** Default hold window for a slot: 10 minutes of inactivity releases it. */
  val defaultHold: Duration = 10.minutes

  /** Build an empty limiter as a layer. */
  def layer[K: Tag]: ZLayer[Any, Nothing, CrawlerLimiter[K]] =
    ZLayer.fromZIO:
      ConcurrentMap.empty[String, Slot[K]].map(CrawlerLimiter[K](_))

  /**
   * Build the crawler-limiter `HandlerAspect`.
   *
   * Behaviour, per request:
   *
   *   - If the User-Agent doesn't match any of `knownCrawlers`, pass
   *     through.
   *   - If `resourceKey(request)` returns `None`, pass through. (Use this
   *     to exempt routes you don't want to rate-limit at all — robots.txt,
   *     sitemap, badges, the index page, etc.)
   *   - Otherwise call [[CrawlerLimiter.tryClaim]] and either pass through
   *     or fail the request with `429 Too Many Requests` plus
   *     `Retry-After: 60`.
   *
   * @param resourceKey   maps a request to its slot key (or `None` to
   *                      exempt the request from limiting).
   * @param hold          how long a slot stays held by a crawler after
   *                      its last access. Defaults to [[defaultHold]].
   * @param knownCrawlers User-Agent substrings that count as crawlers.
   *                      Defaults to [[defaultKnownCrawlers]].
   */
  def middleware[K](
    resourceKey: Request => Option[K],
    hold: Duration = defaultHold,
    knownCrawlers: Set[String] = defaultKnownCrawlers,
  )(using Tag[K], CanEqual[K, K]): HandlerAspect[CrawlerLimiter[K], Unit] =
    HandlerAspect.interceptIncomingHandler:
      Handler.fromFunctionZIO[Request]: request =>
        matchedCrawler(request, knownCrawlers) match
          case None =>
            ZIO.succeed(request -> ())
          case Some(crawler) =>
            resourceKey(request) match
              case None =>
                ZIO.succeed(request -> ())
              case Some(key) =>
                ZIO.serviceWithZIO[CrawlerLimiter[K]]: limiter =>
                  limiter.tryClaim(crawler, key, hold).flatMap:
                    case true =>
                      ZIO.succeed(request -> ())
                    case false =>
                      ZIO.fail(
                        Response
                          .status(Status.TooManyRequests)
                          .addHeader(Header.RetryAfter.ByDuration(1.minute))
                      )
