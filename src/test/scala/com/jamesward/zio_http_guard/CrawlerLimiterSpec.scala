package com.jamesward.zio_http_guard

import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*
import zio.http.*
import zio.test.*

/**
 * Tests the per-crawler resource limiter in isolation. The limiter's slot
 * is released solely by inactivity (`hold`) — there is no external eviction
 * to coordinate with.
 *
 * Uses `String` as the resource-key type to keep the test free of any
 * domain types; the original GAV-shaped use case in `javadoccentral` works
 * the same way with `MavenCentral.GroupArtifactVersion`.
 */
object CrawlerLimiterSpec extends ZIOSpecDefault:

  private val res1: String = "g:one:1"
  private val res2: String = "g:two:1"
  private val crawler = "googlebot"
  private val hold = 10.minutes

  private val makeLimiter: ZIO[Any, Nothing, CrawlerLimiter[String]] =
    ConcurrentMap.empty[String, CrawlerLimiter.Slot[String]].map(CrawlerLimiter[String](_))

  def spec = suite("CrawlerLimiter")(

    test("first request for a crawler claims the slot"):
      defer:
        val limiter = makeLimiter.run
        val allowed = limiter.tryClaim(crawler, res1, hold).run
        assertTrue(allowed)
    ,

    test("same crawler requesting the same resource keeps getting allowed"):
      defer:
        val limiter = makeLimiter.run
        val first  = limiter.tryClaim(crawler, res1, hold).run
        val second = limiter.tryClaim(crawler, res1, hold).run
        val third  = limiter.tryClaim(crawler, res1, hold).run
        assertTrue(first, second, third)
    ,

    test("same crawler requesting a different resource gets denied while slot is active"):
      defer:
        val limiter = makeLimiter.run
        val first  = limiter.tryClaim(crawler, res1, hold).run
        val second = limiter.tryClaim(crawler, res2, hold).run
        assertTrue(first, !second)
    ,

    test("different crawlers have independent slots"):
      defer:
        val limiter = makeLimiter.run
        val bot1 = limiter.tryClaim("bot1", res1, hold).run
        val bot2 = limiter.tryClaim("bot2", res2, hold).run
        assertTrue(bot1, bot2)
    ,

    test("slot is released after `hold` of inactivity"):
      defer:
        val limiter = makeLimiter.run
        limiter.tryClaim(crawler, res1, hold).run
        // Blocked on a different resource while the slot is active.
        val beforeHold = limiter.tryClaim(crawler, res2, hold).run
        TestClock.adjust(hold + 1.second).run
        // After the hold elapses with no res2 traffic claiming it, the
        // crawler is free to move on.
        val afterHold = limiter.tryClaim(crawler, res2, hold).run
        assertTrue(!beforeHold, afterHold)
    ,

    test("repeat hits to the same resource refresh the hold window"):
      defer:
        val limiter = makeLimiter.run
        limiter.tryClaim(crawler, res1, hold).run
        // Stay inside the hold, but advance most of the way.
        TestClock.adjust(hold.minus(1.second)).run
        limiter.tryClaim(crawler, res1, hold).run // refresh
        TestClock.adjust(hold.minus(1.second)).run
        // Total elapsed ~ 2 * (hold - 1s), well past `hold`, but the
        // mid-way refresh keeps the slot held → res2 still denied.
        val blocked = limiter.tryClaim(crawler, res2, hold).run
        assertTrue(!blocked)
    ,

    test("matchedCrawler matches User-Agent substrings, case-insensitive"):
      val realCrawler = Request.get("/").addHeader("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
      val notACrawler = Request.get("/").addHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) FakeBot/1.0")
      assertTrue(
        CrawlerLimiter.matchedCrawler(realCrawler).contains("googlebot"),
        CrawlerLimiter.matchedCrawler(notACrawler).isEmpty,
      )
    ,

    test("matchedCrawler returns None when User-Agent header is missing"):
      val req = Request.get("/")
      assertTrue(CrawlerLimiter.matchedCrawler(req).isEmpty)

  )
