package com.jamesward.zio_http_guard

import com.jamesward.zio_http_guard.BadActor.Status.*
import zio.*
import zio.direct.*
import zio.test.*

import java.time.Instant

object BadActorSpec extends ZIOSpecDefault:

  // Wrap `BadActor.checkReq` for terser test bodies.
  private def check(ip: BadActor.IP, instant: Instant, suspect: Boolean): ZIO[BadActor, Nothing, BadActor.Status] =
    ZIO.serviceWithZIO[BadActor](_.checkReq(ip, instant, suspect))

  def spec = suite("BadActor")(

    test("5 suspect requests in 10s -> next suspect request is banned"):
      defer:
        val ip = "192.168.1.1"
        val baseTime = Instant.now()

        // 5 suspect requests at t=0..4s — all allowed (window not yet full
        // at request time; the 5th lands the timestamp that closes the ring).
        val instants = (0 until 5).map(i => baseTime.plusSeconds(i.toLong)).toList
        val results = ZIO.foreach(instants)(check(ip, _, suspect = true)).run

        // 6th suspect request at t=5s: ring holds [0,1,2,3,4], spread = 4s,
        // which is inside the 10s window -> banned.
        val finalResult = check(ip, baseTime.plusSeconds(5), suspect = true).run

        assertTrue(
          results.forall(_ == Allowed),
          finalResult == Banned,
        )

    , test("non-suspect requests are never tracked, never banned"):
      defer:
        val ip = "192.168.1.2"
        val now = Instant.now()

        // 10 non-suspect requests over 5s (way more than the threshold) —
        // none should change the IP's status.
        val instants = (0 until 10).map(i => now.plusMillis(i.toLong * 500)).toList
        val results = ZIO.foreach(instants)(check(ip, _, suspect = false)).run

        assertTrue(results.forall(_ == Allowed))

    , test("suspect requests spread beyond the window are allowed"):
      defer:
        val ip = "192.168.1.3"
        val baseTime = Instant.now()

        // 5 suspect requests at t=0,3,6,9,12s — ring fills, but the spread
        // (12s) already exceeds the 10s window before the 6th request.
        val instants = (0 until 5).map(i => baseTime.plusSeconds(i.toLong * 3)).toList
        val results = ZIO.foreach(instants)(check(ip, _, suspect = true)).run

        // 6th suspect request: ring spread is 12s, outside the window, so allowed.
        val finalResult = check(ip, baseTime.plusSeconds(15), suspect = true).run

        assertTrue(
          results.forall(_ == Allowed),
          finalResult == Allowed,
        )

  ).provide(BadActor.live)
