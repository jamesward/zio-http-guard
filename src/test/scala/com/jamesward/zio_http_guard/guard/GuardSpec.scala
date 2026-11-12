package com.jamesward.zio_http_guard.guard

import zio.*
import zio.direct.*
import zio.http.*
import zio.test.*

object GuardSpec extends ZIOSpecDefault:

  private given CanEqual[Status, Status] = CanEqual.derived
  private given CanEqual[Duration, Duration] = CanEqual.derived

  private def reasonOf(detector: Detector, request: Request): UIO[Option[Reason]] =
    detector.check(request, ClientIp("1.1.1.1")).map(_.map(_.reason))

  private def text(routes: Routes[Any, Response], request: Request): ZIO[Scope, Throwable, String] =
    routes.runZIO(request).flatMap(_.body.asString)

  private def text(fiber: Fiber[Nothing, Response]): Task[String] =
    fiber.join.flatMap(_.body.asString)

  private def fired(swarm: Detector, ip: String): UIO[Boolean] =
    swarm.check(get("/listfiles/x/1", ip), ClientIp(ip)).map(_.isDefined)

  private def verdictFor(detector: Detector, path: String, ip: String): UIO[Option[Verdict]] =
    detector.check(get(path, ip), ClientIp(ip))

  private def hints(headers: (String, String)*): UIO[Option[Reason]] =
    reasonOf(ClientHints.detector, get("/", "1.1.1.1", headers*))

  private def get(path: String, ip: String, headers: (String, String)*): Request =
    headers.foldLeft(Request.get(URL(Path.decode(path))).addHeader("X-Forwarded-For", s"10.0.0.1, $ip")):
      case (request, (name, value)) => request.addHeader(name, value)

  private val ok = Routes(Method.GET / trailing -> Handler.fromFunction[(Path, Request)](_ => Response.text("real")))

  private val chrome156 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

  def spec = suite("guard")(
    suite("config")(
      test("bulkheads and actions parse"):
        assertTrue(
          GuardConfig.parseBulkheads("regular=24/48, suspect=4/0") == Right(Map(PoolName("regular") -> GuardConfig.Pool(24, 48), PoolName("suspect") -> GuardConfig.Pool(4, 0))),
          GuardConfig.parseBulkheads("regular=0/1").isLeft,
          GuardConfig.parseBulkheads("regular=24").isLeft,
          Action.parse("BULKHEAD:suspect") == Right(Action.Bulkhead(PoolName("suspect"))),
          Action.parse("bulkhead:").isLeft,
          Action.parse("block") == Right(Action.Block),
        )
      ,
      test("reads environment variables under the prefix, keeping defaults for the rest"):
        defer:
          val provider = ConfigProvider.fromMap(Map(
            "WJ_MODE" -> "observe",
            "WJ_BULKHEADS" -> "suspect=4/8",
            "WJ_ACTION_SUSPECT" -> "bulkhead:suspect",
            "WJ_BLOCK_RESPONSE" -> "429",
            "WJ_DISABLED_DETECTORS" -> "swarm, probe",
            "WJ_SWARM_WINDOW" -> "3s",
          ))
          val config = provider.load(GuardConfig.config("WJ")).run
          val swarm  = provider.load(Swarm.settings("WJ")).run
          assertTrue(
            config.mode == GuardConfig.Mode.Observe,
            config.action(Tier.Suspect) == Action.Bulkhead(PoolName("suspect")),
            config.action(Tier.Confirmed) == Action.Block,
            config.blockResponse == GuardConfig.BlockResponse.TooManyRequests,
            config.disabledDetectors == Set(DetectorName("swarm"), DetectorName("probe")),
            config.flagFor == 10.minutes,
            swarm == Swarm.Settings(3.seconds, 4),
          )
      ,
      test("an action naming an undefined bulkhead fails to build"):
        defer:
          val config = GuardConfig(actions = Map(Tier.Suspect -> Action.Bulkhead(PoolName("nope"))))
          val exit   = ZIO.scoped(Guard.make(config, Chunk.empty)).exit.run
          assertTrue(exit.isFailure)
    ),
    suite("detectors")(
      test("client IP is the trusted hop from the end of X-Forwarded-For"):
        val request = get("/", "34.1.2.3")
        assertTrue(
          ClientId.forwardedFor(1)(request) == Some(ClientIp("34.1.2.3")),
          ClientId.forwardedFor(2)(request) == Some(ClientIp("10.0.0.1")),
          Network.of(ClientIp("34.1.2.3")).value == "34.1.0.0/16",
        )
      ,
      test("probe paths and probe referers"):
        defer:
          val probe     = reasonOf(Probe.path(), get("/947870aad14388ee.mkv", "1.1.1.1")).run
          val fromProbe = reasonOf(Probe.referer(), get("/listfiles/a/b", "1.1.1.1", "Referer" -> "https://www.webjars.org/abcdef0123.mov")).run
          assertTrue(
            Probe.randomMedia(Path.decode("/947870aad14388ee075d2ba0b537c4a8e673.mkv")),
            !Probe.randomMedia(Path.decode("/favicon.ico")),
            !Probe.randomMedia(Path.decode("/files/abcdef0123.mp4")),
            probe == Some(Probe.pathReason),
            fromProbe == Some(Probe.refererReason),
          )
      ,
      test("client hints that contradict the Chrome User-Agent"):
        defer:
          val consistent = hints("User-Agent" -> chrome156, "Sec-CH-UA" -> "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"").run
          val mismatched = hints("User-Agent" -> chrome156, "Sec-CH-UA" -> "\"Chromium\";v=\"157\", \"Google Chrome\";v=\"157\"").run
          val missing    = hints("User-Agent" -> chrome156).run
          val firefox    = hints("User-Agent" -> "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0").run
          assertTrue(consistent.isEmpty, mismatched == Some(ClientHints.mismatch), missing == Some(ClientHints.missing), firefox.isEmpty)
      ,
      test("swarm: the same key from the threshold-th distinct client within the window"):
        ZIO.scoped:
          defer:
            val swarm = Swarm.make(Swarm.Settings(5.seconds, 3), r => Some(r.path.encode)).run
            val first  = fired(swarm, "1.1.1.1").run
            val repeat = fired(swarm, "1.1.1.1").run
            val second = fired(swarm, "2.2.2.2").run
            val third  = fired(swarm, "3.3.3.3").run
            TestClock.adjust(6.seconds).run
            val later  = fired(swarm, "4.4.4.4").run
            assertTrue(!first, !repeat, !second, third, !later)
      ,
      test("new keys per client: only costly keys count, limited per window"):
        ZIO.scoped:
          defer:
            val detector = NewKeyPerClient.make[String](NewKeyPerClient.Settings(2, 10.minutes), r => Some(r.path.encode), k => ZIO.succeed(k != "/cached")).run
            val results = ZIO.foreach(List("/a", "/b", "/cached", "/c"))(verdictFor(detector, _, "1.1.1.1")).run
            val other   = verdictFor(detector, "/d", "2.2.2.2").run
            TestClock.adjust(11.minutes).run
            val later   = verdictFor(detector, "/e", "1.1.1.1").run
            assertTrue(
              results.take(3).forall(_.isEmpty),
              results(3).flatMap(_.response).map(_.status) == Some(Status.TooManyRequests),
              other.isEmpty,
              later.isEmpty,
            )
    ),
    suite("guard")(
      test("confirmed requests are blocked and the client stays flagged; observe mode only records"):
        ZIO.scoped:
          defer:
            val enforce = Guard.make(GuardConfig(), Chunk(Probe.path())).run
            val routes  = ok @@ enforce.middleware
            val probe   = routes.runZIO(get("/947870aad14388ee.mkv", "1.1.1.1")).run
            val after   = text(routes, get("/listfiles/a/b", "1.1.1.1")).run
            val other   = text(routes, get("/listfiles/a/b", "2.2.2.2")).run
            TestClock.adjust(11.minutes).run
            val expired = text(routes, get("/listfiles/a/b", "1.1.1.1")).run
            val observe = Guard.make(GuardConfig(mode = GuardConfig.Mode.Observe), Chunk(Probe.path())).run
            val watched = text((ok @@ observe.middleware), get("/947870aad14388ee.mkv", "3.3.3.3")).run
            val verdict = observe.judge(get("/947870aad14388ee.mkv", "3.3.3.3"), ClientIp("3.3.3.3")).run
            assertTrue(
              probe.status == Status.Ok,
              after.isEmpty,
              other == "real",
              expired == "real",
              watched == "real",
              verdict.map(_.tier) == Some(Tier.Confirmed),
            )
      ,
      test("a verdict's own response wins over the block response; disabled detectors don't run"):
        ZIO.scoped:
          defer:
            val limit = NewKeyPerClient.make[String](NewKeyPerClient.Settings(1, 10.minutes), r => Some(r.path.encode), _ => ZIO.succeed(true)).run
            val guard = Guard.make(GuardConfig(), Chunk(limit)).run
            val routes = ok @@ guard.middleware
            routes.runZIO(get("/a", "1.1.1.1")).run
            val limited = routes.runZIO(get("/b", "1.1.1.1")).run
            val off = Guard.make(GuardConfig(disabledDetectors = Set(Probe.pathName)), Chunk(Probe.path())).run
            val passed = text((ok @@ off.middleware), get("/947870aad14388ee.mkv", "2.2.2.2")).run
            assertTrue(limited.status == Status.TooManyRequests, passed == "real")
      ,
      test("a full bulkhead sheds with 503 while other tiers pass"):
        ZIO.scoped:
          defer:
            val gate   = Promise.make[Nothing, Unit].run
            val slow   = Routes(Method.GET / trailing -> Handler.fromFunctionZIO[(Path, Request)](_ => gate.await.as(Response.text("real"))))
            val suspect = Detector.pure(DetectorName("ua")): (request, _) =>
              Option.when(request.headers.get("User-Agent").contains("bot"))(Verdict(Tier.Suspect, Reason("ua")))
            val config = GuardConfig(
              bulkheads = Map(PoolName("suspect") -> GuardConfig.Pool(1, 0)),
              actions = Map(Tier.Regular -> Action.Pass, Tier.Suspect -> Action.Bulkhead(PoolName("suspect")), Tier.Confirmed -> Action.Block),
            )
            val guard  = Guard.make(config, Chunk(suspect)).run
            val routes = slow @@ guard.middleware
            val held   = routes.runZIO(get("/x", "1.1.1.1", "User-Agent" -> "bot")).fork.run
            ZIO.yieldNow.repeatN(200).run
            val shed    = routes.runZIO(get("/x", "2.2.2.2", "User-Agent" -> "bot")).run
            val regular = routes.runZIO(get("/x", "3.3.3.3")).fork.run
            gate.succeed(()).run
            val heldBody = text(held).run
            val regularBody = text(regular).run
            assertTrue(shed.status == Status.ServiceUnavailable, heldBody == "real", regularBody == "real")
    ),
  )
