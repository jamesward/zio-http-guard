package com.jamesward.zio_http_guard.guard

import nl.vroste.rezilience.Bulkhead
import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*
import zio.http.*

import java.time.Instant

/**
 * Runs every enabled [[Detector]] on each request, takes the highest
 * [[Tier]] any of them returns, and applies the [[Action]] for that tier.
 * A client with a [[Tier.Confirmed]] verdict stays Confirmed (`flagged`)
 * for `flagFor`.
 *
 * The consuming app owns the detectors and their keys, plus `actionFor`
 * overrides (e.g. bulkhead only expensive routes); [[GuardConfig]]
 * (environment variables) owns thresholds, the tier→action table, the mode
 * and disabled detectors. Handling a new kind of flood means changing one of
 * those, not this library.
 *
 * Every request's log lines carry `client_ip` and `guard_tier` (plus
 * `guard_reason` when a detector fired); blocked requests never reach the
 * request logger, so each gets a `guard_blocked` line.
 */
final case class Guard(
  config: GuardConfig,
  detectors: Chunk[Detector],
  bulkheads: Map[PoolName, Bulkhead],
  actionFor: (Tier, Request) => Option[Action],
  flagged: ConcurrentMap[ClientIp, Instant],
  flaggedSize: Ref[Int],
  stats: GuardStats,
):
  private val enabled = detectors.filterNot(d => config.disabledDetectors.contains(d.name))

  private def flaggedVerdict(client: ClientIp, now: Instant): UIO[Option[Verdict]] =
    flagged.get(client).map(_.filter(isRecent(_, now, config.flagFor)).map(_ => Verdict(Tier.Confirmed, Reason.Flagged)))

  private def flag(client: ClientIp, now: Instant): UIO[Unit] =
    defer:
      val size = flaggedSize.get.run
      if size < config.maxFlagged then
        val prior = flagged.put(client, now).run
        flaggedSize.update(_ + 1).when(prior.isEmpty).run

  /** The request's verdict, recording it in the detectors' state, the flags and the stats. */
  def judge(request: Request, client: ClientIp): UIO[Option[Verdict]] =
    defer:
      val now      = Clock.instant.run
      val verdicts = ZIO.foreach(enabled)(_.check(request, client)).run.flatten
      val previous = flaggedVerdict(client, now).run
      val verdict  = (verdicts ++ previous).maxByOption(_.tier)
      flag(client, now).when(verdicts.exists(_.tier == Tier.Confirmed)).run
      stats.record(request, client, verdict).run
      verdict

  private def blockResponse(request: Request, verdict: Option[Verdict]): UIO[Response] =
    val reason = verdict.map(v => s" reason=${v.reason.value}")
    val ua     = request.headers.get(Header.UserAgent.name).map(ua => s" user-agent=$ua")
    stats.blocked *>
      ZIO.logInfo(s"guard_blocked url=${request.path.encode}${reason.mkString}${ua.mkString}")
        .as(verdict.flatMap(_.response).getOrElse(config.blockResponse.response))

  private def act[R](action: Action, request: Request, verdict: Option[Verdict], handle: ZIO[R, Response, Response]): ZIO[R, Response, Response] =
    action match
      case Action.Pass  => handle
      case Action.Block => blockResponse(request, verdict).flip
      case Action.Bulkhead(pool) =>
        // `Guard.make` checks every configured pool exists; an `actionFor` override may name one that doesn't.
        bulkheads.get(pool).fold(ZIO.logWarning(s"guard: undefined bulkhead ${pool.value}; passing") *> handle): bulkhead =>
          bulkhead(handle).catchAll(_.fold(stats.shed(pool) *> ZIO.fail(GuardConfig.shedResponse), ZIO.fail(_)))

  private def guarded[R](request: Request, client: ClientIp, handle: ZIO[R, Response, Response]): ZIO[R, Response, Response] =
    judge(request, client).flatMap: verdict =>
      val tier = verdict.fold(Tier.Regular)(_.tier)
      val action = config.mode match
        case GuardConfig.Mode.Observe => Action.Pass
        case _                        => actionFor(tier, request).getOrElse(config.action(tier))
      val annotations = LogAnnotation("guard_tier", tier.toString) :: verdict.map(v => LogAnnotation("guard_reason", v.reason.value)).toList
      ZIO.logAnnotate(LogAnnotation("client_ip", client.value), annotations*)(act(action, request, verdict, handle))

  /**
   * The guard as zio-http middleware. Apply it outside the request logger so
   * the logger's lines carry the guard's annotations. (zio-http's
   * `HandlerAspect` can't hold a bulkhead slot across the handler, so this
   * implements `Middleware` directly.)
   */
  val middleware: Middleware[Any] =
    new Middleware[Any]:
      def apply[Env1, Err](routes: Routes[Env1, Err]): Routes[Env1, Err] =
        routes.transform[Env1]: handler =>
          Handler.scoped[Env1]:
            Handler.fromFunctionZIO[Request]: request =>
              (config.mode, ClientId.forwardedFor(config.trustedHops)(request)) match
                case (GuardConfig.Mode.Off, _) | (_, None) => handler(request)
                case (_, Some(client))                     => guarded(request, client, handler(request))

object Guard:

  /**
   * Builds a guard from `config`, starting its bulkheads, the flag sweeper
   * and the `guard_stats` reporter in the scope.
   *
   * @param actionFor per-request override of the tier→action table, e.g.
   *                  `case (Tier.Regular, req) if expensive(req) => Some(Action.Bulkhead(regular))`.
   * @param statsKey  what `guard_stats` ranks by distinct clients (default: the path).
   */
  def make(
    config: GuardConfig,
    detectors: Chunk[Detector],
    actionFor: (Tier, Request) => Option[Action] = (_, _) => None,
    statsKey: Request => Option[String] = request => Some(request.path.encode),
  ): ZIO[Scope, Config.Error, Guard] =
    val used    = config.actions.values.collect { case Action.Bulkhead(pool) => pool }.toSet
    val missing = used -- config.bulkheads.keySet
    defer:
      if missing.nonEmpty then
        ZIO.fail(Config.Error.InvalidData(Chunk.empty, s"actions use undefined bulkheads: ${missing.map(_.value).mkString(",")}")).run
      val bulkheads = ZIO.foreach(config.bulkheads)((name, pool) => Bulkhead.make(pool.inFlight, pool.queued).map(name -> _)).run
      val flagged   = ConcurrentMap.empty[ClientIp, Instant].run
      val size      = Ref.make(0).run
      // The sweeper recounts too, so `size` (which caps the map) stays exact.
      val sweep =
        Clock.instant.flatMap(now => flagged.removeIf((_, at) => !isRecent(at, now, config.flagFor))) *>
          flagged.toChunk.flatMap(entries => size.set(entries.size))
      sweep.repeat(Schedule.spaced(1.minute)).forkScoped.run
      val stats = GuardStats.make(statsKey, bulkheads, size.get).run
      stats.report.repeat(Schedule.spaced(config.statsInterval)).delay(config.statsInterval).forkScoped.run
      ZIO.logInfo(
        s"guard_started mode=${config.mode} detectors=${detectors.map(_.name.value).mkString(",")} " +
        s"disabled=${config.disabledDetectors.map(_.value).mkString(",")}"
      ).run
      Guard(config, detectors, bulkheads, actionFor, flagged, size, stats)
