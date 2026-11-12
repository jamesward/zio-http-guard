package com.jamesward.zio_http_guard.guard

import zio.*
import zio.http.*

/**
 * Guard settings, read from environment variables (e.g. Heroku config vars)
 * under a prefix, `GUARD` by default:
 *
 * {{{
 * GUARD_MODE=enforce                       # enforce | observe | off
 * GUARD_TRUSTED_HOPS=1                     # proxies that append to X-Forwarded-For
 * GUARD_FLAG_FOR=10m                       # how long a Confirmed client stays Confirmed
 * GUARD_STATS_INTERVAL=1m
 * GUARD_BULKHEADS=regular=24/48,suspect=4/8   # pool=inFlight/queued
 * GUARD_ACTION_REGULAR=pass                # pass | block | bulkhead:<pool>
 * GUARD_ACTION_SUSPECT=pass
 * GUARD_ACTION_CONFIRMED=block
 * GUARD_BLOCK_RESPONSE=ok                  # ok | 404 | 429 | 503
 * GUARD_DISABLED_DETECTORS=swarm,probe
 * }}}
 *
 * In `observe` mode every detector runs and every verdict is logged and
 * counted, but no request is blocked or limited: the way to try a new
 * detector or threshold on production traffic. Detector settings (e.g.
 * `GUARD_SWARM_WINDOW`) are read by each detector's own `settings`.
 */
final case class GuardConfig(
  mode: GuardConfig.Mode = GuardConfig.Mode.Enforce,
  trustedHops: Int = 1,
  flagFor: Duration = 10.minutes,
  maxFlagged: Int = 200_000,
  statsInterval: Duration = 1.minute,
  bulkheads: Map[PoolName, GuardConfig.Pool] = Map.empty,
  actions: Map[Tier, Action] = Map(Tier.Regular -> Action.Pass, Tier.Suspect -> Action.Pass, Tier.Confirmed -> Action.Block),
  blockResponse: GuardConfig.BlockResponse = GuardConfig.BlockResponse.Ok,
  disabledDetectors: Set[DetectorName] = Set.empty,
):
  def action(tier: Tier): Action = actions.getOrElse(tier, Action.Pass)

object GuardConfig:

  enum Mode:
    case Enforce
    case Observe
    case Off

  given CanEqual[Mode, Mode] = CanEqual.derived
  given CanEqual[BlockResponse, BlockResponse] = CanEqual.derived

  final case class Pool(inFlight: Int, queued: Int) derives CanEqual

  /** What a blocked request gets when its verdict carries no response of its own. */
  enum BlockResponse:
    /** A tiny `200`: the cheapest answer, and gives a flood nothing to retry. */
    case Ok
    case NotFound
    case TooManyRequests
    case Unavailable

    def response: Response =
      this match
        case Ok              => Response(Status.Ok, Headers(Header.CacheControl.NoStore), Body.fromString(""))
        case NotFound        => Response.status(Status.NotFound)
        case TooManyRequests => Response(Status.TooManyRequests, Headers(Header.RetryAfter.ByDuration(1.minute)))
        case Unavailable     => shedResponse

  /** Response when a bulkhead and its queue are full. */
  val shedResponse: Response =
    Response(
      Status.ServiceUnavailable,
      Headers(Header.RetryAfter.ByDuration(30.seconds), Header.CacheControl.NoStore),
      Body.fromString("Too busy, try again shortly"),
    )

  private def parseWith[A](config: Config[String])(f: String => Either[String, A]): Config[A] =
    config.mapOrFail(text => f(text).left.map(Config.Error.InvalidData(Chunk.empty, _)))

  private def parseMode(text: String): Either[String, Mode] =
    Mode.values.find(_.toString.equalsIgnoreCase(text.trim)).toRight(s"unknown mode '$text' (expected enforce, observe, or off)")

  private def parseBlockResponse(text: String): Either[String, BlockResponse] =
    text.trim.toLowerCase(java.util.Locale.ROOT) match
      case "ok" | "200" => Right(BlockResponse.Ok)
      case "404"        => Right(BlockResponse.NotFound)
      case "429"        => Right(BlockResponse.TooManyRequests)
      case "503"        => Right(BlockResponse.Unavailable)
      case other        => Left(s"unknown block response '$other' (expected ok, 404, 429, or 503)")

  /** `regular=24/48,suspect=4/8` */
  def parseBulkheads(text: String): Either[String, Map[PoolName, Pool]] =
    val entries = text.split(',').toList.map(_.trim).filter(_.nonEmpty).map: entry =>
      entry.split("[=/]").toList.map(_.trim) match
        case List(name, inFlight, queued) =>
          (inFlight.toIntOption, queued.toIntOption) match
            case (Some(i), Some(q)) if i > 0 && q >= 0 => Right(PoolName(name) -> Pool(i, q))
            case _                                     => Left(s"bad bulkhead '$entry'")
        case _ => Left(s"bad bulkhead '$entry' (expected name=inFlight/queued)")
    entries.partitionMap(identity) match
      case (Nil, pools) => Right(pools.toMap)
      case (errors, _)  => Left(errors.mkString("; "))

  private def detectorNames(text: String): Set[DetectorName] =
    text.split(',').map(_.trim).filter(_.nonEmpty).map(DetectorName(_)).toSet

  /** Reads a [[GuardConfig]] from `<prefix>_*` variables; anything unset keeps its default. */
  def config(prefix: String = "GUARD", defaults: GuardConfig = GuardConfig()): Config[GuardConfig] =
    def key(name: String) = s"${prefix}_$name"
    def tierAction(tier: Tier) =
      parseWith(Config.string(key(s"ACTION_${tier.toString.toUpperCase}")))(Action.parse).withDefault(defaults.action(tier))
    (
      parseWith(Config.string(key("MODE")))(parseMode).withDefault(defaults.mode) ++
      Config.int(key("TRUSTED_HOPS")).withDefault(defaults.trustedHops) ++
      Config.duration(key("FLAG_FOR")).withDefault(defaults.flagFor) ++
      Config.int(key("MAX_FLAGGED")).withDefault(defaults.maxFlagged) ++
      Config.duration(key("STATS_INTERVAL")).withDefault(defaults.statsInterval) ++
      parseWith(Config.string(key("BULKHEADS")))(parseBulkheads).withDefault(defaults.bulkheads) ++
      tierAction(Tier.Regular) ++ tierAction(Tier.Suspect) ++ tierAction(Tier.Confirmed) ++
      parseWith(Config.string(key("BLOCK_RESPONSE")))(parseBlockResponse).withDefault(defaults.blockResponse) ++
      Config.string(key("DISABLED_DETECTORS")).map(detectorNames).withDefault(defaults.disabledDetectors)
    ).map: (mode, hops, flagFor, maxFlagged, statsInterval, bulkheads, regular, suspect, confirmed, block, disabled) =>
      GuardConfig(mode, hops, flagFor, maxFlagged, statsInterval, bulkheads,
        Map(Tier.Regular -> regular, Tier.Suspect -> suspect, Tier.Confirmed -> confirmed), block, disabled)
