package com.jamesward.zio_http_guard.guard

import zio.*
import zio.http.*

/** How much a request is trusted, lowest to highest suspicion. */
enum Tier:
  case Regular
  case Suspect
  case Confirmed

object Tier:
  given CanEqual[Tier, Tier] = CanEqual.derived
  given Ordering[Tier] = Ordering.by(_.ordinal)

/**
 * A detector's judgement of a request.
 *
 * @param response used instead of the configured block response when this
 *                 verdict's request is blocked (e.g. a `429` with
 *                 `Retry-After` for a rate limit).
 * @param flag     whether a [[Tier.Confirmed]] verdict flags the client, so
 *                 its later requests are Confirmed too. A rate limit sets it
 *                 to false: only the requests over the limit are refused, and
 *                 the client's other requests (e.g. cached pages) still pass.
 */
final case class Verdict(tier: Tier, reason: Reason, response: Option[Response] = None, flag: Boolean = true)

/**
 * Judges a request. A detector may keep state (the swarm and new-key
 * detectors do), so every enabled detector sees every request the guard
 * applies to; the guard acts on the highest tier any of them returns.
 */
final case class Detector(name: DetectorName, check: (Request, ClientIp) => UIO[Option[Verdict]])

object Detector:
  /** A stateless detector from a plain function. */
  def pure(name: DetectorName)(f: (Request, ClientIp) => Option[Verdict]): Detector =
    Detector(name, (request, client) => ZIO.succeed(f(request, client)))

/** What the guard does with a request of a given tier. */
enum Action:
  case Pass
  /** Run the request in the named bulkhead; when it and its queue are full, respond with [[GuardConfig.shedResponse]]. */
  case Bulkhead(pool: PoolName)
  /** Respond without running the request: the verdict's response, else the configured block response. */
  case Block

object Action:
  given CanEqual[Action, Action] = CanEqual.derived

  private val bulkheadPrefix = "bulkhead:"

  /** `pass`, `block`, or `bulkhead:<pool>`. */
  def parse(text: String): Either[String, Action] =
    text.trim.toLowerCase(java.util.Locale.ROOT) match
      case "pass"  => Right(Pass)
      case "block" => Right(Block)
      case s if s.startsWith(bulkheadPrefix) && s.length > bulkheadPrefix.length =>
        Right(Bulkhead(PoolName(s.drop(bulkheadPrefix.length))))
      case other => Left(s"unknown action '$other' (expected pass, block, or bulkhead:<pool>)")
