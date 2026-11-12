package com.jamesward.zio_http_guard.guard

import zio.*
import zio.http.*

import java.time.Instant

/** A client's IP address, as the guard identifies it (see [[ClientId.forwardedFor]]). */
opaque type ClientIp = String
object ClientIp:
  def apply(ip: String): ClientIp = ip
  extension (ip: ClientIp) def value: String = ip
  given CanEqual[ClientIp, ClientIp] = CanEqual.derived

/** A `/16` network (or a whole non-IPv4 address); floods cluster by provider. */
opaque type Network = String
object Network:
  def of(ip: ClientIp): Network =
    ip.value.split('.') match
      case Array(a, b, _, _) => s"$a.$b.0.0/16"
      case _                 => ip.value
  extension (network: Network) def value: String = network

/** Why a detector judged a request, as logged and counted (e.g. `swarm`). */
opaque type Reason = String
object Reason:
  def apply(reason: String): Reason = reason
  extension (reason: Reason) def value: String = reason
  given CanEqual[Reason, Reason] = CanEqual.derived
  given Ordering[Reason] = Ordering.String

  val Flagged: Reason = "flagged"

/** A detector's name, used in logs and in `<PREFIX>_DISABLED_DETECTORS`. */
opaque type DetectorName = String
object DetectorName:
  def apply(name: String): DetectorName = name
  extension (name: DetectorName) def value: String = name
  given CanEqual[DetectorName, DetectorName] = CanEqual.derived

/** A bulkhead's name, used in `<PREFIX>_BULKHEADS` and `bulkhead:<pool>` actions. */
opaque type PoolName = String
object PoolName:
  def apply(name: String): PoolName = name
  extension (name: PoolName) def value: String = name
  given CanEqual[PoolName, PoolName] = CanEqual.derived
  given Ordering[PoolName] = Ordering.String

private[guard] def isRecent(at: Instant, now: Instant, window: Duration): Boolean =
  java.time.Duration.between(at, now).compareTo(window.asJava) < 0
