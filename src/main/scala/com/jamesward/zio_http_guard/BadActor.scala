package com.jamesward.zio_http_guard

import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*

import java.time.Instant

/**
 * Per-IP "suspect-request" sliding-window detector.
 *
 * Each IP has a small ring of timestamps (capped at [[BadActor.banOnRequestCount]]).
 * A request marked `suspect = true` appends a timestamp; a request marked
 * `suspect = false` is always [[BadActor.Status.Allowed]] and never modifies the ring.
 *
 * An IP is [[BadActor.Status.Banned]] when the ring is full *and* the time between
 * its oldest and newest timestamps fits inside [[BadActor.banWindow]] —
 * i.e. the IP made `banOnRequestCount` suspect requests within `banWindow`.
 *
 * The detector is purely a ZIO service over a `ConcurrentMap`. There is no
 * background eviction; entries persist for the lifetime of the layer. For
 * long-running servers this is fine: each entry is at most
 * `banOnRequestCount` Instants plus a `Ref` wrapper.
 */
final case class BadActor(
  banWindow: Duration,
  banOnRequestCount: Int,
  store: ConcurrentMap[BadActor.IP, Ref[Chunk[Instant]]],
):
  import BadActor.*

  /**
   * Record this request and return the resulting status.
   *
   *   - `suspect = false` → always [[BadActor.Status.Allowed]]; the ring is untouched.
   *   - `suspect = true`  → append the timestamp (drop oldest if full),
   *     then re-evaluate the window.
   *
   * Once an IP is banned, every subsequent suspect request keeps it banned
   * (the ring stays saturated within `banWindow`) until enough time elapses
   * for the oldest timestamp to fall out of the window.
   */
  def checkReq(ip: IP, instant: Instant, suspect: Boolean): UIO[Status] =

    // Append, dropping the oldest if at capacity. The ring never grows past
    // `banOnRequestCount`, so memory per IP is bounded.
    def append(chunk: Chunk[Instant], item: Instant): Chunk[Instant] =
      if chunk.size >= banOnRequestCount then chunk.drop(1) :+ item
      else chunk :+ item

    def newEntry: UIO[Status] =
      ZIO.when(suspect):
        defer:
          val ref = Ref.make(Chunk(instant)).run
          store.put(ip, ref).run
      .as(Status.Allowed)

    def existingEntry(ref: Ref[Chunk[Instant]]): UIO[Status] =
      defer:
        val items = ref.get.run

        val status =
          if items.size >= banOnRequestCount then
            val diff = Duration.fromJava(java.time.Duration.between(items.min, items.max))
            if diff <= banWindow then Status.Banned else Status.Allowed
          else
            Status.Allowed

        // Only record the timestamp if we're still allowing the request. If
        // already banned, refreshing the ring would re-saturate the window
        // and effectively make the ban permanent for as long as suspect
        // traffic continues — we want bans to age out naturally.
        if status == Status.Allowed && suspect then
          ref.update(append(_, instant)).run

        status

    defer:
      val maybeUser = store.get(ip).run
      maybeUser.fold(newEntry)(existingEntry).run

object BadActor:

  type IP = String

  /** Result of [[BadActor.checkReq]]. */
  enum Status:
    case Allowed
    case Banned

  given CanEqual[Status, Status] = CanEqual.derived

  /** Default sliding-window length: 10 seconds. */
  val defaultBanWindow: Duration = 10.seconds

  /** Default suspect-request threshold: 5 within [[defaultBanWindow]]. */
  val defaultBanOnRequestCount: Int = 5

  /**
   * Build a [[BadActor]] layer with explicit window/threshold values.
   *
   * @param banWindow         sliding-window length over which suspect requests are counted.
   * @param banOnRequestCount number of suspect requests inside `banWindow` that triggers a ban.
   */
  def layer(
    banWindow: Duration = defaultBanWindow,
    banOnRequestCount: Int = defaultBanOnRequestCount,
  ): ZLayer[Any, Nothing, BadActor] =
    ZLayer.fromZIO:
      ConcurrentMap.empty[IP, Ref[Chunk[Instant]]].map(BadActor(banWindow, banOnRequestCount, _))

  /** Convenience layer using the default window/threshold values. */
  val live: ZLayer[Any, Nothing, BadActor] = layer()
