package com.jamesward.zio_http_guard.guard

import nl.vroste.rezilience.Bulkhead
import zio.*
import zio.concurrent.ConcurrentMap
import zio.direct.*
import zio.http.*

/**
 * The periodic `guard_stats` log line, for spotting floods:
 *
 *   - `requests`, `distinct_clients`, `top_clients`, `top_networks` (`/16`):
 *     one heavy hitter shows up in `top_clients`; a swarm as many clients
 *     with ~1 request each, often concentrated in a few networks.
 *   - `top_keys`: keys (default: paths) by distinct clients; a swarm fans
 *     the same key out to many clients.
 *   - `tiers`, `reasons`: verdict counts; `blocked`, `shed`: what was acted on.
 *   - per-bulkhead `in_flight/queued`, and `flagged` clients.
 *
 * Counters cover one interval and are reset after each report. At most
 * [[GuardStats.maxTracked]] distinct clients are counted per interval, so a
 * flood can't grow them without bound.
 */
final case class GuardStats(
  statsKey: Request => Option[String],
  byClient: ConcurrentMap[ClientIp, Long],
  clientsByKey: ConcurrentMap[String, Set[ClientIp]],
  tracked: Ref[Int],
  tiers: Ref[Map[Tier, Long]],
  reasons: Ref[Map[Reason, Long]],
  blockedCount: Ref[Long],
  shedCounts: Ref[Map[PoolName, Long]],
  bulkheads: Map[PoolName, Bulkhead],
  flaggedCount: UIO[Int],
):
  import GuardStats.*

  private def bump[K](ref: Ref[Map[K, Long]], key: K): UIO[Unit] =
    ref.update(m => m.updated(key, m.getOrElse(key, 0L) + 1))

  private def count(request: Request, client: ClientIp): UIO[Unit] =
    defer:
      val prior = byClient.putIfAbsent(client, 0L).run
      tracked.update(_ + 1).when(prior.isEmpty).run
      byClient.compute(client, (_, n) => Some(n.getOrElse(0L) + 1)).run
      ZIO.foreachDiscard(statsKey(request)): key =>
        clientsByKey.compute(key, (_, clients) => Some(clients.getOrElse(Set.empty) + client))
      .run

  def record(request: Request, client: ClientIp, verdict: Option[Verdict]): UIO[Unit] =
    defer:
      val size = tracked.get.run
      count(request, client).when(size < maxTracked).run
      bump(tiers, verdict.fold(Tier.Regular)(_.tier)).run
      ZIO.foreachDiscard(verdict)(v => bump(reasons, v.reason)).run

  val blocked: UIO[Unit] = blockedCount.update(_ + 1)
  def shed(pool: PoolName): UIO[Unit] = bump(shedCounts, pool)

  private def drain[K, V](map: ConcurrentMap[K, V]): UIO[Chunk[(K, V)]] =
    map.toChunk.flatMap(entries => ZIO.foreachDiscard(entries)((key, _) => map.remove(key)).as(entries))

  private def top[K](counts: Iterable[(K, Long)])(render: K => String): String =
    counts.toSeq.sortBy(-_._2).take(topN).map((key, n) => s"${render(key)}=$n").mkString(",")

  val report: UIO[Unit] =
    defer:
      tracked.set(0).run
      val clients  = drain(byClient).run
      val keys     = drain(clientsByKey).run
      val tierN    = tiers.getAndSet(Map.empty).run
      val reasonN  = reasons.getAndSet(Map.empty).run
      val blockedN = blockedCount.getAndSet(0L).run
      val shedN    = shedCounts.getAndSet(Map.empty).run
      val pools    = ZIO.foreach(bulkheads.toList.sortBy(_._1))((name, b) => b.metrics.map(m => s"${name.value}=${m.inFlight}/${m.inQueue}")).run
      val flagged  = flaggedCount.run
      val networks = clients.groupMapReduce((ip, _) => Network.of(ip))(_._2)(_ + _)
      val swarmed  = keys.map((key, cs) => key -> cs.size.toLong).filter(_._2 > 1)
      ZIO.logInfo(
        s"guard_stats requests=${clients.map(_._2).sum} distinct_clients=${clients.size} " +
        s"top_clients=${top(clients)(_.value)} top_networks=${top(networks)(_.value)} top_keys=${top(swarmed)(identity)} " +
        s"tiers=${Tier.values.map(t => s"$t=${tierN.getOrElse(t, 0L)}").mkString(",")} " +
        s"reasons=${reasonN.toSeq.sortBy(_._1).map((r, n) => s"${r.value}=$n").mkString(",")} " +
        s"blocked=$blockedN shed=${shedN.toSeq.sortBy(_._1).map((p, n) => s"${p.value}=$n").mkString(",")} " +
        s"bulkheads=${pools.mkString(",")} flagged=$flagged"
      ).run

object GuardStats:
  private val topN = 10
  val maxTracked: Int = 100_000

  def make(statsKey: Request => Option[String], bulkheads: Map[PoolName, Bulkhead], flaggedCount: UIO[Int]): UIO[GuardStats] =
    defer:
      GuardStats(
        statsKey,
        ConcurrentMap.empty[ClientIp, Long].run,
        ConcurrentMap.empty[String, Set[ClientIp]].run,
        Ref.make(0).run,
        Ref.make(Map.empty[Tier, Long]).run,
        Ref.make(Map.empty[Reason, Long]).run,
        Ref.make(0L).run,
        Ref.make(Map.empty[PoolName, Long]).run,
        bulkheads,
        flaggedCount,
      )
