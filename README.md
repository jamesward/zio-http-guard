zio-http-guard
--------------------

[![javadocs.dev](https://www.javadocs.dev/com.jamesward/zio-http-guard_3/badge.svg)](https://www.javadocs.dev/com.jamesward/zio-http-guard_3/latest)

Guard middleware for [zio-http](https://github.com/zio/zio-http): identify floods, crawlers and probes, and decide per request whether to serve, limit, or block.

## Guard

`com.jamesward.zio_http_guard.guard.Guard` runs a list of **detectors** on each request. Each detector may return a **verdict** (`Regular`, `Suspect` or `Confirmed`, plus a reason). The guard takes the highest tier and applies that tier's **action**: `pass`, `block`, or `bulkhead:<pool>` (a [rezilience](https://github.com/svroonland/rezilience) bulkhead that sheds with a `503` when full). A client with a `Confirmed` verdict stays `Confirmed` for `GUARD_FLAG_FOR`, unless the verdict is a rate limit (`Verdict.flag = false`).

The app owns the detectors and what they key on; thresholds, actions and the mode are environment variables, so a new kind of flood is handled by changing the app or its config, not this library.

```scala
import com.jamesward.zio_http_guard.guard.*

val guardLayer: ZLayer[Any, Config.Error, Guard] =
  ZLayer.scoped:
    for
      config <- ZIO.config(GuardConfig.config())
      swarm  <- ZIO.config(Swarm.settings()).flatMap(Swarm.make(_, req => Some(req.path.encode)))
      guard  <- Guard.make(config, Chunk(swarm, Probe.path(), Probe.referer(), ClientHints.detector))
    yield guard

// Apply outside the request logger so its lines carry client_ip / guard_tier / guard_reason.
routes @@ Middleware.requestLogging(loggedRequestHeaders = ClientId.identifyingHeaders) @@ guard.middleware

// Or take the guard from the environment and provide `guardLayer` with your other layers:
routes @@ Middleware.requestLogging(loggedRequestHeaders = ClientId.identifyingHeaders) @@ Guard.fromEnvironment
```

### Detectors

| Detector | Verdict |
|---|---|
| `Swarm.make(settings, key)` | `Confirmed` once `GUARD_SWARM_CLIENTS` distinct clients request the same key within `GUARD_SWARM_WINDOW` |
| `NewKeyPerClient.make(settings, key, isCostly, clientKey)` | A `429` once a client requests more than `GUARD_NEW_KEYS_PER_CLIENT` costly keys within `GUARD_NEW_KEYS_WINDOW`. A rate limit doesn't flag the client, so its other requests still pass. `clientKey` decides who shares a budget: `ClientKey.ip` (default) or `ClientKey.crawlerOrIp()`, which gives each declared crawler (`Crawler.known` User-Agent tokens) one budget across all its IPs |
| `Probe.path()` / `Probe.referer()` | `Confirmed` for a probe path (default: root-level random-hex media files), or a `Referer` that is one |
| `ClientHints.detector` | `Confirmed` when `Sec-CH-UA` contradicts a Chrome User-Agent; `Suspect` when it's missing |
| `Detector(name, check)` / `Detector.pure(name)(f)` | anything the app needs |

`Guard.make`'s `actionFor` overrides the action per request, e.g. bulkhead only the expensive routes:

```scala
Guard.make(config, detectors, actionFor = {
  case (Tier.Regular, req) if expensive(req) => Some(Action.Bulkhead(PoolName("regular")))
  case _                                     => None
})
```

### Configuration

| Variable | Default | |
|---|---|---|
| `GUARD_MODE` | `enforce` | `observe` runs and logs every detector but never blocks or limits; `off` skips the guard |
| `GUARD_TRUSTED_HOPS` | `1` | proxies appending to `X-Forwarded-For` (Heroku: 1) |
| `GUARD_FLAG_FOR` | `10m` | |
| `GUARD_BULKHEADS` | | `regular=24/48,suspect=4/8` (pool=inFlight/queued) |
| `GUARD_ACTION_REGULAR` / `_SUSPECT` / `_CONFIRMED` | `pass` / `pass` / `block` | |
| `GUARD_BLOCK_RESPONSE` | `ok` | `ok` (tiny `200`), `404`, `429`, `503` |
| `GUARD_DISABLED_DETECTORS` | | e.g. `swarm,client-hints` |
| `GUARD_STATS_INTERVAL` | `1m` | |
| `GUARD_SWARM_WINDOW` / `GUARD_SWARM_CLIENTS` | `5s` / `4` | |
| `GUARD_NEW_KEYS_PER_CLIENT` / `GUARD_NEW_KEYS_WINDOW` | `30` / `10m` | |

Pass a different prefix (`GuardConfig.config("WEBJARS_GUARD")`) to run more than one guard.

### Logging

- `guard_stats` every `GUARD_STATS_INTERVAL`: requests, distinct clients, top clients and `/16` networks, top keys by distinct clients (a swarm fans one key out to many clients), verdicts by tier and reason, blocked and shed counts, bulkhead occupancy, flagged clients.
- `guard_blocked` for each blocked request (they never reach the request logger).
- `ClientId.identifyingHeaders` for `Middleware.requestLogging`, and `ClientId.annotate()` to put `client_ip` on every log line of routes the guard doesn't wrap.

All state is bounded and swept.

## Also

- `BadActorMiddleware` / `BadActor`: bans IPs that make repeated probe requests.
- `CrawlerLimiter`: one resource key at a time per known crawler User-Agent.
