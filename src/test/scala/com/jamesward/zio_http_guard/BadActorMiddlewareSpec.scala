package com.jamesward.zio_http_guard

import zio.*
import zio.direct.*
import zio.http.*
import zio.test.*

object BadActorMiddlewareSpec extends ZIOSpecDefault:

  private given CanEqual[Status, Status] = CanEqual.derived
  private val forwardedFor = Header.Custom("X-Forwarded-For", "192.168.1.10")

  def spec = suite("BadActorMiddleware")(

    test("defaultSuspect matches common security exposure probes"):
      val probes = List(
        "/.env",
        "/.env.production",
        "/.environment",
        "/.envrc",
        "/.envs/.production/.django",
        "/config/.env.local",
        "/api/config/.env.backup",
        "/stripe/.env",
        "/.gcp/credentials",
        "/.git-credentials",
        "/.git/config.old",
        "/.github/workflows/ci.yml",
        "/.hg/store/00changelog.i",
        "/.htaccess",
        "/.kube/config",
        "/.mail.env",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        "/.secrets",
        "/.ssh/id_rsa",
        "/.svn/entries",
        "/.terraformrc",
        "/.user.ini",
        "/.aws/credentials",
        "/.DS_Store",
        "/Dockerfile.prod",
        "/backup/Dockerfile.dev",
        "/Jenkinsfile",
        "/backup/Gemfile",
        "/Laravel.log",
        "/2026/phpinfo.php",
        "/admin/shell.PHP.bak",
        "/cgi-bin/status.cgi.old",
        "/test.aspx",
        "/health.jsp",
        "/blog/wp-json",
        "/wordpress/setup",
        "/__nextjs_action",
        "/__debug/status",
        "/actuator/env",
        "/server-status",
      ).map(Request.get)

      val legitimate = List(
        "/.well-known/api-catalog",
        "/.well-known/traffic-advice",
        "/.nojekyll",
        "/dev.zio/zio_3/2.1.26/index.html",
        "/com.example/example/1.0.0/com/example/Environment.html",
        "/com.php/example/1.0.0/index.html",
        "/com.jsp/example/1.0.0/index.html",
        "/org.eclipse.jgit/org.eclipse.jgit/7.3.0/index.html",
        "/org.example/wp-api/1.0.0/index.html",
        "/com.example/dockerfile/1.0.0/Dockerfile.html",
        "/com.example/example/1.0.0/assets/Gemfile",
        "/com.example/example/1.0.0/com/example/Actuator.html",
        "/io.modelcontextprotocol.sdk/mcp-core/1.0.0/resources/fonts/dejavu.css",
        "/org.jetbrains/annotations/26.0.2/element-list",
        "/com/amazonaws/services",
      ).map(Request.get)

      assertTrue(
        probes.forall(BadActorMiddleware.defaultSuspect),
        legitimate.forall(req => !BadActorMiddleware.defaultSuspect(req)),
      )
    ,

    test("a first suspect request is rejected before the protected handler runs"):
      defer:
        val calls = Ref.make(0).run
        val routes = Routes(
          Method.GET / "config" / ".env" -> Handler.fromZIO(calls.update(_ + 1).as(Response.ok))
        ) @@ BadActorMiddleware(bannedResponse = Response.status(Status.Forbidden))

        val response = routes.runZIO(Request.get("/config/.env").addHeader(forwardedFor)).run
        val callCount = calls.get.run

        assertTrue(
          response.status == Status.NotFound,
          callCount == 0,
        )
    ,

    test("repeated suspect requests receive the configured banned response"):
      defer:
        val calls = Ref.make(0).run
        val routes = Routes(
          Method.GET / "2026" / "phpinfo.php" -> Handler.fromZIO(calls.update(_ + 1).as(Response.ok))
        ) @@ BadActorMiddleware(bannedResponse = Response.status(Status.Forbidden))
        val request = Request.get("/2026/phpinfo.php").addHeader(forwardedFor)

        val first = routes.runZIO(request).run
        val second = routes.runZIO(request).run
        val third = routes.runZIO(request).run
        val callCount = calls.get.run

        assertTrue(
          first.status == Status.NotFound,
          second.status == Status.NotFound,
          third.status == Status.Forbidden,
          callCount == 0,
        )

  ).provide(
    BadActor.layer(banOnRequestCount = 2),
    Scope.default,
  )
