package com.jamesward.zio_http_guard.guard

import zio.*
import zio.direct.*
import zio.http.*
import zio.test.*

object ProbeSpec extends ZIOSpecDefault:

  private given CanEqual[Status, Status] = CanEqual.derived

  private val probes = List(
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
  ).map(Path.decode)

  private val legitimate = List(
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
  ).map(Path.decode)

  private val client = ClientIp("1.1.1.1")

  def spec = suite("Probe")(
    test("suspectPath matches security-exposure probes"):
      assertTrue(probes.filterNot(Probe.suspectPath).isEmpty)
    ,
    test("suspectPath leaves legitimate paths alone"):
      assertTrue(legitimate.filter(Probe.suspectPath).isEmpty)
    ,
    test("a probe verdict carries a 404 unless told to use the block response"):
      defer:
        val default  = Probe.path(Probe.suspectPath).check(Request.get("/.env"), client).run
        val fallback = Probe.path(Probe.suspectPath, response = None).check(Request.get("/.env"), client).run
        val clean    = Probe.path(Probe.suspectPath).check(Request.get("/dev.zio/zio_3/2.1.26/index.html"), client).run
        assertTrue(
          default.flatMap(_.response).map(_.status) == Some(Status.NotFound),
          fallback.exists(_.response.isEmpty),
          clean.isEmpty,
        )
  )
