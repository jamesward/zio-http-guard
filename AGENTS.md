# AGENTS.md: zio-http-guard

zio-http-guard is a ZIO HTTP library of guard middleware (bad-actor banning, crawler limiting).

## Agent tooling

- For Scala 3 and ZIO code (writing or reviewing it), follow `zen-of-scala`. For design, domain modeling, effects and testing strategy, follow `zen-of-james`. Read the relevant Skills in `.kiro/skills/` before working.

- Follow the `zen-of-projects` Skill (extract with `./sbta extractSkillsJars` into the gitignored `.kiro/skills/`); this file records only project-specific facts and exceptions.
- MCP server `sbta` (this build's `./sbta --mcp`, configured in `.mcp.json` and `.kiro/settings/mcp.json`, approved in `.claude/settings.json`): use it for all sbt work: `compile`, `test` (`full` for all), `run`, `check` after editing Scala 3 sources, `glob-search` / `inspect` / `symbol-location` for symbols, `sbt-task` for any other command. Its tools are deferred in Claude Code: load them with ToolSearch (search `sbta`). If it's unavailable, say so and use `./sbta <command>`. Logs: `project/target/sbta/mcp.log`.
- Maintenance routine: `.factory/MAINTENANCE.md` (weekly), following the `zen-of-projects` Skill.

## Build and exceptions

- Full validation: `Test / compile; testFull` (no `stage`: this is a library).
- Exception: `dev.zio:zio-direct` 1.0.0-RC7 is a prerelease because no stable release exists.
- `-release 17` targets Java 17 bytecode; CI builds on Java 25.
