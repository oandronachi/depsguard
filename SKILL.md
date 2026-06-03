---
name: dependency-guardrail
description: >-
  Use whenever you are about to add, upgrade, or evaluate a third-party
  dependency in any ecosystem (PyPI, npm, Cargo/Rust, Maven/Java-Kotlin, Go,
  NuGet, RubyGems), or when a user asks whether a package or version is safe,
  what license it uses, or which CVEs affect it. Provides decision-grade
  dependency context and an ALLOW/WARN/BLOCK policy verdict via the depsguard
  MCP server.
---

# Dependency Guardrail

This skill governs how to use the **depsguard** MCP tools so that dependency
decisions in an AI-native SDLC are made on real data, not guesses.

## When to use

Trigger this skill before any action that introduces or changes a dependency —
editing `requirements.txt`, `package.json`, `Cargo.toml`, `pom.xml`, `go.mod`,
etc. — and whenever the user asks "is X safe?", "what license is X?", or "what
CVEs affect X@version?".

## How to use the tools

Follow this order; stop as soon as you have what the task needs.

1. **Unknown version?** Call `get_package_info(ecosystem, name)` to find the
   latest/default version and what exists.
2. **Evaluating a specific version?** Call `get_version_details(ecosystem, name,
   version)` for its licenses, source repo, and the advisory IDs affecting it.
3. **Need severity for an advisory ID?** Call `get_advisory_details(advisory_id)`
   for CVSS severity and CVE aliases.
4. **Making an add/upgrade decision?** Prefer `evaluate_dependency_policy(
   ecosystem, name, version, max_severity)` — it composes the above into a single
   ALLOW / WARN / BLOCK verdict. Use a stricter `max_severity` (e.g. "low") for
   production or safety-relevant code.

## Acting on the verdict

- **BLOCK** — do not add/upgrade. Report the offending advisories and propose a
  patched version (use `get_package_info` to find a newer one).
- **WARN** — surface the advisories to the user and ask for confirmation before
  proceeding; do not silently merge.
- **ALLOW** — proceed, but still state the license so licensing stays visible.

## Notes

- `ecosystem` is one of: pypi, npm, cargo, maven, go, nuget, rubygems.
- Advisories returned affect the version **directly**; they do not include
  vulnerabilities inherited from transitive dependencies. Say so when relevant.
- Package names are ecosystem-native (e.g. Maven uses `groupId:artifactId`).
