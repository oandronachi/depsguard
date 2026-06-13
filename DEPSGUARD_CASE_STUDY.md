# DepsGuard — Case Study

## Overview

**DepsGuard is an MCP (Model Context Protocol) server that gives AI coding
assistants the context to make safe dependency decisions — and a policy
guardrail that turns that context into an `ALLOW / WARN / BLOCK` verdict an
agent or a CI step can act on, _before_ a dependency is added or upgraded.**

It addresses a specific gap in the **AI-native SDLC**: assistants such as Claude
Code, Cursor, and Copilot can add or bump dependencies far faster than a human
can review their security and licensing implications. DepsGuard puts a
structured, decision-grade tool surface — and an opinionated guardrail — directly
in the agent's path.

| | |
|---|---|
| **Data source** | Google's [deps.dev](https://deps.dev) (Open Source Insights) v3 API — licenses, source repos, OSV/GHSA advisories. No API key, no account, free. Data is CC-BY 4.0. |
| **Coverage** | 7 ecosystems — Cargo (Rust), Maven (Java/Kotlin), npm, PyPI, Go, NuGet, RubyGems — including the ones automotive and systems software ship in. |
| **Surface** | One server module (< 300 lines), an agent skill, an evaluation harness, a LangGraph example, GitHub Actions CI, and a hardened Docker image. |
| **Stack** | Python 3.10+, the official MCP Python SDK (FastMCP), `httpx`, `venv` + `hatchling`, `pytest`, GitHub Actions, Docker, LangGraph. MIT licensed. |

---

## The problem

In an AI-native SDLC, dependency changes are increasingly proposed by agents,
not typed by humans. That shifts the bottleneck: the *decision* to pull in
`some-package@1.2.3` now happens at machine speed, but the *judgement* about
whether that version is safe, maintained, and appropriately licensed still
needs to happen — and a model guessing from training data is exactly the wrong
way to do it.

Concretely, an assistant about to edit `requirements.txt`, `package.json`,
`Cargo.toml`, `pom.xml`, or `go.mod` needs answers to questions like:

- Does this exact version have known security advisories? How severe?
- What license does it carry, and is that acceptable here?
- Is it deprecated or yanked?
- Given all that — should the change proceed at all?

Without a tool, the model either hallucinates an answer or omits the check
entirely. DepsGuard replaces the guess with real data and a verdict.

---

## The solution: context **plus** a guardrail

DepsGuard exposes four MCP tools. The first three are thin, typed wrappers over
single deps.dev endpoints; the fourth composes them into an actionable decision.

| Tool | What it returns |
|------|-----------------|
| `get_package_info(ecosystem, name)` | Version list, latest/default version, publish dates, deprecation/yank flags |
| `get_version_details(ecosystem, name, version)` | Licenses, source repo, and the security-advisory IDs affecting that exact version |
| `get_advisory_details(advisory_id)` | Title, CVSS v3 severity, CVE aliases, and a link for an OSV/GHSA advisory |
| `evaluate_dependency_policy(ecosystem, name, version, max_severity)` | **Guardrail:** composes the above into an `ALLOW / WARN / BLOCK` verdict |

The intended flow is: *look up a version → read its advisory IDs → expand
severity → or just call the guardrail for a one-shot decision.* A bundled
`SKILL.md` teaches the agent exactly when and how to chain the tools, and how to
act on each verdict (BLOCK: propose a patched version; WARN: surface and ask;
ALLOW: proceed but keep the license visible).

The policy itself is deliberately simple and auditable:

- **BLOCK** if any advisory's severity exceeds `max_severity`.
- **WARN** if advisories exist but none exceed `max_severity`.
- **ALLOW** if there are no known direct advisories.

`max_severity` defaults to `high` (so only `critical` blocks), and can be
tightened to `low` for production or safety-relevant code.

---

## Design decisions

The interesting part of a project like this is the judgement calls. A few that
shaped DepsGuard:

### 1. Context engineering: compact structured output, not raw API dumps
Each tool returns a small, purpose-built JSON object — version + publish date +
deprecation flag, or licenses + advisory IDs — rather than echoing deps.dev's
full response. The goal is to stay friendly to the agent's context window: the
model gets exactly the fields it needs to decide, and the advisory list is
capped and sorted most-recent-first so a package with hundreds of versions
can't flood the conversation.

### 2. A guardrail, not just a lookup
Data alone still leaves the model to reason about thresholds. Folding the
lookups into a single `ALLOW / WARN / BLOCK` verdict gives the agent (or a CI
job) something to branch on directly, and makes the policy a reviewable,
configurable artifact rather than an implicit prompt instruction.

### 3. Modeling severity from *real* data, including its quirks
Severity is bucketed from the CVSS v3 score (`≥9` critical, `≥7` high, `≥4`
medium, `>0` low). The subtlety: deps.dev returns a score of **`0` with an empty
vector** for advisories that simply have *no* CVSS v3 score yet — not a genuine
0.0. Treating that as `low` would *under*-report risk, so DepsGuard maps it to
`unknown`, which the guardrail then ranks as `medium` (conservative by default).
This only surfaced by exercising the live API; the unit tests were extended to
pin the `score == 0` case.

### 4. The tools are a dependency under test
An agent is only as reliable as the tools it calls, so the tool surface is
treated as a dependency under test on two levels:
- **Offline unit tests** mock the HTTP layer for fast, deterministic checks of
  parsing, URL-encoding (e.g. Maven `groupId:artifactId`, scoped npm names),
  error paths (404/429/network), and the policy logic.
- **Live evals** run against real packages on *stable* ground truth — published
  advisories aren't retracted, so a historically-vulnerable version stays
  vulnerable — and assert invariants rather than brittle exact counts. They run
  weekly in CI as a feedback loop that catches upstream data/API drift.

### 5. Read-only, least privilege, fail-closed
The server makes only read-only `GET`s to a fixed API base (no SSRF surface),
percent-encodes every user-supplied path segment (no path injection), and sets a
request timeout. The LangGraph example **fails closed** — any error in the
lookup becomes a `BLOCK`, never a silent pass. The container runs as an
unprivileged user. For a tool whose whole job is security posture, the tool's
own posture has to match.

### 6. Bounded concurrency
The guardrail expands every advisory on a version. Doing that one blocking
request at a time serializes N round-trips; doing it with unbounded concurrency
could hammer deps.dev for a package with a long advisory list. DepsGuard uses
`asyncio.gather` behind a semaphore — parallel, but capped — and preserves input
order so the reported list stays deterministic.

### 7. Human-in-the-loop where it matters
A `WARN` is exactly the case where automation should pause: advisories exist but
are within policy. The LangGraph gate routes `WARN` to a human-approval step
(via an interrupt), lets `ALLOW` proceed, and stops on `BLOCK`.

### 8. Reproducible, namespaced packaging
The project installs under a single `depsguard` package (no generic top-level
names leaking into site-packages), local development and CI run from an explicit
`.venv`, and the Docker image still builds from the checked-in `uv.lock` with
`uv sync --locked` for byte-reproducible container dependencies.

---

## A worked example

Proposing `urllib3 1.26.4` (a deliberately old, known-vulnerable release):

```
$ evaluate_dependency_policy(pypi, urllib3, 1.26.4, max_severity="medium")
```

DepsGuard looks the version up, finds **13 advisories** affecting it directly
(licenses: `MIT`), expands each for severity, and returns:

```json
{
  "verdict": "BLOCK",
  "package": "pypi:urllib3@1.26.4",
  "policy_max_severity": "medium",
  "worst_severity": "high",
  "reason": "13 advisory(ies); worst severity 'high' exceeds policy max 'medium'."
}
```

→ **BLOCK.** The agent does not apply the change; it reports the offending
advisories and can look up a patched version instead. The same call at
`max_severity="high"` returns **WARN** (there is no `critical` advisory), which
would route to human approval in the LangGraph gate. A clean package returns
**ALLOW**. See [`docs/demo.md`](docs/demo.md) for the full transcript and a
PR-style report.

---

## What it demonstrates

- **AI-native SDLC thinking** — putting guardrails in the agent's path before a
  change lands, not after.
- **Context engineering** for tool design — compact, decision-grade outputs.
- **Guardrails & policy** — composable `ALLOW / WARN / BLOCK` with conservative,
  configurable defaults.
- **Evaluation discipline** — treating tools as a tested dependency, with drift
  detection as a standing feedback loop.
- **Supply-chain security** — OSV/GHSA advisories, CVSS severity, licensing,
  least-privilege execution.
- **MCP integration**, **agentic orchestration** (LangGraph, human-in-the-loop),
  **CI**, and **reproducible containerization**.

---

## Limitations & future work

- Advisories reflect those affecting the selected version **directly** — not
  vulnerabilities inherited from transitive dependencies. Extending the guardrail
  across a full resolved dependency graph (deps.dev exposes one) and adding
  OpenSSF Scorecard signals are the natural next steps; this build scopes to the
  highest-signal tools first.
- License information is advisory context, not legal advice.
- The guardrail is intentionally conservative and should be adapted per
  organization.
- Live data depends on upstream deps.dev/OSV coverage and may drift over time —
  which is precisely why the eval suite runs on a schedule.
