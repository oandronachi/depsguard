"""depsguard — an MCP server that gives AI coding assistants dependency context.

Part of an AI-native SDLC: when an agent (Claude Code, Cursor, Copilot) is about
to add or upgrade a dependency, these tools feed it decision-grade context from
Google's deps.dev (Open Source Insights) — versions, licenses, and the OSV/GHSA
security advisories affecting a given version — plus a policy *guardrail* that
returns an ALLOW / WARN / BLOCK verdict the agent or a CI step can act on.

Covers 7 ecosystems including the ones automotive software ships in: Cargo
(Rust) and Maven (Java/Kotlin), alongside npm, PyPI, Go, NuGet, and RubyGems.

No API key. No account. Free. Data is CC-BY 4.0 (Google deps.dev).
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = "https://api.deps.dev/v3"
USER_AGENT = "depsguard-mcp/0.1 (+https://github.com/oandronachi/depsguard)"
TIMEOUT = httpx.Timeout(15.0)

# deps.dev expects the ecosystem in UPPER CASE in the path.
Ecosystem = Literal["pypi", "npm", "cargo", "maven", "go", "nuget", "rubygems"]

mcp = FastMCP("depsguard")


async def _get(path: str) -> dict[str, Any]:
    """GET a deps.dev endpoint and return parsed JSON.

    Opens the client per-call (not at startup) so the server still lists its
    tools even if the network is down. Raises a clean message on 404 / errors.
    """
    url = f"{API_BASE}/{path}"
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        try:
            resp = await client.get(url)
        except httpx.RequestError as exc:
            raise RuntimeError(f"Could not reach deps.dev: {exc}") from exc

    if resp.status_code == 404:
        raise RuntimeError(
            "Not found on deps.dev. Check the ecosystem, name, and version "
            "(names are case-sensitive; deps.dev only indexes published releases)."
        )
    if resp.status_code == 429:
        raise RuntimeError("deps.dev is rate-limiting right now. Wait a moment and retry.")
    resp.raise_for_status()
    return resp.json()


def _sys(ecosystem: str) -> str:
    eco = ecosystem.strip().lower()
    valid = {"pypi", "npm", "cargo", "maven", "go", "nuget", "rubygems"}
    if eco not in valid:
        valid_list = ", ".join(sorted(valid))
        raise ValueError(f"Unknown ecosystem '{ecosystem}'. Use one of: {valid_list}.")
    return eco.upper()


_SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Bound the guardrail's advisory fan-out so a version with a long advisory list
# can't open an unbounded number of concurrent connections to deps.dev.
_MAX_CONCURRENT_ADVISORY_LOOKUPS = 8


def _severity_from_score(score: Any) -> str:
    # deps.dev uses 0 for "no v3 score".
    if isinstance(score, (int, float)) and score > 0:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    return "unknown"


def _severity_rank(severity: str) -> int:
    if severity in _SEVERITY_ORDER:
        return _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER.index("medium")


@mcp.tool()
async def get_package_info(ecosystem: Ecosystem, name: str) -> dict[str, Any]:
    """Look up an open-source package and list its available versions.

    Use this first when the user names a package but not a version, or asks
    "what versions of X exist?" / "what's the latest X?". Returns the package
    name (canonicalized), the total version count, the default/latest version,
    and the most recent versions with their publish dates and deprecation flags.

    ecosystem: one of pypi, npm, cargo, maven, go, nuget, rubygems.
    name: the package name as used in that ecosystem (e.g. "requests",
        "react", "org.apache.logging.log4j:log4j-core" for Maven).
    """
    system = _sys(ecosystem)
    data = await _get(f"systems/{system}/packages/{quote(name, safe='')}")
    versions = data.get("versions", [])
    default = next((v for v in versions if v.get("isDefault")), None)

    def _fmt(v: dict[str, Any]) -> dict[str, Any]:
        vk = v.get("versionKey", {})
        out = {"version": vk.get("version"), "published_at": v.get("publishedAt")}
        if v.get("isDefault"):
            out["is_default"] = True
        if v.get("isDeprecated"):
            out["deprecated"] = True
            if v.get("deprecatedReason"):
                out["deprecated_reason"] = v["deprecatedReason"]
        return out

    # Most recent first, capped so we don't flood the model's context.
    recent = sorted(
        versions, key=lambda v: v.get("publishedAt") or "", reverse=True
    )[:15]

    return {
        "ecosystem": ecosystem.lower(),
        "name": data.get("packageKey", {}).get("name", name),
        "total_versions": len(versions),
        "default_version": (default or {}).get("versionKey", {}).get("version"),
        "recent_versions": [_fmt(v) for v in recent],
    }


@mcp.tool()
async def get_version_details(
    ecosystem: Ecosystem,
    name: str,
    version: str,
) -> dict[str, Any]:
    """Get licenses, source links, and KNOWN SECURITY ADVISORIES for one exact version.

    Use this when the user asks "is X@VERSION safe?", "what license does
    X@VERSION use?", or wants the advisory IDs affecting a specific release.
    The returned advisory_ids are OSV/GHSA identifiers — pass any of them to
    `get_advisory_details` to get severity (CVSS) and a description.

    Note: advisories listed here affect THIS version directly; they do not
    include vulnerabilities inherited from its dependencies.

    ecosystem: one of pypi, npm, cargo, maven, go, nuget, rubygems.
    name: the package name in that ecosystem.
    version: the exact version string (e.g. "2.31.0").
    """
    system = _sys(ecosystem)
    encoded_name = quote(name, safe="")
    encoded_version = quote(version, safe="")
    data = await _get(
        f"systems/{system}/packages/{encoded_name}/versions/{encoded_version}"
    )
    advisory_ids = [a.get("id") for a in data.get("advisoryKeys", []) if a.get("id")]
    source = next(
        (l.get("url") for l in data.get("links", []) if l.get("label") == "SOURCE_REPO"),
        None,
    )
    return {
        "ecosystem": ecosystem.lower(),
        "name": data.get("versionKey", {}).get("name", name),
        "version": data.get("versionKey", {}).get("version", version),
        "published_at": data.get("publishedAt"),
        "licenses": data.get("licenses", []),
        "is_deprecated": bool(data.get("isDeprecated", False)),
        "source_repo": source,
        "advisory_count": len(advisory_ids),
        "advisory_ids": advisory_ids,
        "_hint": (
            "No known direct advisories for this version."
            if not advisory_ids
            else "Call get_advisory_details on each advisory id for severity and details."
        ),
    }


@mcp.tool()
async def get_advisory_details(advisory_id: str) -> dict[str, Any]:
    """Get severity and a description for an OSV/GHSA security advisory.

    Use this after `get_version_details` returns advisory_ids, or whenever the
    user gives you an advisory identifier directly (e.g. "GHSA-2qrg-x229-3v8q"
    or a CVE that maps to one). Returns the title, CVSS v3 score and vector,
    aliases (including CVEs), and a link to the full advisory.

    advisory_id: an OSV identifier such as "GHSA-xxxx-xxxx-xxxx".
    """
    aid = advisory_id.strip()
    data = await _get(f"advisories/{quote(aid, safe='')}")
    score = data.get("cvss3Score")
    severity = _severity_from_score(score)
    return {
        "id": data.get("advisoryKey", {}).get("id", aid),
        "title": data.get("title"),
        "severity": severity,
        "cvss3_score": score,
        "cvss3_vector": data.get("cvss3Vector"),
        "aliases": data.get("aliases", []),
        "url": data.get("url"),
    }


@mcp.tool()
async def evaluate_dependency_policy(
    ecosystem: Ecosystem,
    name: str,
    version: str,
    max_severity: Literal["low", "medium", "high", "critical"] = "high",
) -> dict[str, Any]:
    """Guardrail: should this dependency be ADDED/UPGRADED to? Returns ALLOW/WARN/BLOCK.

    Composes the lookup tools into one verdict an agent (or a CI step) can act on
    *before* it modifies a project's dependencies — the kind of automated
    validation of software artefacts an AI-native SDLC needs.

    Policy:
      - BLOCK if any known advisory's severity exceeds `max_severity`.
      - WARN  if advisories exist but none exceed `max_severity`.
      - ALLOW if no known direct advisories.

    ecosystem: one of pypi, npm, cargo, maven, go, nuget, rubygems.
    name / version: the exact package and version under consideration.
    max_severity: the highest advisory severity tolerated before blocking
        (default "high" blocks only "critical"; set "low" to block anything).
    """
    if max_severity not in _SEVERITY_ORDER:
        valid_list = ", ".join(_SEVERITY_ORDER)
        raise ValueError(
            f"Unknown max_severity '{max_severity}'. Use one of: {valid_list}."
        )

    details = await get_version_details(ecosystem, name, version)
    threshold = _SEVERITY_ORDER.index(max_severity)

    # Expand advisories concurrently (bounded) rather than one blocking GET at a
    # time; gather preserves order, so the reported list stays deterministic.
    sem = asyncio.Semaphore(_MAX_CONCURRENT_ADVISORY_LOOKUPS)

    async def _expand(aid: str) -> dict[str, Any]:
        async with sem:
            return await get_advisory_details(aid)

    adv_records = await asyncio.gather(
        *(_expand(aid) for aid in details["advisory_ids"])
    )

    advisories: list[dict[str, Any]] = []
    worst_rank = -1
    worst_severity: str | None = None
    for adv in adv_records:
        sev = adv["severity"]
        rank = _severity_rank(sev)
        if rank > worst_rank:
            worst_rank = rank
            worst_severity = sev
        advisories.append(
            {
                "id": adv["id"],
                "severity": sev,
                "title": adv["title"],
                "url": adv["url"],
            }
        )

    if not advisories:
        verdict, reason = "ALLOW", "No known direct advisories for this version."
    elif worst_rank > threshold:
        verdict = "BLOCK"
        reason = (
            f"{len(advisories)} advisory(ies); worst severity "
            f"'{worst_severity}' exceeds policy max '{max_severity}'."
        )
    else:
        verdict = "WARN"
        reason = (
            f"{len(advisories)} advisory(ies) present but within policy max "
            f"'{max_severity}'. Review before merging."
        )

    return {
        "verdict": verdict,
        "package": f"{ecosystem.lower()}:{details['name']}@{details['version']}",
        "policy_max_severity": max_severity,
        "worst_severity": worst_severity,
        "licenses": details["licenses"],
        "advisories": advisories,
        "reason": reason,
    }


def main() -> None:
    """Console entry point so the server is runnable via `depsguard` / `uvx`."""
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
