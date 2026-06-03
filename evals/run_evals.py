"""Evaluation harness for depsguard's agent-facing tools.

An agent is only as reliable as the tools it depends on. This harness treats the
MCP tools as a dependency under test and scores them on a labelled set of real
packages: correctness on known-vulnerable versions, structural validity across
ecosystems, and an internal-consistency invariant on the guardrail. It prints
per-case results plus aggregate metrics and exits non-zero on any failure, so it
doubles as an automated feedback loop in CI.

Run (hits live deps.dev):
    uv run python -m evals.run_evals
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import depsguard.server as server


@dataclass
class Result:
    passed: bool
    detail: str


@dataclass
class Case:
    name: str
    kind: str  # for grouping metrics: "correctness" | "coverage" | "consistency"
    run: Callable[[], Awaitable[Result]]


# --- Cases -----------------------------------------------------------------
# Ground truth is chosen to be STABLE: published advisories are not retracted,
# so a historically-vulnerable version stays vulnerable. We avoid asserting
# "zero advisories" (which can change over time) and prefer invariants.


async def _vulnerable_version_is_flagged() -> Result:
    """urllib3 1.26.4 has long-standing security advisories."""
    out = await server.get_version_details("pypi", "urllib3", "1.26.4")
    ok = out["advisory_count"] >= 1 and "MIT" in out["licenses"]
    return Result(
        ok,
        f"advisory_count={out['advisory_count']}, licenses={out['licenses']}",
    )


async def _package_listing_is_well_formed() -> Result:
    out = await server.get_package_info("pypi", "requests")
    ok = (
        out["name"] == "requests"
        and out["total_versions"] > 0
        and isinstance(out["default_version"], str)
    )
    return Result(
        ok,
        (
            f"name={out['name']}, total_versions={out['total_versions']}, "
            f"default={out['default_version']}"
        ),
    )


async def _advisory_details_resolve() -> Result:
    """First advisory on the vulnerable version must expand to a usable record."""
    ver = await server.get_version_details("pypi", "urllib3", "1.26.4")
    adv = await server.get_advisory_details(ver["advisory_ids"][0])
    ok = adv["severity"] in {
        "low",
        "medium",
        "high",
        "critical",
        "unknown",
    } and bool(adv["url"])
    return Result(ok, f"id={adv['id']}, severity={adv['severity']}")


async def _cargo_ecosystem_reachable() -> Result:
    """Coverage check for Rust/Cargo. Structural only."""
    out = await server.get_version_details("cargo", "serde", "1.0.197")
    ok = out["version"] == "1.0.197" and isinstance(out["licenses"], list)
    return Result(ok, f"version={out['version']}, licenses={out['licenses']}")


async def _maven_ecosystem_reachable() -> Result:
    """Coverage check for Java/Kotlin/Maven."""
    out = await server.get_version_details(
        "maven",
        "com.google.guava:guava",
        "33.0.0-jre",
    )
    ok = out["version"] == "33.0.0-jre" and isinstance(out["licenses"], list)
    return Result(ok, f"version={out['version']}, licenses={out['licenses']}")


async def _guardrail_is_consistent() -> Result:
    """Invariant: the guardrail verdict must agree with the advisory data it saw."""
    v = await server.evaluate_dependency_policy(
        "pypi",
        "urllib3",
        "1.26.4",
        max_severity="low",
    )
    has_adv = len(v["advisories"]) > 0
    # With max_severity='low', any advisory must produce WARN or BLOCK, never ALLOW.
    ok = (v["verdict"] != "ALLOW") if has_adv else (v["verdict"] == "ALLOW")
    return Result(
        ok,
        (
            f"verdict={v['verdict']}, advisories={len(v['advisories'])}, "
            f"worst={v['worst_severity']}"
        ),
    )


CASES: list[Case] = [
    Case(
        "vulnerable_version_is_flagged",
        "correctness",
        _vulnerable_version_is_flagged,
    ),
    Case(
        "package_listing_is_well_formed",
        "correctness",
        _package_listing_is_well_formed,
    ),
    Case("advisory_details_resolve", "correctness", _advisory_details_resolve),
    Case("cargo_ecosystem_reachable", "coverage", _cargo_ecosystem_reachable),
    Case("maven_ecosystem_reachable", "coverage", _maven_ecosystem_reachable),
    Case("guardrail_is_consistent", "consistency", _guardrail_is_consistent),
]


async def run_suite() -> int:
    results: list[tuple[Case, Result]] = []
    for case in CASES:
        try:
            res = await case.run()
        except Exception as exc:  # a thrown tool is a failed eval, not a crash
            res = Result(False, f"ERROR: {type(exc).__name__}: {exc}")
        results.append((case, res))
        mark = "PASS" if res.passed else "FAIL"
        print(f"[{mark}] {case.name:<34} {res.detail}")

    total = len(results)
    passed = sum(1 for _, r in results if r.passed)
    by_kind: dict[str, list[bool]] = {}
    for case, r in results:
        by_kind.setdefault(case.kind, []).append(r.passed)

    print("\n--- metrics ---")
    print(f"overall: {passed}/{total} ({passed / total:.0%})")
    for kind, flags in sorted(by_kind.items()):
        print(f"  {kind}: {sum(flags)}/{len(flags)}")

    return 0 if passed == total else 1


def main() -> None:
    sys.exit(asyncio.run(run_suite()))


if __name__ == "__main__":
    main()
