"""LangGraph dependency gate example for depsguard.

This is a small, runnable example of an agentic dependency-review workflow:

1. A proposed dependency add/upgrade enters a LangGraph StateGraph.
2. The graph calls depsguard's evaluate_dependency_policy tool.
3. ALLOW proceeds, BLOCK fails closed, and WARN pauses for approval.
4. The graph emits a PR-style Markdown report.

Default mode uses a real MCP stdio client and launches depsguard with the
active Python interpreter. In normal use, run this from the project `.venv`.
Use `--transport direct` to call the local Python tool function directly, or
`--transport mock` for a deterministic offline demo.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Literal, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

Severity = Literal["low", "medium", "high", "critical"]
Transport = Literal["stdio", "direct", "mock"]
ApprovalMode = Literal["interrupt", "approve", "reject"]

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
DEFAULT_SERVER_COMMAND = sys.executable
DEFAULT_SERVER_ARGS = ["-m", "depsguard.server"]


class GateState(TypedDict, total=False):
    ecosystem: str
    name: str
    version: str
    max_severity: Severity
    transport: Transport
    server_command: str
    server_args: list[str]
    approval_mode: ApprovalMode
    policy: dict[str, Any]
    verdict: str
    decision: str
    status: str
    final_verdict: str
    agent_action: str
    human_approved: bool
    error: str
    report: str


def severity_rank(severity: str) -> int:
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER.index("medium")


async def call_policy(state: GateState) -> dict[str, Any]:
    request = {
        "ecosystem": state["ecosystem"],
        "name": state["name"],
        "version": state["version"],
        "max_severity": state["max_severity"],
    }

    transport = state.get("transport", "stdio")
    if transport == "mock":
        return mock_policy(request)
    if transport == "direct":
        return await call_policy_direct(request)
    if transport == "stdio":
        return await call_policy_stdio(
            request,
            state.get("server_command", DEFAULT_SERVER_COMMAND),
            state.get("server_args", DEFAULT_SERVER_ARGS),
        )
    raise ValueError(f"Unknown transport: {transport}")


async def call_policy_direct(request: dict[str, Any]) -> dict[str, Any]:
    import depsguard.server as server

    return await server.evaluate_dependency_policy(**request)


async def call_policy_stdio(
    request: dict[str, Any],
    command: str,
    args: list[str],
) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=args)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "evaluate_dependency_policy",
                arguments=request,
            )
    return extract_mcp_tool_result(result)


def extract_mcp_tool_result(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured

    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured

    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            decoded = json.loads(text)
            if isinstance(decoded, dict):
                return decoded

    raise RuntimeError(f"Could not decode MCP tool result: {result!r}")


def mock_policy(request: dict[str, Any]) -> dict[str, Any]:
    package = f"{request['ecosystem']}:{request['name']}@{request['version']}"
    max_severity = request["max_severity"]

    vulnerable = (
        request["ecosystem"] == "pypi"
        and request["name"].lower() == "urllib3"
        and request["version"] == "1.26.4"
    )
    if not vulnerable:
        return {
            "verdict": "ALLOW",
            "package": package,
            "policy_max_severity": max_severity,
            "worst_severity": None,
            "licenses": ["MIT"],
            "advisories": [],
            "reason": "Mock policy: no known direct advisories for this version.",
        }

    advisory = {
        "id": "GHSA-2xpw-w6gg-jr37",
        "severity": "high",
        "title": "Mock urllib3 vulnerable-version advisory",
        "url": "https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37",
    }
    worst = advisory["severity"]
    verdict = (
        "BLOCK"
        if severity_rank(worst) > severity_rank(max_severity)
        else "WARN"
    )
    reason = (
        f"Mock policy: 1 advisory; worst severity '{worst}' exceeds policy max "
        f"'{max_severity}'."
        if verdict == "BLOCK"
        else f"Mock policy: 1 advisory present but within policy max '{max_severity}'."
    )
    return {
        "verdict": verdict,
        "package": package,
        "policy_max_severity": max_severity,
        "worst_severity": worst,
        "licenses": ["MIT"],
        "advisories": [advisory],
        "reason": reason,
    }


async def evaluate_policy_node(state: GateState) -> dict[str, Any]:
    try:
        policy = await call_policy(state)
    except Exception as exc:
        policy = {
            "verdict": "BLOCK",
            "package": f"{state['ecosystem']}:{state['name']}@{state['version']}",
            "policy_max_severity": state["max_severity"],
            "worst_severity": None,
            "licenses": [],
            "advisories": [],
            "reason": (
                "depsguard policy lookup failed closed: "
                f"{type(exc).__name__}: {exc}"
            ),
        }
        return {
            "policy": policy,
            "verdict": "BLOCK",
            "decision": "BLOCK",
            "error": policy["reason"],
        }

    verdict = str(policy.get("verdict", "BLOCK")).upper()
    update: dict[str, Any] = {"policy": policy, "verdict": verdict}
    if verdict == "ALLOW":
        update["decision"] = "ALLOW"
    elif verdict == "BLOCK":
        update["decision"] = "BLOCK"
    return update


def route_policy(state: GateState) -> str:
    return "approval" if state.get("verdict") == "WARN" else "report"


def approval_node(state: GateState) -> dict[str, Any]:
    mode = state.get("approval_mode", "interrupt")
    if mode == "approve":
        approved = True
    elif mode == "reject":
        approved = False
    else:
        response = interrupt(
            {
                "kind": "dependency_policy_warning",
                "message": (
                    "depsguard returned WARN. A human must approve before "
                    "proceeding."
                ),
                "package": state["policy"].get("package"),
                "policy": state["policy"],
                "report": render_report(state, pending=True),
            }
        )
        approved = coerce_approval(response)

    return {
        "human_approved": approved,
        "decision": "ALLOW" if approved else "BLOCK",
    }


def coerce_approval(response: Any) -> bool:
    if isinstance(response, bool):
        return response
    if isinstance(response, str):
        return response.strip().lower() in {
            "y",
            "yes",
            "approve",
            "approved",
            "true",
        }
    if isinstance(response, dict):
        return bool(response.get("approved"))
    return False


def report_node(state: GateState) -> dict[str, Any]:
    decision = state.get("decision")
    if not decision:
        decision = "ALLOW" if state.get("verdict") == "ALLOW" else "BLOCK"
    final_state = finalize_state({**state, "decision": decision})
    return {
        "decision": final_state["decision"],
        "status": final_state["status"],
        "final_verdict": final_state["final_verdict"],
        "agent_action": final_state["agent_action"],
        "report": render_report(final_state),
    }


def build_graph():
    builder = StateGraph(GateState)
    builder.add_node("evaluate_policy", evaluate_policy_node)
    builder.add_node("approval", approval_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "evaluate_policy")
    builder.add_conditional_edges(
        "evaluate_policy",
        route_policy,
        {"approval": "approval", "report": "report"},
    )
    builder.add_edge("approval", "report")
    builder.add_edge("report", END)

    return builder.compile(checkpointer=MemorySaver())


def render_report(state: GateState, pending: bool = False) -> str:
    policy = state["policy"]
    verdict = policy.get("verdict", state.get("verdict", "UNKNOWN"))
    decision = "PENDING HUMAN APPROVAL" if pending else state.get("decision", verdict)
    status = "pending_human_approval" if pending else state.get("status", "unknown")
    final_verdict = "PENDING" if pending else state.get("final_verdict", decision)
    agent_action = (
        "Wait for a human to approve or reject the WARN result."
        if pending
        else state.get(
            "agent_action",
            agent_action_for_policy(policy, state.get("human_approved")),
        )
    )
    advisories = policy.get("advisories", [])
    licenses = policy.get("licenses", [])

    lines = [
        "## Dependency Gate Report",
        "",
        f"- Package: `{policy.get('package', package_label(state))}`",
        f"- depsguard verdict: `{verdict}`",
        f"- Workflow decision: `{decision}`",
        f"- Status: `{status}`",
        f"- Final verdict: `{final_verdict}`",
        (
            "- Policy max severity: "
            f"`{policy.get('policy_max_severity', state.get('max_severity'))}`"
        ),
        f"- Worst severity: `{policy.get('worst_severity') or 'none'}`",
        f"- Licenses: `{', '.join(licenses) if licenses else 'unknown'}`",
        f"- Reason: {policy.get('reason', 'No reason returned.')}",
    ]

    if state.get("error"):
        lines.append(f"- Error: `{state['error']}`")

    lines.extend(["", "### Advisories", ""])
    if not advisories:
        lines.append("No known direct advisories were returned for this version.")
    else:
        lines.extend(
            [
                "| Severity | Advisory | Title | URL |",
                "|---|---|---|---|",
            ]
        )
        for advisory in advisories:
            url = advisory.get("url") or ""
            linked_url = f"[link]({url})" if url else ""
            lines.append(
                "| {severity} | `{id}` | {title} | {url} |".format(
                    severity=advisory.get("severity", "unknown"),
                    id=advisory.get("id", "unknown"),
                    title=str(advisory.get("title") or "").replace("|", "\\|"),
                    url=linked_url,
                )
            )

    lines.extend(
        [
            "",
            (
                "> Note: depsguard reports advisories affecting the selected "
                "package version directly; it does not resolve the full "
                "transitive dependency graph."
            ),
            "",
            "### Final Outcome",
            "",
            f"**Status:** `{status}`",
            f"**Final verdict:** `{final_verdict}`",
            f"**Required agent action:** {agent_action}",
        ]
    )
    return "\n".join(lines)


def finalize_state(state: GateState) -> GateState:
    policy = state["policy"]
    verdict = str(policy.get("verdict", state.get("verdict", "BLOCK"))).upper()
    decision = state.get("decision") or ("ALLOW" if verdict == "ALLOW" else "BLOCK")
    human_approved = state.get("human_approved")

    if verdict == "ALLOW" and decision == "ALLOW":
        status = "approved"
        final_verdict = "ALLOW"
    elif verdict == "WARN" and decision == "ALLOW":
        status = "approved_with_warning"
        final_verdict = "WARN_APPROVED"
        human_approved = True if human_approved is None else human_approved
    elif verdict == "WARN":
        status = "rejected"
        final_verdict = "WARN_REJECTED"
        human_approved = False if human_approved is None else human_approved
    else:
        status = "blocked"
        final_verdict = "BLOCK"

    agent_action = agent_action_for_policy(policy, human_approved)
    return {
        **state,
        "decision": decision,
        "status": status,
        "final_verdict": final_verdict,
        "human_approved": bool(human_approved) if human_approved is not None else False,
        "agent_action": agent_action,
    }


def agent_action_for_policy(
    policy: dict[str, Any],
    human_approved: bool | None = None,
) -> str:
    verdict = str(policy.get("verdict", "BLOCK")).upper()
    if verdict == "ALLOW":
        return "Proceed with the dependency change and keep the license visible in the PR."
    if verdict == "WARN":
        if human_approved:
            return "Proceed only because a human explicitly approved the WARN result."
        return "Do not apply the dependency change until a human approves the WARN result."
    return (
        "Do not apply the dependency change. Propose a safer version or route "
        "to security review."
    )


def package_label(state: GateState) -> str:
    return f"{state['ecosystem']}:{state['name']}@{state['version']}"


def default_thread_id(args: argparse.Namespace) -> str:
    raw = f"dependency-gate:{args.ecosystem}:{args.name}:{args.version}"
    return "".join(ch if ch.isalnum() or ch in ".:-_" else "_" for ch in raw)


def extract_interrupt_payload(result: dict[str, Any]) -> Any:
    interrupts = result.get("__interrupt__") or []
    if not interrupts:
        return None
    first = interrupts[0]
    return getattr(first, "value", first)


def print_noninteractive_pause_message() -> None:
    print(
        "\nGraph paused for human approval. Re-run with "
        "`--auto-approve-warn` or `--reject-warn` for non-interactive demos.",
        file=sys.stderr,
    )


async def run(args: argparse.Namespace) -> int:
    approval_mode: ApprovalMode = "interrupt"
    if args.auto_approve_warn:
        approval_mode = "approve"
    elif args.reject_warn:
        approval_mode = "reject"

    server_args = args.server_arg if args.server_arg else list(DEFAULT_SERVER_ARGS)
    initial_state: GateState = {
        "ecosystem": args.ecosystem,
        "name": args.name,
        "version": args.version,
        "max_severity": args.max_severity,
        "transport": args.transport,
        "server_command": args.server_command,
        "server_args": server_args,
        "approval_mode": approval_mode,
    }

    graph = build_graph()
    config = {"configurable": {"thread_id": args.thread_id or default_thread_id(args)}}
    result = await graph.ainvoke(initial_state, config)

    interrupt_payload = extract_interrupt_payload(result)
    if interrupt_payload is not None:
        print(json.dumps(interrupt_payload, indent=2, sort_keys=True))
        if not sys.stdin.isatty():
            print_noninteractive_pause_message()
            return 2

        try:
            answer = input("\nApprove this WARN dependency change? [y/N] ")
        except EOFError:
            print_noninteractive_pause_message()
            return 2

        result = await graph.ainvoke(
            Command(resume={"approved": coerce_approval(answer)}),
            config,
        )

    if args.json:
        print(json.dumps(jsonable(result), indent=2, sort_keys=True))
    else:
        print(result["report"])
    return 0 if result.get("decision") == "ALLOW" else 1


def jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [jsonable(item) for item in value]
        return repr(value)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a LangGraph dependency gate backed by depsguard.",
    )
    parser.add_argument(
        "ecosystem",
        choices=["pypi", "npm", "cargo", "maven", "go", "nuget", "rubygems"],
    )
    parser.add_argument("name")
    parser.add_argument("version")
    parser.add_argument("--max-severity", choices=SEVERITY_ORDER, default="high")
    parser.add_argument(
        "--transport",
        choices=["stdio", "direct", "mock"],
        default="stdio",
    )
    parser.add_argument(
        "--thread-id",
        help="LangGraph checkpoint thread_id. Defaults to a package-derived ID.",
    )
    parser.add_argument(
        "--server-command",
        default=DEFAULT_SERVER_COMMAND,
        help="MCP stdio server command for --transport stdio.",
    )
    parser.add_argument(
        "--server-arg",
        action="append",
        help=(
            "MCP stdio server argument. Repeat to override the default: "
            "-m depsguard.server."
        ),
    )

    approval = parser.add_mutually_exclusive_group()
    approval.add_argument(
        "--auto-approve-warn",
        action="store_true",
        help="Approve WARN results without interrupting.",
    )
    approval.add_argument(
        "--reject-warn",
        action="store_true",
        help="Reject WARN results without interrupting.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the final graph state as JSON instead of Markdown.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(run(parse_args(argv or sys.argv[1:])))


if __name__ == "__main__":
    raise SystemExit(main())
