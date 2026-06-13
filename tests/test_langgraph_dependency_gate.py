import io
import sys

import pytest

pytest.importorskip("langgraph")

from examples import langgraph_dependency_gate as gate


def test_stdio_defaults_use_active_python_interpreter():
    args = gate.parse_args(["pypi", "urllib3", "1.26.4"])

    assert args.server_command == sys.executable
    assert args.server_arg is None


class _TtyEof(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.asyncio
async def test_warn_interrupt_eof_returns_pause_code(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _TtyEof(""))
    args = gate.parse_args(
        [
            "pypi",
            "urllib3",
            "1.26.4",
            "--transport",
            "mock",
            "--json",
        ]
    )

    code = await gate.run(args)
    captured = capsys.readouterr()

    assert code == 2
    assert "dependency_policy_warning" in captured.out
    assert "Graph paused for human approval" in captured.err
