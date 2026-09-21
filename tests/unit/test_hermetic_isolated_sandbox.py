"""HermeticIsolatedSandbox — SubprocessSandbox wrapper with allowlist + timeout."""

from __future__ import annotations

import asyncio

import pytest

from aimw.models import ExecutionContext, ToolRequest
from aimw.sandbox.e2b_sandbox import HermeticIsolatedSandbox


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        user_id="u1",
        agent_id="a1",
        session_id="s1",
        roles=["operator"],
        delegated_scopes=[],
    )


def _req(tool: str = "shell", fn: str = "echo") -> ToolRequest:
    return ToolRequest(
        tool_name=tool, function_name=fn, parameters={}, call_id="c1"
    )


@pytest.mark.asyncio
async def test_default_execute_ok() -> None:
    sb = HermeticIsolatedSandbox(timeout_s=1.0)
    result = await sb.execute(_req(), _ctx())
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "shell.echo" in result.stdout


@pytest.mark.asyncio
async def test_allowlist_denies_unknown() -> None:
    sb = HermeticIsolatedSandbox(
        timeout_s=1.0,
        allowed_commands=["shell.echo"],
    )
    denied = await sb.execute(_req(tool="curl", fn="get"), _ctx())
    assert denied.exit_code == 126
    assert "allowlist" in denied.stderr.lower()

    allowed = await sb.execute(_req(), _ctx())
    assert allowed.exit_code == 0


@pytest.mark.asyncio
async def test_stricter_timeout() -> None:
    async def slow(request, context):  # noqa: ANN001
        await asyncio.sleep(2.0)
        return "late"

    sb = HermeticIsolatedSandbox(timeout_s=0.1)
    sb.register("shell", "slow", slow)
    result = await sb.execute(_req(fn="slow"), _ctx())
    assert result.timed_out is True
    assert result.exit_code == 124


def test_is_base_sandbox() -> None:
    from aimw.sandbox.base import BaseSandbox

    assert issubclass(HermeticIsolatedSandbox, BaseSandbox)


def test_ignores_e2b_credentials() -> None:
    sb = HermeticIsolatedSandbox(api_key="should-not-leak", template_id="tpl")
    assert sb.api_key is None
    assert sb.template_id is None
