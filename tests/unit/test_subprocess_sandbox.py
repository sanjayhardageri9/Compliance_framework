from __future__ import annotations

import asyncio

from aimw.models import ToolRequest
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox


async def test_default_implementation_returns_success(context_factory):
    sandbox = SubprocessSandbox()
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    result = await sandbox.execute(req, ctx)
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "search_tool.query" in result.stdout


async def test_registered_implementation_is_used(context_factory):
    sandbox = SubprocessSandbox()

    async def echo_impl(request: ToolRequest, context) -> str:
        return f"echoed: {request.parameters.get('msg')}"

    sandbox.register("search_tool", "query", echo_impl)
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool", function_name="query", parameters={"msg": "hi"}, call_id="c1"
    )
    result = await sandbox.execute(req, ctx)
    assert result.stdout == "echoed: hi"


async def test_timeout_produces_failed_result_not_a_hang(context_factory):
    sandbox = SubprocessSandbox(timeout_s=0.05)

    async def slow_impl(request: ToolRequest, context) -> str:
        await asyncio.sleep(5)
        return "should never get here"

    sandbox.register("search_tool", "query", slow_impl)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    result = await sandbox.execute(req, ctx)
    assert result.timed_out is True
    assert result.exit_code == 124


async def test_implementation_exception_is_captured_not_raised(context_factory):
    sandbox = SubprocessSandbox()

    async def broken_impl(request: ToolRequest, context) -> str:
        raise RuntimeError("kaboom")

    sandbox.register("search_tool", "query", broken_impl)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    result = await sandbox.execute(req, ctx)
    assert result.exit_code == 1
    assert "kaboom" in result.stderr
