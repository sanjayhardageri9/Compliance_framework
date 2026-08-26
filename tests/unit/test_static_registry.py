from __future__ import annotations

import pytest

from aimw.registry.static_registry import StaticToolRegistry


@pytest.fixture
def registry(example_ruleset):
    return StaticToolRegistry(example_ruleset)


async def test_context_without_deploy_role_does_not_see_deploy_tool(registry, context_factory):
    ctx = context_factory(roles=["AgentExecutor"])
    tools = await registry.get_permitted_tools(ctx)
    names = {t["tool_name"] for t in tools}
    assert "deploy_tool" not in names
    assert "search_tool" in names
    assert "sql_tool" in names


async def test_context_with_deploy_role_sees_deploy_tool(registry, context_factory):
    ctx = context_factory(roles=["DeployEngineer"])
    tools = await registry.get_permitted_tools(ctx)
    names = {t["tool_name"] for t in tools}
    assert "deploy_tool" in names


async def test_least_agency_strict_subset(registry, context_factory):
    narrow_ctx = context_factory(roles=["AgentExecutor"])
    broad_ctx = context_factory(roles=["AgentExecutor", "ProductionAdmin"])
    narrow_names = {t["tool_name"] for t in await registry.get_permitted_tools(narrow_ctx)}
    broad_names = {t["tool_name"] for t in await registry.get_permitted_tools(broad_ctx)}
    assert narrow_names < broad_names


async def test_tool_manifest_includes_allowed_functions(registry, context_factory):
    ctx = context_factory(roles=["AgentExecutor"])
    tools = await registry.get_permitted_tools(ctx)
    sql = next(t for t in tools if t["tool_name"] == "sql_tool")
    assert set(sql["functions"]) == {"ExecuteReadOnlyQuery", "UpdateCustomerRecord"}
