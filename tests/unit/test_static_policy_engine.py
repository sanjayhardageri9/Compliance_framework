from __future__ import annotations

import pytest

from aimw.models import ToolRequest
from aimw.policy.errors import PolicyEvaluationError
from aimw.policy.static_engine import StaticPolicyEngine


@pytest.fixture
def engine(example_ruleset):
    return StaticPolicyEngine(example_ruleset)


async def test_allowed_happy_path(engine, context_factory):
    ctx = context_factory(roles=["AgentExecutor"])
    req = ToolRequest(
        tool_name="search_tool", function_name="query", parameters={"q": "weather"}, call_id="c1"
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is True
    assert decision.action_requirements == []


async def test_denied_missing_identity(engine, context_factory):
    ctx = context_factory(roles=[])
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "identity" in decision.reason


async def test_denied_tool_not_allowed(engine, context_factory):
    ctx = context_factory()
    req = ToolRequest(tool_name="shell_tool", function_name="exec", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "tool not permitted" in decision.reason


async def test_denied_function_not_permitted(engine, context_factory):
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool", function_name="delete_index", parameters={}, call_id="c1"
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "function not permitted" in decision.reason


async def test_denied_parameter_deny_pattern(engine, context_factory):
    ctx = context_factory()
    req = ToolRequest(
        tool_name="sql_tool",
        function_name="ExecuteReadOnlyQuery",
        parameters={"query": "DROP TABLE users;"},
        call_id="c1",
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "deny-pattern" in decision.reason


async def test_allowed_sql_benign_query(engine, context_factory):
    ctx = context_factory()
    req = ToolRequest(
        tool_name="sql_tool",
        function_name="ExecuteReadOnlyQuery",
        parameters={"query": "SELECT * FROM users WHERE id = 1"},
        call_id="c1",
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is True


async def test_denied_production_without_role(engine, context_factory):
    ctx = context_factory(roles=["DeployEngineer"])
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "production"},
        call_id="c1",
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "requires one of roles" in decision.reason


async def test_allowed_production_with_role_requires_approval(engine, context_factory):
    ctx = context_factory(roles=["ProductionAdmin"])
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "production"},
        call_id="c1",
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is True
    assert decision.action_requirements == ["human_approval"]


async def test_denied_tool_not_visible_to_role(engine, context_factory):
    ctx = context_factory(roles=["AgentExecutor"])  # lacks DeployEngineer/ProductionAdmin
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "staging"},
        call_id="c1",
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "requires one of roles" in decision.reason


async def test_denied_rate_limit_exceeded(example_ruleset, context_factory):
    engine = StaticPolicyEngine(example_ruleset, call_counter=lambda _sid: 999)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "rate limit" in decision.reason


async def test_internal_exception_raises_policy_evaluation_error(example_ruleset, context_factory):
    def broken_counter(_sid: str) -> int:
        raise RuntimeError("boom")

    engine = StaticPolicyEngine(example_ruleset, call_counter=broken_counter)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    with pytest.raises(PolicyEvaluationError):
        await engine.evaluate_tool_call(ctx, req)
