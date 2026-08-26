from __future__ import annotations

import pytest

from aimw.models import ToolRequest
from aimw.policy.db_engine import DbBackedPolicyEngine
from aimw.policy.errors import PolicyEvaluationError


@pytest.fixture
def engine(db_store):
    return DbBackedPolicyEngine(db_store)


async def test_allowed_happy_path(engine, context_factory):
    ctx = context_factory(roles=["AgentExecutor"])
    req = ToolRequest(
        tool_name="search_tool", function_name="query", parameters={"q": "weather"}, call_id="c1"
    )
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is True


async def test_denied_missing_identity(engine, context_factory):
    ctx = context_factory(roles=[])
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "identity" in decision.reason


async def test_denied_global_rbac_unknown_role(engine, context_factory):
    ctx = context_factory(roles=["NotARealRole"])
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "global RBAC" in decision.reason


async def test_denied_tool_not_in_store(engine, context_factory):
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


async def test_denied_rate_limit_exceeded(db_store, context_factory):
    engine = DbBackedPolicyEngine(db_store, call_counter=lambda _sid: 999)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    decision = await engine.evaluate_tool_call(ctx, req)
    assert decision.allowed is False
    assert "rate limit" in decision.reason


async def test_live_rule_update_takes_effect_without_restart(db_store, context_factory):
    """The whole point of DB-backed rules: an UPDATE is visible on the next call."""
    engine = DbBackedPolicyEngine(db_store)
    ctx = context_factory()
    req = ToolRequest(
        tool_name="search_tool", function_name="crawl", parameters={}, call_id="c1"
    )
    before = await engine.evaluate_tool_call(ctx, req)
    assert before.allowed is False

    db_store._conn.execute(
        "INSERT INTO tool_functions (tool_name, function_name, requires_approval) "
        "VALUES ('search_tool', 'crawl', 0)"
    )
    db_store._conn.commit()

    after = await engine.evaluate_tool_call(ctx, req)
    assert after.allowed is True


async def test_internal_exception_raises_policy_evaluation_error(db_store, context_factory):
    def broken_counter(_sid: str) -> int:
        raise RuntimeError("boom")

    engine = DbBackedPolicyEngine(db_store, call_counter=broken_counter)
    ctx = context_factory()
    req = ToolRequest(tool_name="search_tool", function_name="query", parameters={}, call_id="c1")
    with pytest.raises(PolicyEvaluationError):
        await engine.evaluate_tool_call(ctx, req)
