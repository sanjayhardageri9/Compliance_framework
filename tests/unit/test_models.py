from __future__ import annotations

import pytest
from pydantic import ValidationError

from aimw.models import ExecutionContext, PolicyDecision, ToolRequest


def test_execution_context_requires_all_fields():
    with pytest.raises(ValidationError):
        ExecutionContext(user_id="u1")  # type: ignore[call-arg]


def test_execution_context_valid():
    ctx = ExecutionContext(
        user_id="u1",
        agent_id="a1",
        session_id="s1",
        roles=["AgentExecutor"],
        delegated_scopes=[],
        metadata={},
    )
    assert ctx.user_id == "u1"
    assert ctx.roles == ["AgentExecutor"]


def test_tool_request_valid():
    req = ToolRequest(
        tool_name="search_tool",
        function_name="query",
        parameters={"q": "hello"},
        call_id="call-1",
    )
    assert req.parameters == {"q": "hello"}


def test_policy_decision_action_requirements_default_is_independent_list():
    d1 = PolicyDecision(allowed=True, reason="ok")
    d2 = PolicyDecision(allowed=True, reason="ok")
    d1.action_requirements.append("human_approval")
    assert d2.action_requirements == []


def test_policy_decision_defaults():
    d = PolicyDecision(allowed=False, reason="denied")
    assert d.modified_parameters is None
    assert d.action_requirements == []
