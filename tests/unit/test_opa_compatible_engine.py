"""OPA-compatible / RegoLite engine — delegates allow/deny to StaticPolicyEngine."""

from __future__ import annotations

import pytest

from aimw.models import ExecutionContext, ToolRequest
from aimw.policy.opa_engine import OpaCompatiblePolicyEngine, RegoLitePolicyEngine
from aimw.policy.rules import PolicyRuleSet, ToolRule


def _ruleset() -> PolicyRuleSet:
    return PolicyRuleSet(
        identity_required_fields=["user_id", "agent_id", "roles"],
        allowed_tools=["shell"],
        tools={
            "shell": ToolRule(
                tool_name="shell",
                allowed_functions=["run"],
                visible_to_roles=["operator"],
            )
        },
        rate_limit_per_session=10,
    )


def _ctx(roles: list[str] | None = None) -> ExecutionContext:
    return ExecutionContext(
        user_id="u1",
        agent_id="a1",
        session_id="s1",
        roles=roles or ["operator"],
        delegated_scopes=[],
    )


def _req(tool: str = "shell", fn: str = "run") -> ToolRequest:
    return ToolRequest(
        tool_name=tool, function_name=fn, parameters={}, call_id="c1"
    )


@pytest.mark.asyncio
async def test_allow_delegates_to_static() -> None:
    engine = RegoLitePolicyEngine(_ruleset())
    decision = await engine.evaluate_tool_call(_ctx(), _req())
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_deny_unknown_tool() -> None:
    engine = OpaCompatiblePolicyEngine(_ruleset())
    decision = await engine.evaluate_tool_call(_ctx(), _req(tool="ftp"))
    assert decision.allowed is False
    assert "not permitted" in decision.reason.lower() or "tool" in decision.reason.lower()


@pytest.mark.asyncio
async def test_deny_missing_role() -> None:
    engine = RegoLitePolicyEngine(_ruleset())
    decision = await engine.evaluate_tool_call(_ctx(roles=["viewer"]), _req())
    assert decision.allowed is False


@pytest.mark.asyncio
async def test_requires_ruleset_or_engine() -> None:
    with pytest.raises(ValueError):
        RegoLitePolicyEngine()


def test_is_base_policy_engine() -> None:
    from aimw.interfaces.policy_engine import BasePolicyEngine

    assert issubclass(RegoLitePolicyEngine, BasePolicyEngine)
    assert OpaCompatiblePolicyEngine is RegoLitePolicyEngine
