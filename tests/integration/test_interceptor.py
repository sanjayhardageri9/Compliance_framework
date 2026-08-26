from __future__ import annotations

import asyncio

import pytest

from aimw.audit.worm_log import HashChainedJSONLLogger, verify_chain
from aimw.hitl.approval import InMemoryApprovalQueue
from aimw.interceptor import ToolCallInterceptor
from aimw.interfaces.policy_engine import BasePolicyEngine
from aimw.models import PolicyDecision, ToolRequest
from aimw.policy.static_engine import StaticPolicyEngine
from aimw.reliability.circuit_breaker import CircuitBreaker, InMemoryCircuitBreakerBackend
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox


class RaisingPolicyEngine(BasePolicyEngine):
    async def evaluate_tool_call(self, context, request) -> PolicyDecision:
        raise RuntimeError("policy engine is broken")


class HangingPolicyEngine(BasePolicyEngine):
    async def evaluate_tool_call(self, context, request) -> PolicyDecision:
        await asyncio.sleep(60)
        return PolicyDecision(allowed=True, reason="unreachable")


class UnsupportedRequirementPolicyEngine(BasePolicyEngine):
    async def evaluate_tool_call(self, context, request) -> PolicyDecision:
        return PolicyDecision(
            allowed=True,
            reason="approved with a novel requirement",
            action_requirements=["dual_control"],
        )


class ApprovalRequiredPolicyEngine(BasePolicyEngine):
    async def evaluate_tool_call(self, context, request) -> PolicyDecision:
        return PolicyDecision(
            allowed=True, reason="pending approval", action_requirements=["human_approval"]
        )


class RaisingSandbox(SubprocessSandbox):
    async def execute(self, request, context):
        raise RuntimeError("sandbox exploded")


def _req(call_id: str = "c1") -> ToolRequest:
    return ToolRequest(
        tool_name="search_tool", function_name="query", parameters={"q": "x"}, call_id=call_id
    )


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


async def test_allowed_call_executes_and_audits(example_ruleset, audit_path, context_factory):
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is True
    assert result.sandbox_result is not None
    assert result.sandbox_result.exit_code == 0
    assert verify_chain(audit_path).valid is True
    assert verify_chain(audit_path).record_count == 1


async def test_denied_call_never_reaches_sandbox(example_ruleset, audit_path, context_factory):
    executed = False

    class SpySandbox(SubprocessSandbox):
        async def execute(self, request, context):
            nonlocal executed
            executed = True
            return await super().execute(request, context)

    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=SpySandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory()
    req = ToolRequest(
        tool_name="sql_tool",
        function_name="ExecuteReadOnlyQuery",
        parameters={"query": "DROP TABLE users"},
        call_id="c1",
    )
    result = await interceptor.handle(ctx, req)

    assert result.allowed is False
    assert executed is False
    assert result.audit_record.decision["allowed"] is False


async def test_fail_closed_on_engine_exception(audit_path, context_factory):
    interceptor = ToolCallInterceptor(
        policy_engine=RaisingPolicyEngine(),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is False
    assert "fail-closed" in result.decision.reason
    assert result.sandbox_result is None
    assert verify_chain(audit_path).record_count == 1


async def test_fail_closed_on_engine_timeout(audit_path, context_factory):
    interceptor = ToolCallInterceptor(
        policy_engine=HangingPolicyEngine(),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        decision_timeout_s=0.05,
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is False
    assert "timeout" in result.decision.reason
    assert result.sandbox_result is None


async def test_approval_required_and_granted_executes(example_ruleset, audit_path, context_factory):
    approvals = InMemoryApprovalQueue()
    approvals.set_decision("deploy-1", True)
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        approval_callback=approvals,
    )
    ctx = context_factory(roles=["ProductionAdmin"])
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "production"},
        call_id="deploy-1",
    )
    result = await interceptor.handle(ctx, req)

    assert result.allowed is True
    assert result.sandbox_result is not None
    assert len(approvals.received) == 1
    # The human reviewer must see the raw, unredacted request.
    assert approvals.received[0][1].parameters == {"environment": "production"}


async def test_approval_required_and_denied_blocks_execution(
    example_ruleset, audit_path, context_factory
):
    approvals = InMemoryApprovalQueue()
    approvals.set_decision("deploy-1", False)
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        approval_callback=approvals,
    )
    ctx = context_factory(roles=["ProductionAdmin"])
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "production"},
        call_id="deploy-1",
    )
    result = await interceptor.handle(ctx, req)

    assert result.allowed is False
    assert "not granted" in result.decision.reason
    assert result.sandbox_result is None


async def test_approval_required_but_no_callback_configured_denies(
    example_ruleset, audit_path, context_factory
):
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory(roles=["ProductionAdmin"])
    req = ToolRequest(
        tool_name="deploy_tool",
        function_name="deploy",
        parameters={"environment": "production"},
        call_id="deploy-1",
    )
    result = await interceptor.handle(ctx, req)

    assert result.allowed is False
    assert "no approval_callback" in result.decision.reason


async def test_unknown_action_requirement_is_fail_closed_denied(audit_path, context_factory):
    interceptor = ToolCallInterceptor(
        policy_engine=UnsupportedRequirementPolicyEngine(),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is False
    assert "unsupported action requirement" in result.decision.reason
    assert result.sandbox_result is None


async def test_approval_callback_exception_is_fail_closed(audit_path, context_factory):
    async def broken_callback(context, request, decision):
        raise RuntimeError("webhook unreachable")

    interceptor = ToolCallInterceptor(
        policy_engine=ApprovalRequiredPolicyEngine(),
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        approval_callback=broken_callback,
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is False
    assert "approval resolution failure: fail-closed" in result.decision.reason
    assert result.sandbox_result is None


async def test_sandbox_exception_is_captured_as_failed_result(
    example_ruleset, audit_path, context_factory
):
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=RaisingSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
    )
    ctx = context_factory()
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is True  # policy allowed it; the sandbox itself failed
    assert result.sandbox_result is not None
    assert result.sandbox_result.exit_code == 1
    assert "sandbox exploded" in result.sandbox_result.stderr


async def test_circuit_breaker_open_denies_before_policy_engine_runs(
    example_ruleset, audit_path, context_factory
):
    policy_engine = StaticPolicyEngine(example_ruleset)
    breaker = CircuitBreaker(
        InMemoryCircuitBreakerBackend(failure_threshold=0.5, min_samples=1, cooldown_seconds=60)
    )
    # Manually trip the breaker for this agent/tool pair.
    await breaker.record_result("agent-1", "search_tool", success=False)
    assert await breaker.check("agent-1", "search_tool") is False

    interceptor = ToolCallInterceptor(
        policy_engine=policy_engine,
        sandbox=SubprocessSandbox(),
        audit_log=HashChainedJSONLLogger(audit_path),
        circuit_breaker=breaker,
    )
    ctx = context_factory(agent_id="agent-1")
    result = await interceptor.handle(ctx, _req())

    assert result.allowed is False
    assert "circuit breaker open" in result.decision.reason
    assert result.sandbox_result is None


async def test_repeated_sandbox_failures_trip_the_breaker_for_subsequent_calls(
    example_ruleset, audit_path, context_factory
):
    sandbox = SubprocessSandbox()

    async def failing_impl(request, context):
        raise RuntimeError("tool backend down")

    sandbox.register("search_tool", "query", failing_impl)

    breaker = CircuitBreaker(
        InMemoryCircuitBreakerBackend(failure_threshold=0.5, min_samples=2, cooldown_seconds=60)
    )
    interceptor = ToolCallInterceptor(
        policy_engine=StaticPolicyEngine(example_ruleset),
        sandbox=sandbox,
        audit_log=HashChainedJSONLLogger(audit_path),
        circuit_breaker=breaker,
    )
    ctx = context_factory(agent_id="agent-1")

    first = await interceptor.handle(ctx, _req("c1"))
    assert first.allowed is True  # policy allowed it; sandbox execution itself failed
    assert first.sandbox_result is not None
    assert first.sandbox_result.exit_code == 1

    second = await interceptor.handle(ctx, _req("c2"))
    assert second.sandbox_result is not None
    assert second.sandbox_result.exit_code == 1

    third = await interceptor.handle(ctx, _req("c3"))
    assert third.allowed is False
    assert "circuit breaker open" in third.decision.reason
    assert third.sandbox_result is None
